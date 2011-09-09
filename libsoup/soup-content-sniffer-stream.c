/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-content-sniffer-stream.c
 *
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <gio/gio.h>

#include "soup-content-sniffer-stream.h"
#include "soup-content-sniffer.h"
#include "soup-message.h"

G_DEFINE_TYPE (SoupContentSnifferStream, soup_content_sniffer_stream, G_TYPE_FILTER_INPUT_STREAM)

enum {
	PROP_0,

	PROP_SNIFFER,
	PROP_MESSAGE,
};

struct _SoupContentSnifferStreamPrivate {
	SoupContentSniffer *sniffer;
	SoupMessage *msg;

	gsize buffer_size;
	gboolean sniffing;
	GByteArray *buf;
	GError *error;

	char *content_type;
	GHashTable *content_params;
};

static void
soup_content_sniffer_stream_finalize (GObject *object)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (object);

	if (sniffer->priv->sniffer)
		g_object_unref (sniffer->priv->sniffer);
	if (sniffer->priv->msg)
		g_object_unref (sniffer->priv->msg);
	if (sniffer->priv->buf)
		g_byte_array_free (sniffer->priv->buf, TRUE);
	if (sniffer->priv->error)
		g_error_free (sniffer->priv->error);

	if (sniffer->priv->content_type)
		g_free (sniffer->priv->content_type);
	if (sniffer->priv->content_params)
		g_hash_table_destroy (sniffer->priv->content_params);

	G_OBJECT_CLASS (soup_content_sniffer_stream_parent_class)->finalize (object);
}

static void
soup_content_sniffer_stream_set_property (GObject *object, guint prop_id,
					  const GValue *value, GParamSpec *pspec)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (object);

	switch (prop_id) {
	case PROP_SNIFFER:
		sniffer->priv->sniffer = g_value_dup_object (value);
		/* FIXME: supposed to wait until after got-headers for this */
		sniffer->priv->buffer_size = soup_content_sniffer_get_buffer_size (sniffer->priv->sniffer);
		break;
	case PROP_MESSAGE:
		sniffer->priv->msg = g_value_dup_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_content_sniffer_stream_get_property (GObject *object, guint prop_id,
					  GValue *value, GParamSpec *pspec)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (object);

	switch (prop_id) {
	case PROP_SNIFFER:
		g_value_set_object (value, sniffer->priv->sniffer);
		break;
	case PROP_MESSAGE:
		g_value_set_object (value, sniffer->priv->msg);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/* Tries to read at least @sniffer->priv->buffer_size bytes into
 * @buffer (which has a total size of @count bytes and already has
 * *@so_far bytes in it).
 *
 * read_and_sniff() only returns an error in two cases; if it gets an
 * error while *@so_far is still 0, or if it gets a
 * %G_IO_ERROR_WOULD_BLOCK. In either case, it will return -1 and set
 * *@error (having updated *@so_far to reflect any data that was
 * successfully read in the second case). Likewise, 0 indicating EOF
 * will only be returned if it occurs while *@so_far is 0.
 *
 * Otherwise, if the return value is positive, then it indicates the
 * amount of data in @buffer, which will have been sniffed. If an
 * error had occurred after reading some data, that will be stored in
 * @sniffer->priv->error and should be returned on the next read. (If
 * an EOF occurred after reading some data, then the next read will
 * just return 0.)
 */
static gssize
read_and_sniff (GInputStream *stream, void *buffer, gsize count,
		gsize *so_far, GCancellable *cancellable, GError **error)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (stream);
	gssize nread;
	GError *my_error = NULL;
	SoupBuffer *buf;

	g_return_val_if_fail (count >= sniffer->priv->buffer_size, -1);

	do {
		nread = G_INPUT_STREAM_CLASS (soup_content_sniffer_stream_parent_class)->
			read_fn (stream, (guchar *)buffer + *so_far,
				 count - *so_far, cancellable, &my_error);
		if (nread <= 0)
			break;
		*so_far += nread;
	} while (*so_far < sniffer->priv->buffer_size);

	/* If we got EAGAIN before filling the buffer, just return that. */
	if (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
		g_propagate_error (error, my_error);
		return -1;
	}

	/* Otherwise, we've either filled the buffer or gotten an EOF
	 * or fatal error, so sniff the data.
	 */
	buf = soup_buffer_new (SOUP_MEMORY_TEMPORARY, buffer, *so_far);
	sniffer->priv->content_type =
		soup_content_sniffer_sniff (sniffer->priv->sniffer,
					    sniffer->priv->msg,
					    buf,
					    &sniffer->priv->content_params);
	soup_buffer_free (buf);
	sniffer->priv->sniffing = FALSE;

	if (nread <= 0 && *so_far) {
		/* Save the error/EOF for later, return the data now. */
		sniffer->priv->error = my_error;
		my_error = NULL;
		return *so_far;
	}

	return nread > 0 ? *so_far : nread;
}	

static gssize
soup_content_sniffer_stream_read (GInputStream  *stream,
				  void          *buffer,
				  gsize          count,
				  GCancellable  *cancellable,
				  GError       **error)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (stream);
	gssize nread;
	gsize total;

	if (sniffer->priv->error) {
		g_propagate_error (error, sniffer->priv->error);
		sniffer->priv->error = NULL;
		return -1;
	}

	if (sniffer->priv->sniffing) {
		if (!sniffer->priv->buf &&
		    count > sniffer->priv->buffer_size) {
			/* Try to read directly into @buffer */
			total = 0;
			nread = read_and_sniff (stream, buffer, count,
						&total, cancellable, error);
			if (nread < 0 && total > 0) {
				/* error is WOULD_BLOCK, save the data */
				sniffer->priv->buf = g_byte_array_sized_new (sniffer->priv->buffer_size);
				g_byte_array_append (sniffer->priv->buf, buffer, total);
			}
			return nread;
		} else {
			/* We already read some, or else @buffer is too small,
			 * so read into our own buffer.
			 */
			if (!sniffer->priv->buf)
				sniffer->priv->buf = g_byte_array_sized_new (sniffer->priv->buffer_size);

			total = sniffer->priv->buf->len;
			nread = read_and_sniff (stream, sniffer->priv->buf->data,
						sniffer->priv->buffer_size,
						&total, cancellable, error);
			sniffer->priv->buf->len = total;

			if (nread <= 0)
				return nread;
			/* else, fall through to the "read from buf" case */
		}
	}

	if (sniffer->priv->buf) {
		nread = MIN (count, sniffer->priv->buf->len);
		memcpy (buffer, sniffer->priv->buf->data, nread);
		if (nread == sniffer->priv->buf->len) {
			g_byte_array_free (sniffer->priv->buf, TRUE);
			sniffer->priv->buf = NULL;
		} else
			g_byte_array_remove_range (sniffer->priv->buf, 0, nread);
	} else {
		nread = G_INPUT_STREAM_CLASS (soup_content_sniffer_stream_parent_class)->
			read_fn (stream, buffer, count, cancellable, error);
	}
	return nread;
}

static gssize
soup_content_sniffer_stream_skip (GInputStream  *stream,
				  gsize          count,
				  GCancellable  *cancellable,
				  GError       **error)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (stream);
	gssize nskipped;

	if (sniffer->priv->sniffing) {
		/* Read into the internal buffer... */
		nskipped = soup_content_sniffer_stream_read (stream, NULL, 0, cancellable, error);
		if (nskipped == -1)
			return -1;
		/* Now fall through */
	}

	if (sniffer->priv->buf) {
		nskipped = MIN (count, sniffer->priv->buf->len);
		if (nskipped == sniffer->priv->buf->len) {
			g_byte_array_free (sniffer->priv->buf, TRUE);
			sniffer->priv->buf = NULL;
		} else
			g_byte_array_remove_range (sniffer->priv->buf, 0, nskipped);
	} else {
		nskipped = G_INPUT_STREAM_CLASS (soup_content_sniffer_stream_parent_class)->
			skip (stream, count, cancellable, error);
	}
	return nskipped;
}

static void
soup_content_sniffer_stream_init (SoupContentSnifferStream *sniffer)
{
	sniffer->priv = G_TYPE_INSTANCE_GET_PRIVATE (sniffer,
						     SOUP_TYPE_CONTENT_SNIFFER_STREAM,
						     SoupContentSnifferStreamPrivate);
	sniffer->priv->sniffing = TRUE;
}

static void
soup_content_sniffer_stream_class_init (SoupContentSnifferStreamClass *sniffer_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (sniffer_class);
	GInputStreamClass *input_stream_class =
		G_INPUT_STREAM_CLASS (sniffer_class);
 
	g_type_class_add_private (sniffer_class, sizeof (SoupContentSnifferStreamPrivate));

	object_class->finalize = soup_content_sniffer_stream_finalize;
	object_class->set_property = soup_content_sniffer_stream_set_property;
	object_class->get_property = soup_content_sniffer_stream_get_property;

	input_stream_class->read_fn = soup_content_sniffer_stream_read;
	input_stream_class->skip = soup_content_sniffer_stream_skip;

	g_object_class_install_property (
		object_class, PROP_SNIFFER,
		g_param_spec_object ("sniffer",
				     "Sniffer",
				     "The stream's SoupContentSniffer",
				     SOUP_TYPE_CONTENT_SNIFFER,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_MESSAGE,
		g_param_spec_object ("message",
				     "Message",
				     "The stream's SoupMessage",
				     SOUP_TYPE_MESSAGE,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

GInputStream *
soup_content_sniffer_stream_new (SoupContentSniffer *sniffer,
				 SoupMessage        *msg,
				 GInputStream       *base_stream)
{
	return g_object_new (SOUP_TYPE_CONTENT_SNIFFER_STREAM,
			     "base-stream", base_stream,
			     "close-base-stream", FALSE,
			     "message", msg,
			     "sniffer", sniffer,
			     NULL);
}

const char *
soup_content_sniffer_stream_sniff (SoupContentSnifferStream  *stream,
				   GHashTable               **params)
{
	if (params)
		*params = stream->priv->content_params;
	return stream->priv->content_type;
}
