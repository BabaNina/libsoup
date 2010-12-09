/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-input-stream.c
 *
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <gio/gio.h>

#include "soup-input-stream.h"
#include "soup-message-headers.h"

typedef enum {
	SOUP_INPUT_STREAM_STATE_CHUNK_SIZE,
	SOUP_INPUT_STREAM_STATE_CHUNK_END,
	SOUP_INPUT_STREAM_STATE_CHUNK,
	SOUP_INPUT_STREAM_STATE_TRAILERS,
	SOUP_INPUT_STREAM_STATE_DONE
} SoupInputStreamState;

struct _SoupInputStreamPrivate {
	GInputStream *base_stream;
	GByteArray   *buf;

	SoupEncoding  encoding;
	goffset       read_length;
	SoupInputStreamState chunked_state;
};

static void soup_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupInputStream, soup_input_stream, G_TYPE_FILTER_INPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM,
						soup_input_stream_pollable_init))


static void
soup_input_stream_init (SoupInputStream *stream)
{
	stream->priv = G_TYPE_INSTANCE_GET_PRIVATE (stream,
						    SOUP_TYPE_INPUT_STREAM,
						    SoupInputStreamPrivate);
}

static void
constructed (GObject *object)
{
	SoupInputStream *sstream = SOUP_INPUT_STREAM (object);

	sstream->priv->base_stream = g_filter_input_stream_get_base_stream (G_FILTER_INPUT_STREAM (sstream));
}

static void
finalize (GObject *object)
{
	SoupInputStream *sstream = SOUP_INPUT_STREAM (object);

	if (sstream->priv->buf)
		g_byte_array_free (sstream->priv->buf, TRUE);

	G_OBJECT_CLASS (soup_input_stream_parent_class)->finalize (object);
}

static gssize
read_from_buf (SoupInputStream *sstream, gpointer buffer, gsize count)
{
	GByteArray *buf = sstream->priv->buf;

	if (buf->len < count)
		count = buf->len;
	memcpy (buffer, buf->data, count);

	if (count == buf->len) {
		g_byte_array_free (buf, TRUE);
		sstream->priv->buf = NULL;
	} else {
		memmove (buf->data, buf->data + count,
			 buf->len - count);
		g_byte_array_set_size (buf, buf->len - count);
	}

	return count;
}

static gssize
soup_input_stream_read_raw (SoupInputStream  *sstream,
			    void             *buffer,
			    gsize             count,
			    gboolean          blocking,
			    GCancellable     *cancellable,
			    GError          **error)
{
	gssize nread;

	if (sstream->priv->buf) {
		return read_from_buf (sstream, buffer, count);
	} else if (blocking) {
		nread = g_input_stream_read (sstream->priv->base_stream,
					     buffer, count,
					     cancellable, error);
	} else {
		nread = g_pollable_input_stream_read_nonblocking (
			G_POLLABLE_INPUT_STREAM (sstream->priv->base_stream),
			buffer, count, cancellable, error);
	}

	if (nread == 0 && sstream->priv->encoding != SOUP_ENCODING_EOF) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT, NULL);
		return -1;
	}
	return nread;
}

static gssize
soup_input_stream_read_chunked (SoupInputStream  *sstream,
				void             *buffer,
				gsize             count,
				gboolean          blocking,
				GCancellable     *cancellable,
				GError          **error)
{
	char metabuf[128];
	gssize nread;

again:
	switch (sstream->priv->chunked_state) {
	case SOUP_INPUT_STREAM_STATE_CHUNK_SIZE:
	case SOUP_INPUT_STREAM_STATE_CHUNK_END:
		nread = soup_input_stream_read_line (sstream,
						     metabuf, sizeof (metabuf),
						     blocking,
						     cancellable, error);
		if (nread <= 0)
			return nread;
		if (metabuf[nread - 1] != '\n')
			return -1;

		if (sstream->priv->chunked_state == SOUP_INPUT_STREAM_STATE_CHUNK_SIZE) {
			sstream->priv->read_length = strtoul (metabuf, NULL, 16);
			if (sstream->priv->read_length > 0)
				sstream->priv->chunked_state = SOUP_INPUT_STREAM_STATE_CHUNK;
			else
				sstream->priv->chunked_state = SOUP_INPUT_STREAM_STATE_TRAILERS;
		} else
			sstream->priv->chunked_state = SOUP_INPUT_STREAM_STATE_CHUNK_SIZE;
		break;

	case SOUP_INPUT_STREAM_STATE_CHUNK:
		nread = soup_input_stream_read_raw (sstream, buffer,
						    MIN (count, sstream->priv->read_length),
						    blocking, cancellable, error);
		if (nread > 0) {
			sstream->priv->read_length -= nread;
			if (sstream->priv->read_length == 0)
				sstream->priv->chunked_state = SOUP_INPUT_STREAM_STATE_CHUNK_END;
		}
		return nread;

	case SOUP_INPUT_STREAM_STATE_TRAILERS:
		nread = soup_input_stream_read_line (sstream, buffer, count,
						     blocking, cancellable, error);
		if (nread <= 0)
			return nread;

		if (strncmp (buffer, "\r\n", nread) || strncmp (buffer, "\n", nread))
			sstream->priv->chunked_state = SOUP_INPUT_STREAM_STATE_DONE;
		break;
		
	case SOUP_INPUT_STREAM_STATE_DONE:
		return 0;
	}

	goto again;
}

static gssize
soup_input_stream_read_fn (GInputStream  *stream,
			   void          *buffer,
			   gsize          count,
			   GCancellable  *cancellable,
			   GError       **error)
{
	SoupInputStream *sstream = SOUP_INPUT_STREAM (stream);
	gssize nread;

	switch (sstream->priv->encoding) {
	case SOUP_ENCODING_CHUNKED:
		return soup_input_stream_read_chunked (sstream, buffer, count,
						       TRUE, cancellable,
						       error);

	case SOUP_ENCODING_CONTENT_LENGTH:
		count = MIN (count, sstream->priv->read_length);
		if (count == 0)
			return 0;
		nread = soup_input_stream_read_raw (sstream, buffer, count,
						    TRUE, cancellable, error);
		if (nread > 0)
			sstream->priv->read_length -= nread;
		return nread;

	case SOUP_ENCODING_EOF:
		return soup_input_stream_read_raw (sstream, buffer, count,
						   TRUE, cancellable, error);

	case SOUP_ENCODING_NONE:
	default:
		return 0;
	}
}

static gboolean
soup_input_stream_is_readable (GPollableInputStream *stream)
{
	SoupInputStream *sstream = SOUP_INPUT_STREAM (stream);

	if (sstream->priv->buf)
		return TRUE;
	else
		return g_pollable_input_stream_is_readable (G_POLLABLE_INPUT_STREAM (sstream->priv->base_stream));
}

static GSource *
soup_input_stream_create_source (GPollableInputStream *stream,
				 GCancellable *cancellable)
{
	SoupInputStream *sstream = SOUP_INPUT_STREAM (stream);
	GSource *base_source, *pollable_source;

	if (sstream->priv->buf)
		base_source = g_idle_source_new ();
	else
		base_source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (sstream->priv->base_stream), cancellable);

	g_source_set_dummy_callback (base_source);
	pollable_source = g_pollable_source_new (G_OBJECT (stream));
	g_source_add_child_source (pollable_source, base_source);
	g_source_unref (base_source);

	return pollable_source;
}

static gssize
soup_input_stream_read_nonblocking (GPollableInputStream  *stream,
				    void          *buffer,
				    gsize          count,
				    GError       **error)
{
	SoupInputStream *sstream = SOUP_INPUT_STREAM (stream);
	gssize nread;

	switch (sstream->priv->encoding) {
	case SOUP_ENCODING_CHUNKED:
		return soup_input_stream_read_chunked (sstream, buffer, count,
						       FALSE, NULL, error);

	case SOUP_ENCODING_CONTENT_LENGTH:
		count = MIN (count, sstream->priv->read_length);
		if (count == 0)
			return 0;
		nread = soup_input_stream_read_raw (sstream, buffer, count,
						    FALSE, NULL, error);
		if (nread > 0)
			sstream->priv->read_length -= nread;
		return nread;

	case SOUP_ENCODING_EOF:
		return soup_input_stream_read_raw (sstream, buffer, count,
						   FALSE, NULL, error);

	case SOUP_ENCODING_NONE:
	default:
		return 0;
	}
}

static void
soup_input_stream_class_init (SoupInputStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GInputStreamClass *input_stream_class = G_INPUT_STREAM_CLASS (stream_class);

	g_type_class_add_private (stream_class, sizeof (SoupInputStreamPrivate));

	object_class->constructed = constructed;
	object_class->finalize = finalize;

	input_stream_class->read_fn = soup_input_stream_read_fn;
}

static void
soup_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface,
				 gpointer interface_data)
{
	pollable_interface->is_readable = soup_input_stream_is_readable;
	pollable_interface->create_source = soup_input_stream_create_source;
	pollable_interface->read_nonblocking = soup_input_stream_read_nonblocking;
}

SoupInputStream *
soup_input_stream_new (GInputStream *base_stream)
{
	return g_object_new (SOUP_TYPE_INPUT_STREAM,
			     "base-stream", base_stream,
			     "close-base-stream", FALSE,
			     NULL);
}

void
soup_input_stream_set_encoding (SoupInputStream *sstream,
				SoupEncoding     encoding,
				goffset          content_length)
{
	sstream->priv->encoding = encoding;
	sstream->priv->read_length = content_length;
	if (encoding == SOUP_ENCODING_CHUNKED)
		sstream->priv->chunked_state = SOUP_INPUT_STREAM_STATE_CHUNK_SIZE;
}

gssize
soup_input_stream_read (SoupInputStream       *sstream,
			void                  *buffer,
			gsize                  count,
			gboolean               blocking,
			GCancellable          *cancellable,
			GError               **error)
{
	if (blocking) {
		return g_input_stream_read (G_INPUT_STREAM (sstream),
					    buffer, count,
					    cancellable, error);
	} else {
		return g_pollable_input_stream_read_nonblocking (
			G_POLLABLE_INPUT_STREAM (sstream),
			buffer, count, cancellable, error);
	}
}

gssize
soup_input_stream_read_line (SoupInputStream       *sstream,
			     void                  *buffer,
			     gsize                  length,
			     gboolean               blocking,
			     GCancellable          *cancellable,
			     GError               **error)
{
	gssize nread;
	guint8 *p, *buf = buffer;

	g_return_val_if_fail (SOUP_IS_INPUT_STREAM (sstream), -1);

	if (sstream->priv->buf) {
		GByteArray *buf = sstream->priv->buf;

		p = memchr (buf->data, '\n', buf->len);
		nread = p ? p + 1 - buf->data : buf->len;
		return read_from_buf (sstream, buffer, nread);
	}

	if (blocking) {
		nread = g_input_stream_read (G_INPUT_STREAM (sstream->priv->base_stream),
					     buffer, length,
					     cancellable, error);
	} else {
		nread = g_pollable_input_stream_read_nonblocking (
			G_POLLABLE_INPUT_STREAM (sstream->priv->base_stream),
			buffer, length, cancellable, error);
	}
	if (nread <= 0)
		return nread;

	p = memchr (buffer, '\n', nread);
	if (!p || p == buf + nread - 1)
		return nread;

	p++;
	sstream->priv->buf = g_byte_array_new ();
	g_byte_array_append (sstream->priv->buf,
			     p, nread - (p - buf));
	return p - buf;
}
