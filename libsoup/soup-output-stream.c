/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-output-stream.c
 *
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gio/gio.h>

#include "soup-output-stream.h"
#include "soup-message-headers.h"

typedef enum {
	SOUP_OUTPUT_STREAM_STATE_CHUNK_SIZE,
	SOUP_OUTPUT_STREAM_STATE_CHUNK_END,
	SOUP_OUTPUT_STREAM_STATE_CHUNK,
	SOUP_OUTPUT_STREAM_STATE_TRAILERS,
	SOUP_OUTPUT_STREAM_STATE_DONE
} SoupOutputStreamState;

struct _SoupOutputStreamPrivate {
	GOutputStream *base_stream;
	gboolean      blocking;
	char           buf[20];

	SoupEncoding   encoding;
	goffset        write_length;
	SoupOutputStreamState chunked_state;
};

enum {
	PROP_0,

	PROP_BLOCKING
};

static void soup_output_stream_pollable_init (GPollableOutputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupOutputStream, soup_output_stream, G_TYPE_FILTER_OUTPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_OUTPUT_STREAM,
						soup_output_stream_pollable_init))


static void
soup_output_stream_init (SoupOutputStream *stream)
{
	stream->priv = G_TYPE_INSTANCE_GET_PRIVATE (stream,
						    SOUP_TYPE_OUTPUT_STREAM,
						    SoupOutputStreamPrivate);
	stream->priv->encoding = SOUP_ENCODING_NONE;
}

static void
constructed (GObject *object)
{
	SoupOutputStream *sstream = SOUP_OUTPUT_STREAM (object);

	sstream->priv->base_stream = g_filter_output_stream_get_base_stream (G_FILTER_OUTPUT_STREAM (sstream));
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupOutputStream *sstream = SOUP_OUTPUT_STREAM (object);

	switch (prop_id) {
	case PROP_BLOCKING:
		sstream->priv->blocking = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupOutputStream *sstream = SOUP_OUTPUT_STREAM (object);

	switch (prop_id) {
	case PROP_BLOCKING:
		g_value_set_boolean (value, sstream->priv->blocking);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gssize
soup_output_stream_write_raw (SoupOutputStream  *sstream,
			      const void        *buffer,
			      gsize              count,
			      GCancellable      *cancellable,
			      GError           **error)
{
	if (sstream->priv->blocking) {
		return g_output_stream_write (sstream->priv->base_stream,
					      buffer, count,
					      cancellable, error);
	} else {
		return g_pollable_output_stream_write_nonblocking (
			G_POLLABLE_OUTPUT_STREAM (sstream->priv->base_stream),
			buffer, count, cancellable, error);
	}
}

static gssize
soup_output_stream_write_chunked (SoupOutputStream  *sstream,
				  const void        *buffer,
				  gsize              count,
				  GCancellable      *cancellable,
				  GError           **error)
{
	char *buf = sstream->priv->buf;
	gssize nwrote, len;

again:
	len = strlen (buf);
	if (len) {
		nwrote = soup_output_stream_write_raw (sstream, buf, len,
						       cancellable, error);
		if (nwrote < 0)
			return nwrote;
		memmove (buf, buf + nwrote, len + 1 - nwrote);
		goto again;
	}

	switch (sstream->priv->chunked_state) {
	case SOUP_OUTPUT_STREAM_STATE_CHUNK_SIZE:
		snprintf (buf, sizeof (sstream->priv->buf),
			  "%lx\r\n", (gulong)count);
		len = strlen (buf);

		if (count > 0)
			sstream->priv->chunked_state = SOUP_OUTPUT_STREAM_STATE_CHUNK;
		else
			sstream->priv->chunked_state = SOUP_OUTPUT_STREAM_STATE_TRAILERS;
		break;

	case SOUP_OUTPUT_STREAM_STATE_CHUNK:
		nwrote = soup_output_stream_write_raw (sstream, buffer, count,
						       cancellable, error);
		if (nwrote < (gssize)count)
			return nwrote;

		sstream->priv->chunked_state = SOUP_OUTPUT_STREAM_STATE_CHUNK_END;
		break;

	case SOUP_OUTPUT_STREAM_STATE_CHUNK_END:
		strncpy (buf, "\r\n", sizeof (sstream->priv->buf));
		len = 2;
		sstream->priv->chunked_state = SOUP_OUTPUT_STREAM_STATE_DONE;
		break;

	case SOUP_OUTPUT_STREAM_STATE_TRAILERS:
		strncpy (buf, "\r\n", sizeof (sstream->priv->buf));
		len = 2;
		sstream->priv->chunked_state = SOUP_OUTPUT_STREAM_STATE_DONE;
		break;

	case SOUP_OUTPUT_STREAM_STATE_DONE:
		sstream->priv->chunked_state = SOUP_OUTPUT_STREAM_STATE_CHUNK_SIZE;
		return count;
	}

	goto again;
}

static gssize
soup_output_stream_write_fn (GOutputStream  *stream,
			     const void     *buffer,
			     gsize           count,
			     GCancellable   *cancellable,
			     GError        **error)
{
	SoupOutputStream *sstream = SOUP_OUTPUT_STREAM (stream);

	switch (sstream->priv->encoding) {
	case SOUP_ENCODING_CHUNKED:
		return soup_output_stream_write_chunked (sstream, buffer, count,
							 cancellable,
							 error);

	default:
		return soup_output_stream_write_raw (sstream, buffer, count,
						     cancellable, error);
	}
}

static gboolean
soup_output_stream_is_writable (GPollableOutputStream *stream)
{
	SoupOutputStream *sstream = SOUP_OUTPUT_STREAM (stream);

	return g_pollable_output_stream_is_writable (G_POLLABLE_OUTPUT_STREAM (sstream->priv->base_stream));
}

static GSource *
soup_output_stream_create_source (GPollableOutputStream *stream,
				  GCancellable *cancellable)
{
	SoupOutputStream *sstream = SOUP_OUTPUT_STREAM (stream);
	GSource *base_source, *pollable_source;

	base_source = g_pollable_output_stream_create_source (G_POLLABLE_OUTPUT_STREAM (sstream->priv->base_stream), cancellable);
	g_source_set_dummy_callback (base_source);
	pollable_source = g_pollable_source_new (G_OBJECT (stream));
	g_source_add_child_source (pollable_source, base_source);
	g_source_unref (base_source);

	return pollable_source;
}

static void
soup_output_stream_class_init (SoupOutputStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GOutputStreamClass *output_stream_class = G_OUTPUT_STREAM_CLASS (stream_class);

	g_type_class_add_private (stream_class, sizeof (SoupOutputStreamPrivate));

	object_class->constructed = constructed;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	output_stream_class->write_fn = soup_output_stream_write_fn;

	g_object_class_install_property (
		object_class, PROP_BLOCKING,
		g_param_spec_boolean ("blocking",
				      "Blocking",
				      "Whether the stream uses blocking I/O",
				      TRUE,
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static void
soup_output_stream_pollable_init (GPollableOutputStreamInterface *pollable_interface,
				  gpointer interface_data)
{
	pollable_interface->is_writable = soup_output_stream_is_writable;
	pollable_interface->create_source = soup_output_stream_create_source;
}

SoupOutputStream *
soup_output_stream_new (GOutputStream *base_stream,
			gboolean       blocking)
{
	return g_object_new (SOUP_TYPE_OUTPUT_STREAM,
			     "base-stream", base_stream,
			     "close-base-stream", FALSE,
			     "blocking", blocking,
			     NULL);
}

void
soup_output_stream_set_encoding (SoupOutputStream *sstream,
				 SoupEncoding     encoding)
{
	sstream->priv->encoding = encoding;
	if (encoding == SOUP_ENCODING_CHUNKED)
		sstream->priv->chunked_state = SOUP_OUTPUT_STREAM_STATE_CHUNK_SIZE;
}

gssize
soup_output_stream_write (SoupOutputStream      *sstream,
			  const void            *buffer,
			  gsize                  count,
			  GCancellable          *cancellable,
			  GError               **error)
{
	/* g_output_stream_write() insists that writing 0 bytes is
	 * a no-op, but we handle it specially when doing chunked
	 * encoding.
	 */
	if (count == 0 && sstream->priv->encoding == SOUP_ENCODING_CHUNKED) {
		return soup_output_stream_write_chunked (sstream, buffer, count,
							 cancellable, error);
	} else if (sstream->priv->blocking) {
		return g_output_stream_write (G_OUTPUT_STREAM (sstream),
					      buffer, count,
					      cancellable, error);
	} else {
		return g_pollable_output_stream_write_nonblocking (
			G_POLLABLE_OUTPUT_STREAM (sstream),
			buffer, count, cancellable, error);
	}
}
