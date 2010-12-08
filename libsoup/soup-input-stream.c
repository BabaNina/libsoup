/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-input-stream.c
 *
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <gio/gio.h>

#include "soup-input-stream.h"

struct _SoupInputStreamPrivate {
	GInputStream *base_stream;
	GByteArray   *read_buf;
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

	if (sstream->priv->read_buf)
		g_byte_array_free (sstream->priv->read_buf, TRUE);

	G_OBJECT_CLASS (soup_input_stream_parent_class)->finalize (object);
}

static gssize
read_from_buf (SoupInputStream *sstream, gpointer buffer, gsize count)
{
	GByteArray *read_buf = sstream->priv->read_buf;

	if (read_buf->len < count)
		count = read_buf->len;
	memcpy (buffer, read_buf->data, count);

	if (count == read_buf->len) {
		g_byte_array_free (read_buf, TRUE);
		sstream->priv->read_buf = NULL;
	} else {
		memmove (read_buf->data, read_buf->data + count,
			 read_buf->len - count);
		g_byte_array_set_size (read_buf, read_buf->len - count);
	}

	return count;
}

static gssize
soup_input_stream_read (GInputStream  *stream,
			void          *buffer,
			gsize          count,
			GCancellable  *cancellable,
			GError       **error)
{
	SoupInputStream *sstream = SOUP_INPUT_STREAM (stream);

	if (sstream->priv->read_buf) {
		return read_from_buf (sstream, buffer, count);
	} else {
		return g_input_stream_read (sstream->priv->base_stream,
					    buffer, count,
					    cancellable, error);
	}
}

static gboolean
soup_input_stream_is_readable (GPollableInputStream *stream)
{
	SoupInputStream *sstream = SOUP_INPUT_STREAM (stream);

	if (sstream->priv->read_buf)
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

	if (sstream->priv->read_buf)
		base_source = g_idle_source_new ();
	else
		base_source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (sstream->priv->base_stream), cancellable);

	g_source_set_dummy_callback (base_source);
	pollable_source = g_pollable_source_new (G_OBJECT (stream));
	g_source_add_child_source (pollable_source, base_source);
	g_source_unref (base_source);

	return pollable_source;
}

static void
soup_input_stream_class_init (SoupInputStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GInputStreamClass *input_stream_class = G_INPUT_STREAM_CLASS (stream_class);

	g_type_class_add_private (stream_class, sizeof (SoupInputStreamPrivate));

	object_class->constructed = constructed;
	object_class->finalize = finalize;

	input_stream_class->read_fn = soup_input_stream_read;
}

static void
soup_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface,
				 gpointer interface_data)
{
	pollable_interface->is_readable = soup_input_stream_is_readable;
	pollable_interface->create_source = soup_input_stream_create_source;
}

GInputStream *
soup_input_stream_new (GInputStream *base_stream)
{
	return g_object_new (SOUP_TYPE_INPUT_STREAM,
			     "base-stream", base_stream,
			     "close-base-stream", FALSE,
			     NULL);
}

gssize
soup_input_stream_read_line (SoupInputStream       *sstream,
			     void                  *buffer,
			     gsize                  length,
			     GCancellable          *cancellable,
			     GError               **error)
{
	gssize nread;
	guint8 *p, *buf = buffer;

	g_return_val_if_fail (SOUP_IS_INPUT_STREAM (sstream), -1);

	if (sstream->priv->read_buf) {
		GByteArray *read_buf = sstream->priv->read_buf;

		p = memchr (read_buf->data, '\n', read_buf->len);
		nread = p ? p + 1 - read_buf->data : read_buf->len;
		return read_from_buf (sstream, buffer, nread);
	}

	nread = g_input_stream_read (sstream->priv->base_stream,
				     buffer, length,
				     cancellable, error);
	if (nread <= 0)
		return nread;

	p = memchr (buffer, '\n', nread);
	if (!p || p == buf + nread - 1)
		return nread;

	p++;
	sstream->priv->read_buf = g_byte_array_new ();
	g_byte_array_append (sstream->priv->read_buf,
			     p, nread - (p - buf));
	return p - buf;
}

gssize
soup_input_stream_read_line_nonblocking (SoupInputStream       *sstream,
					 void                  *buffer,
					 gsize                  length,
					 GCancellable          *cancellable,
					 GError               **error)
{
	gssize nread;
	guint8 *p, *buf = buffer;

	g_return_val_if_fail (SOUP_IS_INPUT_STREAM (sstream), -1);

	if (sstream->priv->read_buf) {
		GByteArray *read_buf = sstream->priv->read_buf;

		p = memchr (read_buf->data, '\n', read_buf->len);
		nread = p ? p + 1 - read_buf->data : read_buf->len;
		return read_from_buf (sstream, buffer, nread);
	}

	nread = g_pollable_input_stream_read_nonblocking (
		G_POLLABLE_INPUT_STREAM (sstream->priv->base_stream),
		buffer, length, cancellable, error);
	if (nread <= 0)
		return nread;

	p = memchr (buffer, '\n', nread);
	if (!p || p == buf + nread - 1)
		return nread;

	p++;
	sstream->priv->read_buf = g_byte_array_new ();
	g_byte_array_append (sstream->priv->read_buf,
			     p, nread - (p - buf));
	return p - buf;
}
