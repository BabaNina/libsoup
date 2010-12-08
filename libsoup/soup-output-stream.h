/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef SOUP_OUTPUT_STREAM_H
#define SOUP_OUTPUT_STREAM_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-message-headers.h>

G_BEGIN_DECLS

#define SOUP_TYPE_OUTPUT_STREAM            (soup_output_stream_get_type ())
#define SOUP_OUTPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_OUTPUT_STREAM, SoupOutputStream))
#define SOUP_OUTPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_OUTPUT_STREAM, SoupOutputStreamClass))
#define SOUP_IS_OUTPUT_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_OUTPUT_STREAM))
#define SOUP_IS_OUTPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_OUTPUT_STREAM))
#define SOUP_OUTPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_OUTPUT_STREAM, SoupOutputStreamClass))

typedef struct _SoupOutputStreamPrivate SoupOutputStreamPrivate;

typedef struct {
	GFilterOutputStream parent;

	SoupOutputStreamPrivate *priv;
} SoupOutputStream;

typedef struct {
	GFilterOutputStreamClass parent_class;

	/* Padding for future expansion */
	void (*_libsoup_reserved1) (void);
	void (*_libsoup_reserved2) (void);
	void (*_libsoup_reserved3) (void);
	void (*_libsoup_reserved4) (void);
} SoupOutputStreamClass;

GType soup_output_stream_get_type (void);

SoupOutputStream *soup_output_stream_new          (GOutputStream     *base_stream,
						   gboolean           blocking);

void              soup_output_stream_set_encoding (SoupOutputStream  *sstream,
						   SoupEncoding       encoding);

gssize            soup_output_stream_write        (SoupOutputStream  *sstream,
						   const void        *buffer,
						   gsize              count,
						   GCancellable      *cancellable,
						   GError           **error);

G_END_DECLS

#endif /* SOUP_OUTPUT_STREAM_H */
