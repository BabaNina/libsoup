/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef SOUP_INPUT_STREAM_H
#define SOUP_INPUT_STREAM_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-message-headers.h>

G_BEGIN_DECLS

#define SOUP_TYPE_INPUT_STREAM            (soup_input_stream_get_type ())
#define SOUP_INPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_INPUT_STREAM, SoupInputStream))
#define SOUP_INPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_INPUT_STREAM, SoupInputStreamClass))
#define SOUP_IS_INPUT_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_INPUT_STREAM))
#define SOUP_IS_INPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_INPUT_STREAM))
#define SOUP_INPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_INPUT_STREAM, SoupInputStreamClass))

typedef struct _SoupInputStreamPrivate SoupInputStreamPrivate;

typedef struct {
	GFilterInputStream parent;

	SoupInputStreamPrivate *priv;
} SoupInputStream;

typedef struct {
	GFilterInputStreamClass parent_class;

	/* Padding for future expansion */
	void (*_libsoup_reserved1) (void);
	void (*_libsoup_reserved2) (void);
	void (*_libsoup_reserved3) (void);
	void (*_libsoup_reserved4) (void);
} SoupInputStreamClass;

GType soup_input_stream_get_type (void);

GInputStream *soup_input_stream_new                   (GInputStream          *base_stream);

void          soup_input_stream_set_encoding          (SoupInputStream       *sstream,
						       SoupEncoding           encoding,
						       goffset                content_length);

gssize        soup_input_stream_read_line             (SoupInputStream       *sstream,
						       void                  *buffer,
						       gsize                  length,
						       GCancellable          *cancellable,
						       GError               **error);
gssize        soup_input_stream_read_line_nonblocking (SoupInputStream       *sstream,
						       void                  *buffer,
						       gsize                  length,
						       GCancellable          *cancellable,
						       GError               **error);

G_END_DECLS

#endif /* SOUP_INPUT_STREAM_H */
