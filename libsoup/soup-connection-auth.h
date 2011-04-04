/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef SOUP_CONNECTION_AUTH_H
#define SOUP_CONNECTION_AUTH_H 1

#include <libsoup/soup-auth.h>

G_BEGIN_DECLS

#define SOUP_TYPE_CONNECTION_AUTH            (soup_connection_auth_get_type ())
#define SOUP_CONNECTION_AUTH(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_CONNECTION_AUTH, SoupConnectionAuth))
#define SOUP_CONNECTION_AUTH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_CONNECTION_AUTH, SoupConnectionAuthClass))
#define SOUP_IS_CONNECTION_AUTH(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_CONNECTION_AUTH))
#define SOUP_IS_CONNECTION_AUTH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_CONNECTION_AUTH))
#define SOUP_CONNECTION_AUTH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_CONNECTION_AUTH, SoupConnectionAuthClass))

typedef struct {
	SoupAuth parent;

} SoupConnectionAuth;

typedef struct {
	SoupAuthClass parent_class;

	gboolean  (*update_connection)            (SoupConnectionAuth *auth,
						   SoupMessage        *msg,
						   const char         *auth_header,
						   SoupSocket         *sock);
	char     *(*get_connection_authorization) (SoupConnectionAuth *auth,
						   SoupMessage        *msg,
						   SoupSocket         *sock);
	gboolean  (*is_ready_for_connection)      (SoupConnectionAuth *auth,
						   SoupMessage        *msg,
						   SoupSocket         *sock);
} SoupConnectionAuthClass;

GType soup_connection_auth_get_type (void);

G_END_DECLS

#endif /* SOUP_CONNECTION_AUTH_H */
