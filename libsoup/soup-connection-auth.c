/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-connection-auth.c: Abstract base class for hacky Microsoft
 * connection-based auth mechanisms (NTLM and Negotiate)
 *
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <string.h>

#include "soup-connection-auth.h"
#include "soup-message.h"
#include "soup-misc.h"
#include "soup-uri.h"

static gboolean update (SoupAuth *auth, SoupMessage *msg, GHashTable *auth_params);
static char *get_authorization (SoupAuth *auth, SoupMessage *msg);

typedef struct {
	GHashTable *connections;
} SoupConnectionAuthPrivate;
#define SOUP_CONNECTION_AUTH_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_CONNECTION_AUTH, SoupConnectionAuthPrivate))

G_DEFINE_ABSTRACT_TYPE (SoupConnectionAuth, soup_connection_auth, SOUP_TYPE_AUTH)

static void
soup_connection_auth_init (SoupConnectionAuth *connection)
{
	SoupConnectionAuthPrivate *priv = SOUP_CONNECTION_AUTH_GET_PRIVATE (connection);

	priv->connections = g_hash_table_new_full (NULL, NULL, NULL, g_object_unref);
}

static void
finalize (GObject *object)
{
	SoupConnectionAuthPrivate *priv = SOUP_CONNECTION_AUTH_GET_PRIVATE (object);

	g_hash_table_destroy (priv->connections);

	G_OBJECT_CLASS (soup_connection_auth_parent_class)->finalize (object);
}

static void
soup_connection_auth_class_init (SoupConnectionAuthClass *connauth_class)
{
	SoupAuthClass *auth_class = SOUP_AUTH_CLASS (connauth_class);
	GObjectClass *object_class = G_OBJECT_CLASS (connauth_class);

	g_type_class_add_private (connauth_class, sizeof (SoupConnectionAuthPrivate));

	auth_class->update = update;
	auth_class->get_authorization = get_authorization;

	object_class->finalize = finalize;
}

static gboolean
update (SoupAuth *auth, SoupMessage *msg, GHashTable *auth_params)
{
	SoupConnectionAuthPrivate *priv = SOUP_CONNECTION_AUTH_GET_PRIVATE (auth);
	SoupSocket *sock;

	sock = g_hash_table_lookup (priv->connections, msg);
	if (sock) {
		GHashTableIter iter;
		char *auth_header;
		gpointer key, value;
		gboolean result;

		/* Recreate @auth_header out of @auth_params. If the
		 * base64 data ended with 1 or more "="s, then it
		 * will have been parsed as key=value. Otherwise
		 * it will all have been parsed as key, and value
		 * will be %NULL.
		 */
		g_hash_table_iter_init (&iter, auth_params);
		if (!g_hash_table_iter_next (&iter, &key, &value))
			return FALSE;
		auth_header = value ? g_strdup_printf ("%s=%s", (char *)key, (char *)value) : g_strdup (value);
		if (g_hash_table_iter_next (&iter, &key, &value)) {
			g_free (auth_header);
			return FALSE;
		}

		result = SOUP_CONNECTION_AUTH_GET_CLASS (auth)->
			update_connection (SOUP_CONNECTION_AUTH (auth),
					   msg, auth_header, sock);
		g_free (auth_header);
		return result;
	} else
		return FALSE;
}

static char *
get_authorization (SoupAuth *auth, SoupMessage *msg)
{
	SoupConnectionAuthPrivate *priv = SOUP_CONNECTION_AUTH_GET_PRIVATE (auth);
	SoupSocket *sock;

	sock = g_hash_table_lookup (priv->connections, msg);
	if (sock) {
		return SOUP_CONNECTION_AUTH_GET_CLASS (auth)->
			get_connection_authorization (SOUP_CONNECTION_AUTH (auth),
						      msg, sock);
	} else
		return NULL;
}
