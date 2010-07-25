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

#include "soup-connection-auth.h"

G_DEFINE_ABSTRACT_TYPE (SoupConnectionAuth, soup_connection_auth, SOUP_TYPE_AUTH)

static void
soup_connection_auth_init (SoupConnectionAuth *connection)
{
}

static void
soup_connection_auth_class_init (SoupConnectionAuthClass *connauth_class)
{
}
