/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-ssl.c: temporary ssl integration
 *
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gio/gio.h>

#include "soup-ssl.h"
#include "soup-misc.h"

const gboolean soup_ssl_supported = TRUE;

SoupSSLCredentials *
soup_ssl_get_client_credentials (const char *ca_file)
{
	GTlsClient *tls;

	tls = g_tls_client_new ();
	if (ca_file) {
		GError *error = NULL;

		g_tls_client_set_ca_list_from_file (tls, ca_file, &error);
		if (error) {
			g_warning ("Could not set SSL credentials from '%s': %s",
				   ca_file, error->message);
			g_error_free (error);
		}
	} else
		g_tls_client_set_validation_flags (tls, 0);

	return (SoupSSLCredentials *)tls;
}

void
soup_ssl_free_client_credentials (SoupSSLCredentials *client_creds)
{
	g_object_unref (client_creds);
}

SoupSSLCredentials *
soup_ssl_get_server_credentials (const char *cert_file, const char *key_file)
{
	/* Not yet implemented */
	return NULL;
}

void
soup_ssl_free_server_credentials (SoupSSLCredentials *server_creds)
{
	;
}

/**
 * SOUP_SSL_ERROR:
 *
 * A #GError domain representing an SSL error. Used with #SoupSSLError.
 **/
/**
 * soup_ssl_error_quark:
 *
 * The quark used as %SOUP_SSL_ERROR
 *
 * Return value: The quark used as %SOUP_SSL_ERROR
 **/
GQuark
soup_ssl_error_quark (void)
{
	static GQuark error;
	if (!error)
		error = g_quark_from_static_string ("soup_ssl_error_quark");
	return error;
}

/**
 * SoupSSLError:
 * @SOUP_SSL_ERROR_HANDSHAKE_NEEDS_READ: Internal error. Never exposed
 * outside of libsoup.
 * @SOUP_SSL_ERROR_HANDSHAKE_NEEDS_WRITE: Internal error. Never exposed
 * outside of libsoup.
 * @SOUP_SSL_ERROR_CERTIFICATE: Indicates an error validating an SSL
 * certificate
 *
 * SSL-related I/O errors.
 **/
