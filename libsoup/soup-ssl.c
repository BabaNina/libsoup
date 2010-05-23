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
	GTlsClientContext *tls_context;

	tls_context = g_tls_client_context_new ();
	if (ca_file) {
		GError *error = NULL;

		g_tls_context_set_ca_list_from_file (G_TLS_CONTEXT (tls_context),
						     ca_file, &error);
		if (error) {
			g_warning ("Could not set SSL credentials from '%s': %s",
				   ca_file, error->message);
			g_error_free (error);
		}
	} else
		g_tls_client_context_set_validation_flags (tls_context, 0);

	return (SoupSSLCredentials *)tls_context;
}

void
soup_ssl_free_client_credentials (SoupSSLCredentials *client_creds)
{
	g_object_unref (client_creds);
}

SoupSSLCredentials *
soup_ssl_get_server_credentials (const char *cert_file, const char *key_file)
{
	GTlsServerContext *tls_context;
	GTlsCertificate *cert;
	GError *error = NULL;
	char *cert_pem, *key_pem;

	if (!g_file_get_contents (cert_file, &cert_pem, NULL, &error)) {
		g_warning ("Could not read SSL certificate from '%s': %s",
			   cert_file, error->message);
		g_error_free (error);
		return NULL;
	}
	if (!g_file_get_contents (key_file, &key_pem, NULL, &error)) {
		g_warning ("Could not read SSL private key from '%s': %s",
			   key_file, error->message);
		g_error_free (error);
		g_free (cert_pem);
		return NULL;
	}

	tls_context = g_tls_server_context_new ();
	cert = g_initable_new (g_tls_context_get_certificate_type (G_TLS_CONTEXT (tls_context)),
			       NULL, &error,
			       "certificate-pem", cert_pem,
			       "private-key-pem", key_pem,
			       NULL);
	g_free (cert_pem);
	g_free (key_pem);

	if (!cert) {
		g_warning ("Could not create SSL certificate from '%s' and '%s': %s",
			   cert_file, key_file, error->message);
		g_error_free (error);
		g_object_unref (tls_context);
		return NULL;
	}

	g_object_set_data_full (G_OBJECT (tls_context),
				"soup_ssl_server_credentials",
				cert, g_object_unref);

	return (SoupSSLCredentials *)tls_context;
}

void
soup_ssl_free_server_credentials (SoupSSLCredentials *server_creds)
{
	g_object_unref (server_creds);
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
