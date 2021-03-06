/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-socket.c: Socket networking code.
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "soup-address.h"
#include "soup-socket.h"
#include "soup-marshal.h"
#include "soup-misc.h"
#include "soup-ssl.h"

/**
 * SECTION:soup-socket
 * @short_description: A network socket
 *
 * #SoupSocket is libsoup's TCP socket type. While it is primarily
 * intended for internal use, #SoupSocket<!-- -->s are exposed in the
 * API in various places, and some of their methods (eg,
 * soup_socket_get_remote_address()) may be useful to applications.
 **/

G_DEFINE_TYPE (SoupSocket, soup_socket, G_TYPE_OBJECT)

enum {
	READABLE,
	WRITABLE,
	DISCONNECTED,
	NEW_CONNECTION,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_LOCAL_ADDRESS,
	PROP_REMOTE_ADDRESS,
	PROP_NON_BLOCKING,
	PROP_IS_SERVER,
	PROP_SSL_CREDENTIALS,
	PROP_SSL_STRICT,
	PROP_ASYNC_CONTEXT,
	PROP_TIMEOUT,
	PROP_TRUSTED_CERTIFICATE,
	PROP_CLEAN_DISPOSE,

	LAST_PROP
};

typedef struct {
	int sockfd;
	SoupAddress *local_addr, *remote_addr;
	GSocket *gsock;

	guint non_blocking:1;
	guint is_server:1;
	guint clean_dispose:1;
	guint ssl_strict:1;
	guint trusted_certificate:1;
	GTlsContext *tls_context;
	GTlsSession *tls_session;

	GMainContext   *async_context;
	GSource        *watch_src;
	GSource        *read_src, *write_src;
	GByteArray     *read_buf;

	GMutex *iolock, *addrlock;
	guint timeout;

	GCancellable *connect_cancel;
} SoupSocketPrivate;
#define SOUP_SOCKET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_SOCKET, SoupSocketPrivate))

static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

#ifdef G_OS_WIN32
#define SOUP_IS_INVALID_SOCKET(socket) ((socket) == INVALID_SOCKET)
#define SHUT_RDWR SD_BOTH
#else
#define SOUP_IS_INVALID_SOCKET(socket) ((socket) < 0)
#endif

static void
soup_socket_init (SoupSocket *sock)
{
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (sock);

	priv->sockfd = -1;
	priv->non_blocking = TRUE;
	priv->addrlock = g_mutex_new ();
	priv->iolock = g_mutex_new ();
	priv->timeout = 0;
}

static void
disconnect_internal (SoupSocketPrivate *priv)
{
	if (priv->gsock) {
		g_object_unref (priv->gsock);
		priv->gsock = NULL;
	}
	priv->sockfd = -1;

	if (priv->read_src) {
		g_source_destroy (priv->read_src);
		priv->read_src = NULL;
	}
	if (priv->write_src) {
		g_source_destroy (priv->write_src);
		priv->write_src = NULL;
	}
}

static void
finalize (GObject *object)
{
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (object);

	if (priv->connect_cancel) {
		if (priv->clean_dispose)
			g_warning ("Disposing socket %p during connect", object);
		g_object_unref (priv->connect_cancel);
	}
	if (priv->gsock) {
		if (priv->clean_dispose)
			g_warning ("Disposing socket %p while still connected", object);
		disconnect_internal (priv);
	}

	if (priv->local_addr)
		g_object_unref (priv->local_addr);
	if (priv->remote_addr)
		g_object_unref (priv->remote_addr);

	if (priv->watch_src) {
		if (priv->clean_dispose && !priv->is_server)
			g_warning ("Disposing socket %p during async op", object);
		g_source_destroy (priv->watch_src);
	}
	if (priv->async_context)
		g_main_context_unref (priv->async_context);

	if (priv->read_buf)
		g_byte_array_free (priv->read_buf, TRUE);

	if (priv->tls_context)
		g_object_unref (priv->tls_context);
	if (priv->tls_session)
		g_object_unref (priv->tls_session);

	g_mutex_free (priv->addrlock);
	g_mutex_free (priv->iolock);

	G_OBJECT_CLASS (soup_socket_parent_class)->finalize (object);
}

static void
soup_socket_class_init (SoupSocketClass *socket_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (socket_class);

	g_type_class_add_private (socket_class, sizeof (SoupSocketPrivate));

	/* virtual method override */
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	/* signals */

	/**
	 * SoupSocket::readable:
	 * @sock: the socket
	 *
	 * Emitted when an async socket is readable. See
	 * soup_socket_read(), soup_socket_read_until() and
	 * #SoupSocket:non-blocking.
	 **/
	signals[READABLE] =
		g_signal_new ("readable",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (SoupSocketClass, readable),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupSocket::writable:
	 * @sock: the socket
	 *
	 * Emitted when an async socket is writable. See
	 * soup_socket_write() and #SoupSocket:non-blocking.
	 **/
	signals[WRITABLE] =
		g_signal_new ("writable",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (SoupSocketClass, writable),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupSocket::disconnected:
	 * @sock: the socket
	 *
	 * Emitted when the socket is disconnected, for whatever
	 * reason.
	 **/
	signals[DISCONNECTED] =
		g_signal_new ("disconnected",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (SoupSocketClass, disconnected),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupSocket::new-connection:
	 * @sock: the socket
	 * @new: the new socket
	 *
	 * Emitted when a listening socket (set up with
	 * soup_socket_listen()) receives a new connection.
	 *
	 * You must ref the @new if you want to keep it; otherwise it
	 * will be destroyed after the signal is emitted.
	 **/
	signals[NEW_CONNECTION] =
		g_signal_new ("new_connection",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupSocketClass, new_connection),
			      NULL, NULL,
			      soup_marshal_NONE__OBJECT,
			      G_TYPE_NONE, 1,
			      SOUP_TYPE_SOCKET);

	/* properties */
	/**
	 * SOUP_SOCKET_LOCAL_ADDRESS:
	 *
	 * Alias for the #SoupSocket:local-address property. (Address
	 * of local end of socket.)
	 **/
	g_object_class_install_property (
		object_class, PROP_LOCAL_ADDRESS,
		g_param_spec_object (SOUP_SOCKET_LOCAL_ADDRESS,
				     "Local address",
				     "Address of local end of socket",
				     SOUP_TYPE_ADDRESS,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	/**
	 * SOUP_SOCKET_REMOTE_ADDRESS:
	 *
	 * Alias for the #SoupSocket:remote-address property. (Address
	 * of remote end of socket.)
	 **/
	g_object_class_install_property (
		object_class, PROP_REMOTE_ADDRESS,
		g_param_spec_object (SOUP_SOCKET_REMOTE_ADDRESS,
				     "Remote address",
				     "Address of remote end of socket",
				     SOUP_TYPE_ADDRESS,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	/**
	 * SoupSocket:non-blocking:
	 *
	 * Whether or not the socket uses non-blocking I/O.
	 *
	 * #SoupSocket's I/O methods are designed around the idea of
	 * using a single codepath for both synchronous and
	 * asynchronous I/O. If you want to read off a #SoupSocket,
	 * the "correct" way to do it is to call soup_socket_read() or
	 * soup_socket_read_until() repeatedly until you have read
	 * everything you want. If it returns %SOUP_SOCKET_WOULD_BLOCK
	 * at any point, stop reading and wait for it to emit the
	 * #SoupSocket::readable signal. Then go back to the
	 * reading-as-much-as-you-can loop. Likewise, for writing to a
	 * #SoupSocket, you should call soup_socket_write() either
	 * until you have written everything, or it returns
	 * %SOUP_SOCKET_WOULD_BLOCK (in which case you wait for
	 * #SoupSocket::writable and then go back into the loop).
	 *
	 * Code written this way will work correctly with both
	 * blocking and non-blocking sockets; blocking sockets will
	 * simply never return %SOUP_SOCKET_WOULD_BLOCK, and so the
	 * code that handles that case just won't get used for them.
	 **/
	/**
	 * SOUP_SOCKET_FLAG_NONBLOCKING:
	 *
	 * Alias for the #SoupSocket:non-blocking property. (Whether
	 * or not the socket uses non-blocking I/O.)
	 **/
	g_object_class_install_property (
		object_class, PROP_NON_BLOCKING,
		g_param_spec_boolean (SOUP_SOCKET_FLAG_NONBLOCKING,
				      "Non-blocking",
				      "Whether or not the socket uses non-blocking I/O",
				      TRUE,
				      G_PARAM_READWRITE));
	/**
	 * SOUP_SOCKET_IS_SERVER:
	 *
	 * Alias for the #SoupSocket:is-server property. (Whether or
	 * not the socket is a server socket.)
	 **/
	g_object_class_install_property (
		object_class, PROP_IS_SERVER,
		g_param_spec_boolean (SOUP_SOCKET_IS_SERVER,
				      "Server",
				      "Whether or not the socket is a server socket",
				      FALSE,
				      G_PARAM_READABLE));
	/**
	 * SOUP_SOCKET_SSL_CREDENTIALS:
	 *
	 * Alias for the #SoupSocket:ssl-credentials property.
	 * (SSL credential information.)
	 **/
	g_object_class_install_property (
		object_class, PROP_SSL_CREDENTIALS,
		g_param_spec_object (SOUP_SOCKET_SSL_CREDENTIALS,
				     "SSL credentials",
				     "SSL credential information, passed from the session to the SSL implementation",
				     G_TYPE_TLS_CONTEXT,
				     G_PARAM_READWRITE));
	/**
	 * SOUP_SOCKET_SSL_STRICT:
	 *
	 * Alias for the #SoupSocket:ignore-ssl-cert-errors property.
	 **/
	g_object_class_install_property (
		object_class, PROP_SSL_STRICT,
		g_param_spec_boolean (SOUP_SOCKET_SSL_STRICT,
				      "Strictly validate SSL certificates",
				      "Whether certificate errors should be considered a connection error",
				      TRUE,
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	/**
	 * SOUP_SOCKET_TRUSTED_CERTIFICATE:
	 *
	 * Alias for the #SoupSocket:trusted-certificate
	 * property. Notice that this property's value is only useful
	 * if the socket is for an SSL connection, and only reliable
	 * after some data has been transferred to or from it.
	 **/
	g_object_class_install_property (
		object_class, PROP_TRUSTED_CERTIFICATE,
		g_param_spec_boolean (SOUP_SOCKET_TRUSTED_CERTIFICATE,
				     "Trusted Certificate",
				     "Whether the server certificate is trusted, if this is an SSL socket",
				     FALSE,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	/**
	 * SOUP_SOCKET_ASYNC_CONTEXT:
	 *
	 * Alias for the #SoupSocket:async-context property. (The
	 * socket's #GMainContext.)
	 **/
	g_object_class_install_property (
		object_class, PROP_ASYNC_CONTEXT,
		g_param_spec_pointer (SOUP_SOCKET_ASYNC_CONTEXT,
				      "Async GMainContext",
				      "The GMainContext to dispatch this socket's async I/O in",
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/**
	 * SOUP_SOCKET_TIMEOUT:
	 *
	 * Alias for the #SoupSocket:timeout property. (The timeout
	 * in seconds for blocking socket I/O operations.)
	 **/
	g_object_class_install_property (
		object_class, PROP_TIMEOUT,
		g_param_spec_uint (SOUP_SOCKET_TIMEOUT,
				   "Timeout value",
				   "Value in seconds to timeout a blocking I/O",
				   0, G_MAXUINT, 0,
				   G_PARAM_READWRITE));

	g_object_class_install_property (
		object_class, PROP_CLEAN_DISPOSE,
		g_param_spec_boolean ("clean-dispose",
				      "Clean dispose",
				      "Warn on unclean dispose",
				      FALSE,
				      G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
}


static void
set_fdflags (SoupSocketPrivate *priv)
{
	int opt;

	if (priv->sockfd == -1)
		return;

	opt = 1;
	setsockopt (priv->sockfd, IPPROTO_TCP,
		    TCP_NODELAY, (void *) &opt, sizeof (opt));

	if (!priv->gsock)
		priv->gsock = g_socket_new_from_fd (priv->sockfd, NULL);
	g_socket_set_blocking (priv->gsock, !priv->non_blocking);
	g_socket_set_timeout (priv->gsock, priv->timeout);
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_LOCAL_ADDRESS:
		priv->local_addr = (SoupAddress *)g_value_dup_object (value);
		break;
	case PROP_REMOTE_ADDRESS:
		priv->remote_addr = (SoupAddress *)g_value_dup_object (value);
		break;
	case PROP_NON_BLOCKING:
		priv->non_blocking = g_value_get_boolean (value);
		if (priv->gsock)
			g_socket_set_blocking (priv->gsock, !priv->non_blocking);
		break;
	case PROP_SSL_CREDENTIALS:
		if (priv->tls_context)
			g_object_unref (priv->tls_context);
		priv->tls_context = g_value_dup_object (value);
		break;
	case PROP_SSL_STRICT:
		priv->ssl_strict = g_value_get_boolean (value);
		break;
	case PROP_TRUSTED_CERTIFICATE:
		priv->trusted_certificate = g_value_get_boolean (value);
		break;
	case PROP_ASYNC_CONTEXT:
		priv->async_context = g_value_get_pointer (value);
		if (priv->async_context)
			g_main_context_ref (priv->async_context);
		break;
	case PROP_TIMEOUT:
		priv->timeout = g_value_get_uint (value);
		if (priv->gsock)
			g_socket_set_timeout (priv->gsock, priv->timeout);
		break;
	case PROP_CLEAN_DISPOSE:
		priv->clean_dispose = g_value_get_boolean (value);
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
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_LOCAL_ADDRESS:
		g_value_set_object (value, soup_socket_get_local_address (SOUP_SOCKET (object)));
		break;
	case PROP_REMOTE_ADDRESS:
		g_value_set_object (value, soup_socket_get_remote_address (SOUP_SOCKET (object)));
		break;
	case PROP_NON_BLOCKING:
		g_value_set_boolean (value, priv->non_blocking);
		break;
	case PROP_IS_SERVER:
		g_value_set_boolean (value, priv->is_server);
		break;
	case PROP_SSL_CREDENTIALS:
		g_value_set_object (value, priv->tls_context);
		break;
	case PROP_SSL_STRICT:
		g_value_set_boolean (value, priv->ssl_strict);
		break;
	case PROP_TRUSTED_CERTIFICATE:
		g_value_set_boolean (value, priv->trusted_certificate);
		break;
	case PROP_ASYNC_CONTEXT:
		g_value_set_pointer (value, priv->async_context ? g_main_context_ref (priv->async_context) : NULL);
		break;
	case PROP_TIMEOUT:
		g_value_set_uint (value, priv->timeout);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}


/**
 * soup_socket_new:
 * @optname1: name of first property to set (or %NULL)
 * @...: value of @optname1, followed by additional property/value pairs
 *
 * Creates a new (disconnected) socket
 *
 * Return value: the new socket
 **/
SoupSocket *
soup_socket_new (const char *optname1, ...)
{
	SoupSocket *sock;
	va_list ap;

	va_start (ap, optname1);
	sock = (SoupSocket *)g_object_new_valist (SOUP_TYPE_SOCKET,
						  optname1, ap);
	va_end (ap);

	return sock;
}

static guint
socket_connected (SoupSocket *sock, GSocketConnection *conn, GError *error)
{
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (sock);

	g_object_unref (priv->connect_cancel);
	priv->connect_cancel = NULL;

	if (error) {
		if (error->domain == G_RESOLVER_ERROR) {
			g_error_free (error);
			return SOUP_STATUS_CANT_RESOLVE;
		} else {
			g_error_free (error);
			return SOUP_STATUS_CANT_CONNECT;
		}
	}

	priv->gsock = g_object_ref (g_socket_connection_get_socket (conn));

	/* FIXME: unreffing the stream will forcibly close the connection */
	g_object_set_data_full (G_OBJECT (sock), "GSocketConnection",
				conn, g_object_unref);

	priv->sockfd = g_socket_get_fd (priv->gsock);
	set_fdflags (priv);

	return SOUP_STATUS_OK;
}

/**
 * SoupSocketCallback:
 * @sock: the #SoupSocket
 * @status: an HTTP status code indicating success or failure
 * @user_data: the data passed to soup_socket_connect_async()
 *
 * The callback function passed to soup_socket_connect_async().
 **/

typedef struct {
	SoupSocket *sock;
	SoupSocketCallback callback;
	gpointer user_data;
} SoupSocketAsyncConnectData;

static void
async_connected (GObject *client, GAsyncResult *result, gpointer data)
{
	SoupSocketAsyncConnectData *sacd = data;
	GError *error = NULL;
	GSocketConnection *conn;
	guint status;

	conn = g_socket_client_connect_finish (G_SOCKET_CLIENT (client),
					       result, &error);
	status = socket_connected (sacd->sock, conn, error);

	sacd->callback (sacd->sock, status, sacd->user_data);
	g_object_unref (sacd->sock);
	g_slice_free (SoupSocketAsyncConnectData, sacd);
}

/**
 * soup_socket_connect_async:
 * @sock: a client #SoupSocket (which must not already be connected)
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to call after connecting
 * @user_data: data to pass to @callback
 *
 * Begins asynchronously connecting to @sock's remote address. The
 * socket will call @callback when it succeeds or fails (but not
 * before returning from this function).
 *
 * If @cancellable is non-%NULL, it can be used to cancel the
 * connection. @callback will still be invoked in this case, with a
 * status of %SOUP_STATUS_CANCELLED.
 **/
void
soup_socket_connect_async (SoupSocket *sock, GCancellable *cancellable,
			   SoupSocketCallback callback, gpointer user_data)
{
	SoupSocketPrivate *priv;
	SoupSocketAsyncConnectData *sacd;
	GSocketClient *client;

	g_return_if_fail (SOUP_IS_SOCKET (sock));
	priv = SOUP_SOCKET_GET_PRIVATE (sock);
	g_return_if_fail (priv->remote_addr != NULL);

	sacd = g_slice_new0 (SoupSocketAsyncConnectData);
	sacd->sock = g_object_ref (sock);
	sacd->callback = callback;
	sacd->user_data = user_data;

	priv->connect_cancel = cancellable ? g_object_ref (cancellable) : g_cancellable_new ();

	if (priv->async_context)
		g_main_context_push_thread_default (priv->async_context);

	client = g_socket_client_new ();
	g_socket_client_connect_async (client,
				       G_SOCKET_CONNECTABLE (priv->remote_addr),
				       priv->connect_cancel,
				       async_connected, sacd);
	g_object_unref (client);

	if (priv->async_context)
		g_main_context_pop_thread_default (priv->async_context);
}

/**
 * soup_socket_connect_sync:
 * @sock: a client #SoupSocket (which must not already be connected)
 * @cancellable: a #GCancellable, or %NULL
 *
 * Attempt to synchronously connect @sock to its remote address.
 *
 * If @cancellable is non-%NULL, it can be used to cancel the
 * connection, in which case soup_socket_connect_sync() will return
 * %SOUP_STATUS_CANCELLED.
 *
 * Return value: a success or failure code.
 **/
guint
soup_socket_connect_sync (SoupSocket *sock, GCancellable *cancellable)
{
	SoupSocketPrivate *priv;
	GSocketClient *client;
	GSocketConnection *conn;
	GError *error = NULL;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), SOUP_STATUS_MALFORMED);
	priv = SOUP_SOCKET_GET_PRIVATE (sock);
	g_return_val_if_fail (!priv->is_server, SOUP_STATUS_MALFORMED);
	g_return_val_if_fail (priv->sockfd == -1, SOUP_STATUS_MALFORMED);
	g_return_val_if_fail (priv->remote_addr != NULL, SOUP_STATUS_MALFORMED);

	if (cancellable)
		g_object_ref (cancellable);
	else
		cancellable = g_cancellable_new ();
	priv->connect_cancel = cancellable;

	client = g_socket_client_new ();
	conn = g_socket_client_connect (client,
					G_SOCKET_CONNECTABLE (priv->remote_addr),
					priv->connect_cancel, &error);
	g_object_unref (client);

	return socket_connected (sock, conn, error);
}

int
soup_socket_get_fd (SoupSocket *sock)
{
	g_return_val_if_fail (SOUP_IS_SOCKET (sock), -1);

	return SOUP_SOCKET_GET_PRIVATE (sock)->sockfd;
}

static GSource *
soup_socket_create_watch (SoupSocketPrivate *priv, GIOCondition cond,
			  GSocketSourceFunc callback, gpointer user_data,
			  GCancellable *cancellable)
{
	GSource *watch;

	if (priv->tls_session)
		watch = g_tls_session_create_source (priv->tls_session, cancellable);
	else
		watch = g_socket_create_source (priv->gsock, cond, cancellable);
	g_source_set_callback (watch, (GSourceFunc)callback, user_data, NULL);
	g_source_attach (watch, priv->async_context);
	g_source_unref (watch);

	return watch;
}

static gboolean
listen_watch (GSocket *gsock, GIOCondition condition, gpointer data)
{
	SoupSocket *sock = data, *new;
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (sock), *new_priv;
	struct sockaddr_storage sa;
	int sa_len, sockfd;

	if (condition & (G_IO_HUP | G_IO_ERR)) {
		priv->watch_src = NULL;
		return FALSE;
	}

	/* Using g_socket_accept() here would require more rewriting... */

	sa_len = sizeof (sa);
	sockfd = accept (priv->sockfd, (struct sockaddr *)&sa, (void *)&sa_len);
	if (SOUP_IS_INVALID_SOCKET (sockfd))
		return TRUE;

	new = g_object_new (SOUP_TYPE_SOCKET, NULL);
	new_priv = SOUP_SOCKET_GET_PRIVATE (new);
	new_priv->sockfd = sockfd;
	if (priv->async_context)
		new_priv->async_context = g_main_context_ref (priv->async_context);
	new_priv->non_blocking = priv->non_blocking;
	new_priv->is_server = TRUE;
	if (priv->tls_context)
		new_priv->tls_context = g_object_ref (priv->tls_context);
	set_fdflags (new_priv);

	new_priv->remote_addr = soup_address_new_from_sockaddr ((struct sockaddr *)&sa, sa_len);

	if (new_priv->tls_context) {
		if (!soup_socket_start_ssl (new, NULL)) {
			g_object_unref (new);
			return TRUE;
		}
	}

	g_signal_emit (sock, signals[NEW_CONNECTION], 0, new);
	g_object_unref (new);

	return TRUE;
}

/**
 * soup_socket_listen:
 * @sock: a server #SoupSocket (which must not already be connected or
 * listening)
 *
 * Makes @sock start listening on its local address. When connections
 * come in, @sock will emit %new_connection.
 *
 * Return value: whether or not @sock is now listening.
 **/
gboolean
soup_socket_listen (SoupSocket *sock)

{
	SoupSocketPrivate *priv;
	GSocketAddress *addr;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), FALSE);
	priv = SOUP_SOCKET_GET_PRIVATE (sock);
	g_return_val_if_fail (priv->sockfd == -1, FALSE);
	g_return_val_if_fail (priv->local_addr != NULL, FALSE);

	priv->is_server = TRUE;

	/* @local_addr may have its port set to 0. So we intentionally
	 * don't store it in priv->local_addr, so that if the
	 * caller calls soup_socket_get_local_address() later, we'll
	 * have to make a new addr by calling getsockname(), which
	 * will have the right port number.
	 */
	addr = soup_address_get_gsockaddr (priv->local_addr);
	g_return_val_if_fail (addr != NULL, FALSE);

	priv->sockfd = socket (g_socket_address_get_family (addr),
			       SOCK_STREAM, 0);
	if (SOUP_IS_INVALID_SOCKET (priv->sockfd))
		goto cant_listen;
	set_fdflags (priv);

	/* Bind */
	if (!g_socket_bind (priv->gsock, addr, TRUE, NULL))
		goto cant_listen;
	/* Force local_addr to be re-resolved now */
	g_object_unref (priv->local_addr);
	priv->local_addr = NULL;

	/* Listen */
	if (!g_socket_listen (priv->gsock, NULL))
		goto cant_listen;

	priv->watch_src = soup_socket_create_watch (priv,
						    G_IO_IN | G_IO_ERR | G_IO_HUP,
						    listen_watch, sock,
						    NULL);
	return TRUE;

 cant_listen:
	if (priv->gsock)
		disconnect_internal (priv);

	return FALSE;
}

static gboolean
soup_socket_accept_certificate (GTlsClient *client, GTlsCertificate *cert,
				GTlsValidationFlags errors, gpointer sock)
{
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (sock);

	priv->trusted_certificate = FALSE;
	return !priv->ssl_strict;
}

/**
 * soup_socket_start_ssl:
 * @sock: the socket
 * @cancellable: a #GCancellable
 *
 * Starts using SSL on @socket.
 *
 * Return value: success or failure
 **/
gboolean
soup_socket_start_ssl (SoupSocket *sock, GCancellable *cancellable)
{
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (sock);

	return soup_socket_start_proxy_ssl (sock, soup_address_get_name (priv->remote_addr), cancellable);
}
	
/**
 * soup_socket_start_proxy_ssl:
 * @sock: the socket
 * @ssl_host: hostname of the SSL server
 * @cancellable: a #GCancellable
 *
 * Starts using SSL on @socket, expecting to find a host named
 * @ssl_host.
 *
 * Return value: success or failure
 **/
gboolean
soup_socket_start_proxy_ssl (SoupSocket *sock, const char *ssl_host,
			     GCancellable *cancellable)
{
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (sock);

	if (priv->tls_session)
		return TRUE;
	if (!priv->tls_context)
		return FALSE;

	if (G_IS_TLS_CLIENT_CONTEXT (priv->tls_context)) {
		GTlsClient *client;

		client = g_tls_client_context_create_client (G_TLS_CLIENT_CONTEXT (priv->tls_context),
							     priv->gsock,
							     ssl_host,
							     NULL);

		/* FIXME: need a signal to let us know a successful
		 * handshake happened.
		 */
		priv->trusted_certificate = TRUE;

		g_signal_connect (client, "accept-certificate",
				  G_CALLBACK (soup_socket_accept_certificate),
				  sock);
		priv->tls_session = G_TLS_SESSION (client);
	} else {
		GTlsServer *server;
		GTlsCertificate *default_cert;

		default_cert = g_object_get_data (G_OBJECT (priv->tls_context),
						  "soup_ssl_server_credentials");
		server = g_tls_server_context_create_server (G_TLS_SERVER_CONTEXT (priv->tls_context),
							     priv->gsock,
							     default_cert,
							     G_TLS_AUTHENTICATION_NONE,
							     NULL);
		priv->tls_session = G_TLS_SESSION (server);
	}
	if (!priv->tls_session)
		return FALSE;

	return TRUE;
}
	
/**
 * soup_socket_is_ssl:
 * @sock: a #SoupSocket
 *
 * Tests if @sock is set up to do SSL. Note that this simply means
 * that the %SOUP_SOCKET_SSL_CREDENTIALS property has been set; it
 * does not mean that soup_socket_start_ssl() has been called.
 *
 * Return value: %TRUE if @sock has SSL credentials set
 **/
gboolean
soup_socket_is_ssl (SoupSocket *sock)
{
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (sock);

	return priv->tls_context != NULL;
}

/**
 * soup_socket_disconnect:
 * @sock: a #SoupSocket
 *
 * Disconnects @sock. Any further read or write attempts on it will
 * fail.
 **/
void
soup_socket_disconnect (SoupSocket *sock)
{
	SoupSocketPrivate *priv;
	gboolean already_disconnected = FALSE;

	g_return_if_fail (SOUP_IS_SOCKET (sock));
	priv = SOUP_SOCKET_GET_PRIVATE (sock);

	if (priv->connect_cancel) {
		g_cancellable_cancel (priv->connect_cancel);
		return;
	} else if (g_mutex_trylock (priv->iolock)) {
		if (priv->gsock)
			disconnect_internal (priv);
		else
			already_disconnected = TRUE;
		g_mutex_unlock (priv->iolock);
	} else {
		int sockfd;

		/* Another thread is currently doing IO, so
		 * we can't close the socket. So just shutdown
		 * the file descriptor to force the I/O to fail.
		 * (It will actually be closed when the socket is
		 * destroyed.)
		 */
		sockfd = priv->sockfd;
		priv->sockfd = -1;

		if (sockfd == -1)
			already_disconnected = TRUE;
		else
			shutdown (sockfd, SHUT_RDWR);
	}

	if (already_disconnected)
		return;

	/* Keep ref around signals in case the object is unreferenced
	 * in a handler
	 */
	g_object_ref (sock);

	/* Give all readers a chance to notice the connection close */
	g_signal_emit (sock, signals[READABLE], 0);

	/* FIXME: can't disconnect until all data is read */

	/* Then let everyone know we're disconnected */
	g_signal_emit (sock, signals[DISCONNECTED], 0);

	g_object_unref (sock);
}

/**
 * soup_socket_is_connected:
 * @sock: a #SoupSocket
 *
 * Tests if @sock is connected to another host
 *
 * Return value: %TRUE or %FALSE.
 **/
gboolean
soup_socket_is_connected (SoupSocket *sock)
{
	SoupSocketPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), FALSE);
	priv = SOUP_SOCKET_GET_PRIVATE (sock);

	return priv->gsock != NULL;
}

/**
 * soup_socket_get_local_address:
 * @sock: a #SoupSocket
 *
 * Returns the #SoupAddress corresponding to the local end of @sock.
 *
 * Return value: (transfer none): the #SoupAddress
 **/
SoupAddress *
soup_socket_get_local_address (SoupSocket *sock)
{
	SoupSocketPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), NULL);
	priv = SOUP_SOCKET_GET_PRIVATE (sock);

	g_mutex_lock (priv->addrlock);
	if (!priv->local_addr) {
		struct sockaddr_storage bound_sa;
		int sa_len;

		sa_len = sizeof (bound_sa);
		getsockname (priv->sockfd, (struct sockaddr *)&bound_sa, (void *)&sa_len);
		priv->local_addr = soup_address_new_from_sockaddr ((struct sockaddr *)&bound_sa, sa_len);
	}
	g_mutex_unlock (priv->addrlock);

	return priv->local_addr;
}

/**
 * soup_socket_get_remote_address:
 * @sock: a #SoupSocket
 *
 * Returns the #SoupAddress corresponding to the remote end of @sock.
 *
 * Return value: (transfer none): the #SoupAddress
 **/
SoupAddress *
soup_socket_get_remote_address (SoupSocket *sock)
{
	SoupSocketPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), NULL);
	priv = SOUP_SOCKET_GET_PRIVATE (sock);

	g_mutex_lock (priv->addrlock);
	if (!priv->remote_addr) {
		struct sockaddr_storage bound_sa;
		int sa_len;

		sa_len = sizeof (bound_sa);
		getpeername (priv->sockfd, (struct sockaddr *)&bound_sa, (void *)&sa_len);
		priv->remote_addr = soup_address_new_from_sockaddr ((struct sockaddr *)&bound_sa, sa_len);
	}
	g_mutex_unlock (priv->addrlock);

	return priv->remote_addr;
}


static gboolean
socket_read_watch (GSocket *gsock, GIOCondition cond, gpointer user_data)
{
	SoupSocket *sock = user_data;
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (sock);

	priv->read_src = NULL;

	if (cond & (G_IO_ERR | G_IO_HUP))
		soup_socket_disconnect (sock);
	else
		g_signal_emit (sock, signals[READABLE], 0);

	return FALSE;
}

static SoupSocketIOStatus
read_from_network (SoupSocket *sock, gpointer buffer, gsize len,
		   gsize *nread, GCancellable *cancellable, GError **error)
{
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (sock);
	GError *my_err = NULL;
	gssize my_nread;

	*nread = 0;

	if (!priv->gsock)
		return SOUP_SOCKET_EOF;

	if (priv->tls_session) {
		my_nread = g_tls_session_receive (priv->tls_session, buffer, len,
						  cancellable, &my_err);
	} else {
		my_nread = g_socket_receive (priv->gsock, buffer, len,
					     cancellable, &my_err);
	}
	if (my_nread > 0) {
		g_clear_error (&my_err);
		*nread = my_nread;
		return SOUP_SOCKET_OK;
	} else if (my_nread == 0) {
		g_clear_error (&my_err);
		*nread = my_nread;
		return SOUP_SOCKET_EOF;
	}

	if (g_error_matches (my_err, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
		g_clear_error (&my_err);
		if (!priv->read_src) {
			priv->read_src =
				soup_socket_create_watch (priv,
							  G_IO_IN | G_IO_HUP | G_IO_ERR,
							  socket_read_watch, sock,
							  cancellable);
		}
		return SOUP_SOCKET_WOULD_BLOCK;
	} else if (g_error_matches (my_err, G_TLS_ERROR, G_TLS_ERROR_HANDSHAKE)) {
		my_err->domain = SOUP_SSL_ERROR;
		my_err->code = SOUP_SSL_ERROR_CERTIFICATE;
	}

	g_propagate_error (error, my_err);
	return SOUP_SOCKET_ERROR;
}

static SoupSocketIOStatus
read_from_buf (SoupSocket *sock, gpointer buffer, gsize len, gsize *nread)
{
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (sock);
	GByteArray *read_buf = priv->read_buf;

	*nread = MIN (read_buf->len, len);
	memcpy (buffer, read_buf->data, *nread);

	if (*nread == read_buf->len) {
		g_byte_array_free (read_buf, TRUE);
		priv->read_buf = NULL;
	} else {
		memmove (read_buf->data, read_buf->data + *nread, 
			 read_buf->len - *nread);
		g_byte_array_set_size (read_buf, read_buf->len - *nread);
	}

	return SOUP_SOCKET_OK;
}

/**
 * SoupSocketIOStatus:
 * @SOUP_SOCKET_OK: Success
 * @SOUP_SOCKET_WOULD_BLOCK: Cannot read/write any more at this time
 * @SOUP_SOCKET_EOF: End of file
 * @SOUP_SOCKET_ERROR: Other error
 *
 * Return value from the #SoupSocket IO methods.
 **/

/**
 * soup_socket_read:
 * @sock: the socket
 * @buffer: buffer to read into
 * @len: size of @buffer in bytes
 * @nread: on return, the number of bytes read into @buffer
 * @cancellable: a #GCancellable, or %NULL
 * @error: error pointer
 *
 * Attempts to read up to @len bytes from @sock into @buffer. If some
 * data is successfully read, soup_socket_read() will return
 * %SOUP_SOCKET_OK, and *@nread will contain the number of bytes
 * actually read (which may be less than @len).
 *
 * If @sock is non-blocking, and no data is available, the return
 * value will be %SOUP_SOCKET_WOULD_BLOCK. In this case, the caller
 * can connect to the #SoupSocket::readable signal to know when there
 * is more data to read. (NB: You MUST read all available data off the
 * socket first. #SoupSocket::readable is only emitted after
 * soup_socket_read() returns %SOUP_SOCKET_WOULD_BLOCK, and it is only
 * emitted once. See the documentation for #SoupSocket:non-blocking.)
 *
 * Return value: a #SoupSocketIOStatus, as described above (or
 * %SOUP_SOCKET_EOF if the socket is no longer connected, or
 * %SOUP_SOCKET_ERROR on any other error, in which case @error will
 * also be set).
 **/
SoupSocketIOStatus
soup_socket_read (SoupSocket *sock, gpointer buffer, gsize len,
		  gsize *nread, GCancellable *cancellable, GError **error)
{
	SoupSocketPrivate *priv;
	SoupSocketIOStatus status;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), SOUP_SOCKET_ERROR);
	g_return_val_if_fail (nread != NULL, SOUP_SOCKET_ERROR);

	priv = SOUP_SOCKET_GET_PRIVATE (sock);

	g_mutex_lock (priv->iolock);
	if (priv->read_buf)
		status = read_from_buf (sock, buffer, len, nread);
	else
		status = read_from_network (sock, buffer, len, nread, cancellable, error);
	g_mutex_unlock (priv->iolock);

	return status;
}

/**
 * soup_socket_read_until:
 * @sock: the socket
 * @buffer: buffer to read into
 * @len: size of @buffer in bytes
 * @boundary: boundary to read until
 * @boundary_len: length of @boundary in bytes
 * @nread: on return, the number of bytes read into @buffer
 * @got_boundary: on return, whether or not the data in @buffer
 * ends with the boundary string
 * @cancellable: a #GCancellable, or %NULL
 * @error: error pointer
 *
 * Like soup_socket_read(), but reads no further than the first
 * occurrence of @boundary. (If the boundary is found, it will be
 * included in the returned data, and *@got_boundary will be set to
 * %TRUE.) Any data after the boundary will returned in future reads.
 *
 * soup_socket_read_until() will almost always return fewer than @len
 * bytes: if the boundary is found, then it will only return the bytes
 * up until the end of the boundary, and if the boundary is not found,
 * then it will leave the last <literal>(boundary_len - 1)</literal>
 * bytes in its internal buffer, in case they form the start of the
 * boundary string. Thus, @len normally needs to be at least 1 byte
 * longer than @boundary_len if you want to make any progress at all.
 *
 * Return value: as for soup_socket_read()
 **/
SoupSocketIOStatus
soup_socket_read_until (SoupSocket *sock, gpointer buffer, gsize len,
			gconstpointer boundary, gsize boundary_len,
			gsize *nread, gboolean *got_boundary,
			GCancellable *cancellable, GError **error)
{
	SoupSocketPrivate *priv;
	SoupSocketIOStatus status;
	GByteArray *read_buf;
	guint match_len, prev_len;
	guint8 *p, *end;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), SOUP_SOCKET_ERROR);
	g_return_val_if_fail (nread != NULL, SOUP_SOCKET_ERROR);
	g_return_val_if_fail (len >= boundary_len, SOUP_SOCKET_ERROR);

	priv = SOUP_SOCKET_GET_PRIVATE (sock);

	g_mutex_lock (priv->iolock);

	*got_boundary = FALSE;

	if (!priv->read_buf)
		priv->read_buf = g_byte_array_new ();
	read_buf = priv->read_buf;

	if (read_buf->len < boundary_len) {
		prev_len = read_buf->len;
		g_byte_array_set_size (read_buf, len);
		status = read_from_network (sock,
					    read_buf->data + prev_len,
					    len - prev_len, nread, cancellable, error);
		read_buf->len = prev_len + *nread;

		if (status != SOUP_SOCKET_OK) {
			g_mutex_unlock (priv->iolock);
			return status;
		}
	}

	/* Scan for the boundary */
	end = read_buf->data + read_buf->len;
	for (p = read_buf->data; p <= end - boundary_len; p++) {
		if (!memcmp (p, boundary, boundary_len)) {
			p += boundary_len;
			*got_boundary = TRUE;
			break;
		}
	}

	/* Return everything up to 'p' (which is either just after the
	 * boundary, or @boundary_len - 1 bytes before the end of the
	 * buffer).
	 */
	match_len = p - read_buf->data;
	status = read_from_buf (sock, buffer, MIN (len, match_len), nread);

	g_mutex_unlock (priv->iolock);
	return status;
}

static gboolean
socket_write_watch (GSocket *gsock, GIOCondition cond, gpointer user_data)
{
	SoupSocket *sock = user_data;
	SoupSocketPrivate *priv = SOUP_SOCKET_GET_PRIVATE (sock);

	priv->write_src = NULL;

	if (cond & (G_IO_ERR | G_IO_HUP))
		soup_socket_disconnect (sock);
	else
		g_signal_emit (sock, signals[WRITABLE], 0);

	return FALSE;
}

/**
 * soup_socket_write:
 * @sock: the socket
 * @buffer: data to write
 * @len: size of @buffer, in bytes
 * @nwrote: on return, number of bytes written
 * @cancellable: a #GCancellable, or %NULL
 * @error: error pointer
 *
 * Attempts to write @len bytes from @buffer to @sock. If some data is
 * successfully written, the return status will be %SOUP_SOCKET_OK,
 * and *@nwrote will contain the number of bytes actually written
 * (which may be less than @len).
 *
 * If @sock is non-blocking, and no data could be written right away,
 * the return value will be %SOUP_SOCKET_WOULD_BLOCK. In this case,
 * the caller can connect to the #SoupSocket::writable signal to know
 * when more data can be written. (NB: #SoupSocket::writable is only
 * emitted after soup_socket_write() returns %SOUP_SOCKET_WOULD_BLOCK,
 * and it is only emitted once. See the documentation for
 * #SoupSocket:non-blocking.)
 *
 * Return value: a #SoupSocketIOStatus, as described above (or
 * %SOUP_SOCKET_EOF or %SOUP_SOCKET_ERROR. @error will be set if the
 * return value is %SOUP_SOCKET_ERROR.)
 **/
SoupSocketIOStatus
soup_socket_write (SoupSocket *sock, gconstpointer buffer,
		   gsize len, gsize *nwrote,
		   GCancellable *cancellable, GError **error)
{
	SoupSocketPrivate *priv;
	GError *my_err = NULL;
	gssize my_nwrote;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), SOUP_SOCKET_ERROR);
	g_return_val_if_fail (nwrote != NULL, SOUP_SOCKET_ERROR);

	priv = SOUP_SOCKET_GET_PRIVATE (sock);

	g_mutex_lock (priv->iolock);

	if (!priv->gsock) {
		g_mutex_unlock (priv->iolock);
		return SOUP_SOCKET_EOF;
	}
	if (priv->write_src) {
		g_mutex_unlock (priv->iolock);
		return SOUP_SOCKET_WOULD_BLOCK;
	}

	if (priv->tls_session) {
		my_nwrote = g_tls_session_send (priv->tls_session, buffer, len,
						cancellable, &my_err);
	} else {
		my_nwrote = g_socket_send (priv->gsock, buffer, len,
					   cancellable, &my_err);
	}
	if (my_nwrote > 0) {
		g_mutex_unlock (priv->iolock);
		g_clear_error (&my_err);
		*nwrote = my_nwrote;
		return SOUP_SOCKET_OK;
	}

	if (g_error_matches (my_err, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
		g_mutex_unlock (priv->iolock);

		priv->write_src =
			soup_socket_create_watch (priv,
						  G_IO_OUT | G_IO_HUP | G_IO_ERR, 
						  socket_write_watch, sock, cancellable);
		return SOUP_SOCKET_WOULD_BLOCK;
	} else if (g_error_matches (my_err, G_TLS_ERROR, G_TLS_ERROR_HANDSHAKE)) {
		my_err->domain = SOUP_SSL_ERROR;
		my_err->code = SOUP_SSL_ERROR_CERTIFICATE;
	}

	g_mutex_unlock (priv->iolock);
	g_propagate_error (error, my_err);
	return SOUP_SOCKET_ERROR;
}
