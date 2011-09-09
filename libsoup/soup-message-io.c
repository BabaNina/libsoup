/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-io.c: HTTP message I/O
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "soup-connection.h"
#include "soup-content-sniffer-stream.h"
#include "soup-converter-wrapper.h"
#include "soup-input-stream.h"
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"
#include "soup-misc.h"
#include "soup-output-stream.h"
#include "soup-socket.h"

typedef enum {
	SOUP_MESSAGE_IO_CLIENT,
	SOUP_MESSAGE_IO_SERVER
} SoupMessageIOMode;

typedef enum {
	SOUP_MESSAGE_IO_STATE_NOT_STARTED,
	SOUP_MESSAGE_IO_STATE_HEADERS,
	SOUP_MESSAGE_IO_STATE_BLOCKING,
	SOUP_MESSAGE_IO_STATE_BODY_START,
	SOUP_MESSAGE_IO_STATE_SNIFFING,
	SOUP_MESSAGE_IO_STATE_SNIFFED,
	SOUP_MESSAGE_IO_STATE_BODY,
	SOUP_MESSAGE_IO_STATE_BODY_DATA,
	SOUP_MESSAGE_IO_STATE_BODY_DONE,
	SOUP_MESSAGE_IO_STATE_TRAILERS,
	SOUP_MESSAGE_IO_STATE_FINISHING,
	SOUP_MESSAGE_IO_STATE_DONE
} SoupMessageIOState;

#define SOUP_MESSAGE_IO_STATE_ACTIVE(state) \
	(state != SOUP_MESSAGE_IO_STATE_NOT_STARTED && \
	 state != SOUP_MESSAGE_IO_STATE_BLOCKING && \
	 state != SOUP_MESSAGE_IO_STATE_DONE)

typedef struct {
	SoupMessageQueueItem *item;
	SoupMessageIOMode     mode;
	GCancellable         *cancellable;

	SoupSocket           *sock;
	SoupInputStream      *istream;
	GInputStream         *body_istream;
	SoupOutputStream     *ostream;
	GMainContext         *async_context;
	gboolean              blocking;

	SoupMessageIOState    read_state;
	SoupEncoding          read_encoding;
	GByteArray           *read_meta_buf;
	SoupMessageBody      *read_body;
	goffset               read_length;
	gboolean              read_eof_ok;
	gboolean              read_done;

	SoupContentSnifferStream *sniffer_stream;
	SoupBuffer           *sniffed_buffer;

	SoupMessageIOState    write_state;
	SoupEncoding          write_encoding;
	GString              *write_buf;
	SoupMessageBody      *write_body;
	SoupBuffer           *write_chunk;
	goffset               write_body_offset;
	goffset               write_length;
	goffset               written;

	GSource *read_source, *write_source;
	GSource *unpause_source;
	gboolean paused;

	SoupMessageGetHeadersFn   get_headers_cb;
	SoupMessageParseHeadersFn parse_headers_cb;
	gpointer                  header_data;
	SoupMessageCompletionFn   completion_cb;
	gpointer                  completion_data;
} SoupMessageIOData;
	

#define RESPONSE_BLOCK_SIZE 8192

void
soup_message_io_cleanup (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io;

	soup_message_io_stop (msg);

	io = priv->io_data;
	if (!io)
		return;
	priv->io_data = NULL;

	if (io->sock) {
		if (soup_socket_is_connected (io->sock)) {
			soup_input_stream_set_encoding (io->istream,
							SOUP_ENCODING_NONE, 0);
			soup_output_stream_set_encoding (io->ostream,
							 SOUP_ENCODING_NONE);
		}
		g_object_unref (io->sock);
	}
	if (io->istream)
		g_object_remove_weak_pointer (G_OBJECT (io->istream), (gpointer *)&io->istream);
	if (io->ostream)
		g_object_remove_weak_pointer (G_OBJECT (io->ostream), (gpointer *)&io->ostream);
	if (io->body_istream)
		g_object_unref (io->body_istream);
	if (io->async_context)
		g_main_context_unref (io->async_context);
	if (io->item)
		soup_message_queue_item_unref (io->item);

	g_byte_array_free (io->read_meta_buf, TRUE);

	g_string_free (io->write_buf, TRUE);
	if (io->write_chunk)
		soup_buffer_free (io->write_chunk);

	if (io->sniffed_buffer)
		soup_buffer_free (io->sniffed_buffer);

	g_slice_free (SoupMessageIOData, io);
}

void
soup_message_io_stop (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	if (!io)
		return;

	if (io->read_source) {
		g_source_destroy (io->read_source);
		io->read_source = NULL;
	}
	if (io->write_source) {
		g_source_destroy (io->write_source);
		io->write_source = NULL;
	}

	if (io->unpause_source) {
		g_source_destroy (io->unpause_source);
		io->unpause_source = NULL;
	}

	if (io->read_state < SOUP_MESSAGE_IO_STATE_FINISHING)
		soup_socket_disconnect (io->sock);
}

void
soup_message_io_finished (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;
	SoupMessageCompletionFn completion_cb = io->completion_cb;
	gpointer completion_data = io->completion_data;

	g_object_ref (msg);
	soup_message_io_cleanup (msg);
	if (completion_cb)
		completion_cb (msg, completion_data);
	g_object_unref (msg);
}

static gboolean io_read (SoupInputStream *stream, SoupMessage *msg);
static gboolean io_write (SoupOutputStream *stream, SoupMessage *msg);

static gboolean
request_is_idempotent (SoupMessage *msg)
{
	/* FIXME */
	return (msg->method == SOUP_METHOD_GET);
}

static void
io_error (SoupSocket *sock, SoupMessage *msg, GError *error)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	if (error && error->domain == G_TLS_ERROR) {
		soup_message_set_status_full (msg,
					      SOUP_STATUS_SSL_FAILED,
					      error->message);
	} else if (io->mode == SOUP_MESSAGE_IO_CLIENT &&
		   io->read_state <= SOUP_MESSAGE_IO_STATE_HEADERS &&
		   io->read_meta_buf->len == 0 &&
		   soup_connection_get_ever_used (io->item->conn) &&
		   !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT) &&
		   request_is_idempotent (msg)) {
		/* Connection got closed, but we can safely try again */
		io->item->state = SOUP_MESSAGE_RESTARTING;
	} else if (!SOUP_STATUS_IS_TRANSPORT_ERROR (msg->status_code))
		soup_message_set_status (msg, SOUP_STATUS_IO_ERROR);

	if (error)
		g_error_free (error);

	soup_message_io_finished (msg);
}

static void
setup_read_source (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	io->read_source = g_pollable_input_stream_create_source (
		G_POLLABLE_INPUT_STREAM (io->istream), NULL);
	g_source_set_callback (io->read_source,
			       (GSourceFunc) io_read, msg, NULL);
	g_source_attach (io->read_source, io->async_context);
	g_source_unref (io->read_source);
}

static void
setup_write_source (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	io->write_source = g_pollable_output_stream_create_source (
		G_POLLABLE_OUTPUT_STREAM (io->ostream),
		NULL);
	g_source_set_callback (io->write_source, (GSourceFunc) io_write, msg, NULL);
	g_source_attach (io->write_source, io->async_context);
}

/* Reads data from io->sock into io->read_meta_buf, up until a blank
 * line ("CRLF CRLF" or "LF LF").
 *
 * This function is used to read metadata, and read_body_chunk() is
 * used to read the message body contents.
 *
 * read_metadata, read_body_chunk, and write_data all use the same
 * convention for return values: if they return %TRUE, it means
 * they've completely finished the requested read/write, and the
 * caller should move on to the next step. If they return %FALSE, it
 * means that either (a) the socket returned SOUP_SOCKET_WOULD_BLOCK,
 * so the caller should give up for now and wait for the socket to
 * emit a signal, or (b) the socket returned an error, and io_error()
 * was called to process it and cancel the I/O. So either way, if the
 * function returns %FALSE, the caller should return immediately.
 */
static gboolean
read_metadata (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;
	guchar read_buf[RESPONSE_BLOCK_SIZE];
	gssize nread;
	gboolean got_lf;
	GError *error = NULL;

	if (!io->istream) {
		io_error (io->sock, msg, NULL);
		return FALSE;
	}

	while (1) {
		nread = soup_input_stream_read_line (io->istream,
						     read_buf, sizeof (read_buf),
						     io->cancellable, &error);

		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
			g_error_free (error);
			setup_read_source (msg);
			return FALSE;
		}

		if (nread > 0) {
			g_byte_array_append (io->read_meta_buf, read_buf, nread);
			got_lf = memchr (read_buf, '\n', nread) != NULL;
		} else {
			io_error (io->sock, msg, error);
			return FALSE;
		}

		if (got_lf) {
			if (nread == 1 &&
			    !strncmp ((char *)io->read_meta_buf->data +
				      io->read_meta_buf->len - 2,
				      "\n\n", 2))
				break;
			else if (nread == 2 &&
				 !strncmp ((char *)io->read_meta_buf->data +
					   io->read_meta_buf->len - 3,
					   "\n\r\n", 3))
				break;
		}
	}

	return TRUE;
}

static void
setup_body_istream (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;
	GConverter *decoder, *wrapper;
	GInputStream *filter;
	GSList *d;

	io->body_istream = g_object_ref (io->istream);

	for (d = priv->decoders; d; d = d->next) {
		decoder = d->data;
		wrapper = soup_converter_wrapper_new (decoder, msg);
		filter = g_object_new (G_TYPE_CONVERTER_INPUT_STREAM,
				       "base-stream", io->body_istream,
				       "close-base-stream", FALSE,
				       "converter", wrapper,
				       NULL);
		g_object_unref (io->body_istream);
		io->body_istream = filter;
	}

	if (priv->sniffer) {
		filter = soup_content_sniffer_stream_new (priv->sniffer,
							  msg, io->body_istream);
		io->sniffer_stream = SOUP_CONTENT_SNIFFER_STREAM (filter);
		g_object_unref (io->body_istream);
		io->body_istream = filter;
	}
}

static SoupBuffer *
do_read (SoupMessage *msg, guchar *read_buf, guint len)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;
	SoupBuffer *buffer;
	gssize nread;
	GError *error = NULL;

	if (priv->chunk_allocator) {
		buffer = priv->chunk_allocator (msg, io->read_length, priv->chunk_allocator_data);
		if (!buffer) {
			soup_message_io_pause (msg);
			return NULL;
		}
	} else {
		buffer = soup_buffer_new (SOUP_MEMORY_TEMPORARY,
					  read_buf, len);
	}

	nread = g_input_stream_read (io->body_istream,
				     (guchar *)buffer->data,
				     buffer->length,
				     io->cancellable, &error);
	if (nread > 0) {
		buffer->length = nread;
		io->read_length -= nread;

		soup_message_body_got_chunk (io->read_body, buffer);
		return buffer;
	}
	soup_buffer_free (buffer);

	if (nread == 0) {
		io->read_done = TRUE;
		return NULL;
	}

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
		g_error_free (error);
		setup_read_source (msg);
		return NULL;
	} else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT)) {
		g_clear_error (&error);
		if (io->read_eof_ok) {
			io->read_done = TRUE;
			return NULL;
		}
		/* else... */
	}

	io_error (io->sock, msg, error);
	return NULL;
}

static gssize
do_write (SoupMessage *msg, const char *data, guint len)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;
	gssize nwrote;
	GError *error = NULL;

	if (!io->ostream) {
		io_error (io->sock, msg, NULL);
		return -1;
	}

	nwrote = soup_output_stream_write (io->ostream,
					   data + io->written,
					   len - io->written,
					   io->cancellable, &error);

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
		g_error_free (error);
		setup_write_source (msg);
		g_source_unref (io->write_source);
		return -1;
	} else if (error) {
		io_error (io->sock, msg, error);
		return -1;
	}

	io->written += nwrote;
	return nwrote;
}

/*
 * There are two request/response formats: the basic request/response,
 * possibly with one or more unsolicited informational responses (such
 * as the WebDAV "102 Processing" response):
 *
 *     Client                            Server
 *      W:HEADERS  / R:NOT_STARTED    ->  R:HEADERS  / W:NOT_STARTED
 *      W:BODY     / R:NOT_STARTED    ->  R:BODY     / W:NOT_STARTED
 *     [W:DONE     / R:HEADERS (1xx)  <-  R:DONE     / W:HEADERS (1xx) ...]
 *      W:DONE     / R:HEADERS        <-  R:DONE     / W:HEADERS
 *      W:DONE     / R:BODY           <-  R:DONE     / W:BODY
 *      W:DONE     / R:DONE               R:DONE     / W:DONE
 *     
 * and the "Expect: 100-continue" request/response, with the client
 * blocking halfway through its request, and then either continuing or
 * aborting, depending on the server response:
 *
 *     Client                            Server
 *      W:HEADERS  / R:NOT_STARTED    ->  R:HEADERS  / W:NOT_STARTED
 *      W:BLOCKING / R:HEADERS        <-  R:BLOCKING / W:HEADERS
 *     [W:BODY     / R:BLOCKING       ->  R:BODY     / W:BLOCKING]
 *     [W:DONE     / R:HEADERS        <-  R:DONE     / W:HEADERS]
 *      W:DONE     / R:BODY           <-  R:DONE     / W:BODY
 *      W:DONE     / R:DONE               R:DONE     / W:DONE
 */

static gboolean
io_write (SoupOutputStream *stream, SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;
	SoupBuffer *chunk;
	gssize nwrote;

	if (io->write_source) {
		g_source_destroy (io->write_source);
		io->write_source = NULL;
	}

	g_object_ref (msg);

 write_more:
	switch (io->write_state) {
	case SOUP_MESSAGE_IO_STATE_NOT_STARTED:
		goto out;


	case SOUP_MESSAGE_IO_STATE_HEADERS:
		if (!io->write_buf->len) {
			io->get_headers_cb (msg, io->write_buf,
					    &io->write_encoding,
					    io->header_data);
			if (!io->write_buf->len) {
				soup_message_io_pause (msg);
				goto out;
			}
		}

		while (io->written < io->write_buf->len) {
			nwrote = do_write (msg,
					   io->write_buf->str + io->written,
					   io->write_buf->len - io->written);
			if (nwrote == -1)
				goto out;
			io->written += nwrote;
		}

		io->written = 0;
		g_string_truncate (io->write_buf, 0);

		if (io->write_encoding == SOUP_ENCODING_CONTENT_LENGTH) {
			SoupMessageHeaders *hdrs =
				(io->mode == SOUP_MESSAGE_IO_CLIENT) ?
				msg->request_headers : msg->response_headers;
			io->write_length = soup_message_headers_get_content_length (hdrs);
		}

		soup_output_stream_set_encoding (io->ostream, io->write_encoding);

		if (io->mode == SOUP_MESSAGE_IO_SERVER &&
		    SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) {
			if (msg->status_code == SOUP_STATUS_CONTINUE) {
				/* Stop and wait for the body now */
				io->write_state =
					SOUP_MESSAGE_IO_STATE_BLOCKING;
				io->read_state = SOUP_MESSAGE_IO_STATE_BODY_START;
			} else {
				/* We just wrote a 1xx response
				 * header, so stay in STATE_HEADERS.
				 * (The caller will pause us from the
				 * wrote_informational callback if he
				 * is not ready to send the final
				 * response.)
				 */
			}
		} else if (io->mode == SOUP_MESSAGE_IO_CLIENT &&
			   soup_message_headers_get_expectations (msg->request_headers) & SOUP_EXPECTATION_CONTINUE) {
			/* Need to wait for the Continue response */
			io->write_state = SOUP_MESSAGE_IO_STATE_BLOCKING;
			io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
		} else {
			io->write_state = SOUP_MESSAGE_IO_STATE_BODY;

			/* If the client was waiting for a Continue
			 * but we sent something else, then they're
			 * now done writing.
			 */
			if (io->mode == SOUP_MESSAGE_IO_SERVER &&
			    io->read_state == SOUP_MESSAGE_IO_STATE_BLOCKING)
				io->read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
		}

		if (SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) {
			soup_message_wrote_informational (msg);
			soup_message_cleanup_response (msg);
		} else
			soup_message_wrote_headers (msg);
		break;


	case SOUP_MESSAGE_IO_STATE_BLOCKING:
		io_read (io->istream, msg);

		/* If io_read reached a point where we could write
		 * again, it would have recursively called io_write.
		 * So (a) we don't need to try to keep writing, and
		 * (b) we can't anyway, because msg may have been
		 * destroyed.
		 */
		goto out;


	case SOUP_MESSAGE_IO_STATE_BODY:
		if (!io->write_length &&
		    io->write_encoding != SOUP_ENCODING_EOF &&
		    io->write_encoding != SOUP_ENCODING_CHUNKED) {
		wrote_body:
			io->write_state = SOUP_MESSAGE_IO_STATE_FINISHING;
			soup_message_wrote_body (msg);
			break;
		}

		if (!io->write_chunk) {
			io->write_chunk = soup_message_body_get_chunk (io->write_body, io->write_body_offset);
			if (!io->write_chunk) {
				soup_message_io_pause (msg);
				goto out;
			}
			if (io->write_encoding == SOUP_ENCODING_EOF) {
				if (!io->write_chunk->length)
					goto wrote_body;
			} else if (io->write_encoding == SOUP_ENCODING_CHUNKED) {
				io->write_length = io->write_chunk->length;
			} else if (io->write_chunk->length > io->write_length) {
				/* App is trying to write more than it
				 * claimed it would; we have to truncate.
				 */
				SoupBuffer *truncated =
					soup_buffer_new_subbuffer (io->write_chunk,
								   0, io->write_length);
				soup_buffer_free (io->write_chunk);
				io->write_chunk = truncated;
			}
		}

		nwrote = do_write (msg, io->write_chunk->data + io->written,
				   io->write_chunk->length - io->written);
		if (nwrote == -1)
			goto out;

		chunk = soup_buffer_new (SOUP_MEMORY_TEMPORARY,
					 io->write_chunk->data + io->written,
					 nwrote);
		io->written += nwrote;
		if (io->write_length)
			io->write_length -= nwrote;

		io->write_state = SOUP_MESSAGE_IO_STATE_BODY_DATA;
		soup_message_wrote_body_data (msg, chunk);
		soup_buffer_free (chunk);
		break;

	case SOUP_MESSAGE_IO_STATE_BODY_DATA:
		if (io->written < io->write_chunk->length)
			break;

		io->written = 0;
		if (io->write_chunk->length == 0)
			goto wrote_body;

		if (io->mode == SOUP_MESSAGE_IO_SERVER ||
		    priv->msg_flags & SOUP_MESSAGE_CAN_REBUILD)
			soup_message_body_wrote_chunk (io->write_body, io->write_chunk);
		io->write_body_offset += io->write_chunk->length;
		soup_buffer_free (io->write_chunk);
		io->write_chunk = NULL;

		io->write_state = SOUP_MESSAGE_IO_STATE_BODY;
		soup_message_wrote_chunk (msg);
		break;

	case SOUP_MESSAGE_IO_STATE_FINISHING:
		if (io->write_source) {
			g_source_destroy (io->write_source);
			io->write_source = NULL;
		}
		io->write_state = SOUP_MESSAGE_IO_STATE_DONE;

		if (io->mode == SOUP_MESSAGE_IO_CLIENT) {
			io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
			io_read (io->istream, msg);
		} else
			soup_message_io_finished (msg);
		goto out;


	case SOUP_MESSAGE_IO_STATE_DONE:
	default:
		g_warn_if_reached ();
	}

	if (priv->io_data == io && !io->paused)
		goto write_more;

 out:
	g_object_unref (msg);
	return FALSE;
}

static gboolean
io_read (SoupInputStream *stream, SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;
	guchar *stack_buf = NULL;
	SoupBuffer *buffer;
	guint status;
	const char *sniffed_mime_type;
	GHashTable *params = NULL;

	if (io->read_source) {
		g_source_destroy (io->read_source);
		io->read_source = NULL;
	}

	g_object_ref (msg);

 read_more:
	switch (io->read_state) {
	case SOUP_MESSAGE_IO_STATE_NOT_STARTED:
		goto out;


	case SOUP_MESSAGE_IO_STATE_HEADERS:
		if (!read_metadata (msg))
			goto out;

		/* We need to "rewind" io->read_meta_buf back one line.
		 * That SHOULD be two characters (CR LF), but if the
		 * web server was stupid, it might only be one.
		 */
		if (io->read_meta_buf->len < 3 ||
		    io->read_meta_buf->data[io->read_meta_buf->len - 2] == '\n')
			io->read_meta_buf->len--;
		else
			io->read_meta_buf->len -= 2;
		io->read_meta_buf->data[io->read_meta_buf->len] = '\0';
		status = io->parse_headers_cb (msg, (char *)io->read_meta_buf->data,
					       io->read_meta_buf->len,
					       &io->read_encoding,
					       io->header_data);
		g_byte_array_set_size (io->read_meta_buf, 0);

		if (status != SOUP_STATUS_OK) {
			/* Either we couldn't parse the headers, or they
			 * indicated something that would mean we wouldn't
			 * be able to parse the body. (Eg, unknown
			 * Transfer-Encoding.). Skip the rest of the
			 * reading, and make sure the connection gets
			 * closed when we're done.
			 */
			soup_message_set_status (msg, status);
			soup_message_headers_append (msg->request_headers,
						     "Connection", "close");
			io->read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
			break;
		}

		if (io->read_encoding == SOUP_ENCODING_EOF)
			io->read_eof_ok = TRUE;

		if (io->read_encoding == SOUP_ENCODING_CONTENT_LENGTH) {
			SoupMessageHeaders *hdrs =
				(io->mode == SOUP_MESSAGE_IO_CLIENT) ?
				msg->response_headers : msg->request_headers;
			io->read_length = soup_message_headers_get_content_length (hdrs);

			if (io->mode == SOUP_MESSAGE_IO_CLIENT &&
			    !soup_message_is_keepalive (msg)) {
				/* Some servers suck and send
				 * incorrect Content-Length values, so
				 * allow EOF termination in this case
				 * (iff the message is too short) too.
				 */
				io->read_eof_ok = TRUE;
			}
		}

		soup_input_stream_set_encoding (io->istream,
						io->read_encoding,
						io->read_length);

		if (io->mode == SOUP_MESSAGE_IO_CLIENT &&
		    SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) {
			if (msg->status_code == SOUP_STATUS_CONTINUE &&
			    io->write_state == SOUP_MESSAGE_IO_STATE_BLOCKING) {
				/* Pause the reader, unpause the writer */
				io->read_state =
					SOUP_MESSAGE_IO_STATE_BLOCKING;
				io->write_state =
					SOUP_MESSAGE_IO_STATE_BODY;
			} else {
				/* Just stay in HEADERS */
				io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
			}
		} else if (io->mode == SOUP_MESSAGE_IO_SERVER &&
			   soup_message_headers_get_expectations (msg->request_headers) & SOUP_EXPECTATION_CONTINUE) {
			/* The client requested a Continue response. The
			 * got_headers handler may change this to something
			 * else though.
			 */
			soup_message_set_status (msg, SOUP_STATUS_CONTINUE);
			io->write_state = SOUP_MESSAGE_IO_STATE_HEADERS;
			io->read_state = SOUP_MESSAGE_IO_STATE_BLOCKING;
		} else {
			io->read_state = SOUP_MESSAGE_IO_STATE_BODY_START;

			/* If the client was waiting for a Continue
			 * but got something else, then it's done
			 * writing.
			 */
			if (io->mode == SOUP_MESSAGE_IO_CLIENT &&
			    io->write_state == SOUP_MESSAGE_IO_STATE_BLOCKING)
				io->write_state = SOUP_MESSAGE_IO_STATE_FINISHING;
		}

		if (io->mode == SOUP_MESSAGE_IO_CLIENT &&
		    SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) {
			soup_message_got_informational (msg);
			soup_message_cleanup_response (msg);
		} else
			soup_message_got_headers (msg);
		break;


	case SOUP_MESSAGE_IO_STATE_BLOCKING:
		io_write (io->ostream, msg);

		/* As in the io_write case, we *must* return here. */
		goto out;


	case SOUP_MESSAGE_IO_STATE_BODY_START:
		if (io->read_encoding == SOUP_ENCODING_NONE ||
		    (io->read_encoding == SOUP_ENCODING_CONTENT_LENGTH &&
		     io->read_length == 0))
			io->read_done = TRUE;

		if (priv->sniffer)
			io->read_state = SOUP_MESSAGE_IO_STATE_SNIFFING;
		else if (io->read_done)
			io->read_state = SOUP_MESSAGE_IO_STATE_BODY_DONE;
		else
			io->read_state = SOUP_MESSAGE_IO_STATE_BODY;

		setup_body_istream (msg);
		break;


	case SOUP_MESSAGE_IO_STATE_SNIFFING:
		if (!io->istream) {
			io_error (io->sock, msg, NULL);
			goto out;
		}

		if (!priv->chunk_allocator && !stack_buf)
			stack_buf = alloca (RESPONSE_BLOCK_SIZE);

		io->sniffed_buffer = do_read (msg, stack_buf, RESPONSE_BLOCK_SIZE);
		if (!io->sniffed_buffer && !io->read_done)
			goto out;

		sniffed_mime_type = soup_content_sniffer_stream_sniff (io->sniffer_stream, &params);
		io->read_state = SOUP_MESSAGE_IO_STATE_SNIFFED;
		soup_message_content_sniffed (msg, sniffed_mime_type, params);
		break;


	case SOUP_MESSAGE_IO_STATE_SNIFFED:
		io->read_state = SOUP_MESSAGE_IO_STATE_BODY;
		buffer = io->sniffed_buffer;
		io->sniffed_buffer = NULL;
		if (buffer) {
			soup_message_got_chunk (msg, buffer);
			soup_buffer_free (buffer);
		}
		break;


	case SOUP_MESSAGE_IO_STATE_BODY:
		if (!io->istream) {
			io_error (io->sock, msg, NULL);
			goto out;
		}

		if (!priv->chunk_allocator && !stack_buf)
			stack_buf = alloca (RESPONSE_BLOCK_SIZE);

		buffer = do_read (msg, stack_buf, RESPONSE_BLOCK_SIZE);
		if (!buffer) {
			if (io->read_done) {
				io->read_state = SOUP_MESSAGE_IO_STATE_BODY_DONE;
				break;
			} else
				goto out;
		}

		soup_message_got_chunk (msg, buffer);
		soup_buffer_free (buffer);
		break;


	case SOUP_MESSAGE_IO_STATE_BODY_DONE:
		io->read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
		soup_message_got_body (msg);
		break;


	case SOUP_MESSAGE_IO_STATE_FINISHING:
		if (io->read_source) {
			g_source_destroy (io->read_source);
			io->read_source = NULL;
		}
		io->read_state = SOUP_MESSAGE_IO_STATE_DONE;

		if (io->mode == SOUP_MESSAGE_IO_SERVER) {
			io->write_state = SOUP_MESSAGE_IO_STATE_HEADERS;
			io_write (io->ostream, msg);
		} else
			soup_message_io_finished (msg);
		goto out;


	case SOUP_MESSAGE_IO_STATE_DONE:
	default:
		g_return_val_if_reached (FALSE);
	}

	if (priv->io_data == io && !io->paused)
		goto read_more;

 out:
	g_object_unref (msg);
	return FALSE;
}

static SoupMessageIOData *
new_iostate (SoupMessage *msg, SoupSocket *sock, SoupMessageIOMode mode,
	     SoupMessageGetHeadersFn get_headers_cb,
	     SoupMessageParseHeadersFn parse_headers_cb,
	     gpointer header_data,
	     SoupMessageCompletionFn completion_cb,
	     gpointer completion_data)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io;
	gboolean non_blocking;

	io = g_slice_new0 (SoupMessageIOData);
	io->mode = mode;
	io->get_headers_cb   = get_headers_cb;
	io->parse_headers_cb = parse_headers_cb;
	io->header_data      = header_data;
	io->completion_cb    = completion_cb;
	io->completion_data  = completion_data;

	io->sock = g_object_ref (sock);
	io->istream = SOUP_INPUT_STREAM (soup_socket_get_input_stream (sock));
	if (io->istream)
		g_object_add_weak_pointer (G_OBJECT (io->istream), (gpointer *)&io->istream);
	io->ostream = SOUP_OUTPUT_STREAM (soup_socket_get_output_stream (sock));
	if (io->ostream)
		g_object_add_weak_pointer (G_OBJECT (io->ostream), (gpointer *)&io->ostream);

	g_object_get (io->sock,
		      SOUP_SOCKET_FLAG_NONBLOCKING, &non_blocking,
		      SOUP_SOCKET_ASYNC_CONTEXT, &io->async_context,
		      NULL);
	io->blocking = !non_blocking;

	io->read_meta_buf    = g_byte_array_new ();
	io->write_buf        = g_string_new (NULL);

	io->read_state  = SOUP_MESSAGE_IO_STATE_NOT_STARTED;
	io->write_state = SOUP_MESSAGE_IO_STATE_NOT_STARTED;

	if (priv->io_data)
		soup_message_io_cleanup (msg);
	priv->io_data = io;
	return io;
}

void
soup_message_io_client (SoupMessageQueueItem *item,
			SoupMessageGetHeadersFn get_headers_cb,
			SoupMessageParseHeadersFn parse_headers_cb,
			gpointer header_data,
			SoupMessageCompletionFn completion_cb,
			gpointer completion_data)
{
	SoupMessageIOData *io;
	SoupSocket *sock = soup_connection_get_socket (item->conn);

	io = new_iostate (item->msg, sock, SOUP_MESSAGE_IO_CLIENT,
			  get_headers_cb, parse_headers_cb, header_data,
			  completion_cb, completion_data);

	io->item = item;
	soup_message_queue_item_ref (item);
	io->cancellable = item->cancellable;

	io->read_body       = item->msg->response_body;
	io->write_body      = item->msg->request_body;

	io->write_state     = SOUP_MESSAGE_IO_STATE_HEADERS;
	io_write (io->ostream, item->msg);
}

void
soup_message_io_server (SoupMessage *msg, SoupSocket *sock,
			SoupMessageGetHeadersFn get_headers_cb,
			SoupMessageParseHeadersFn parse_headers_cb,
			gpointer header_data,
			SoupMessageCompletionFn completion_cb,
			gpointer completion_data)
{
	SoupMessageIOData *io;

	io = new_iostate (msg, sock, SOUP_MESSAGE_IO_SERVER,
			  get_headers_cb, parse_headers_cb, header_data,
			  completion_cb, completion_data);

	io->read_body       = msg->request_body;
	io->write_body      = msg->response_body;

	io->read_state      = SOUP_MESSAGE_IO_STATE_HEADERS;
	io_read (io->istream, msg);
}

void  
soup_message_io_pause (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	g_return_if_fail (io != NULL);

	if (io->write_source) {
		g_source_destroy (io->write_source);
		io->write_source = NULL;
	}
	if (io->read_source) {
		g_source_destroy (io->read_source);
		io->read_source = NULL;
	}

	if (io->unpause_source) {
		g_source_destroy (io->unpause_source);
		io->unpause_source = NULL;
	}

	io->paused = TRUE;
}

static gboolean
io_unpause_internal (gpointer msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	g_return_val_if_fail (io != NULL, FALSE);
	io->unpause_source = NULL;
	io->paused = FALSE;

	if (io->write_source || io->read_source)
		return FALSE;

	if (SOUP_MESSAGE_IO_STATE_ACTIVE (io->write_state))
		io_write (io->ostream, msg);
	else if (SOUP_MESSAGE_IO_STATE_ACTIVE (io->read_state))
		io_read (io->istream, msg);

	return FALSE;
}

void
soup_message_io_unpause (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	g_return_if_fail (io != NULL);

	if (!io->blocking) {
		if (!io->unpause_source) {
			io->unpause_source = soup_add_completion (
				io->async_context, io_unpause_internal, msg);
		}
	} else
		io_unpause_internal (msg);
}

/**
 * soup_message_io_in_progress:
 * @msg: a #SoupMessage
 *
 * Tests whether or not I/O is currently in progress on @msg.
 *
 * Return value: whether or not I/O is currently in progress.
 **/
gboolean
soup_message_io_in_progress (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);

	return priv->io_data != NULL;
}
