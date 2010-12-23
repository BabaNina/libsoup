/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-converter-wrapper.c
 *
 * Copyright 2011 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>

#include "soup-converter-wrapper.h"
#include "soup-message.h"

enum {
	PROP_0,
	PROP_BASE_CONVERTER,
	PROP_MESSAGE
};

static void soup_converter_wrapper_iface_init (GConverterIface *iface);

G_DEFINE_TYPE_WITH_CODE (SoupConverterWrapper, soup_converter_wrapper, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (G_TYPE_CONVERTER,
						soup_converter_wrapper_iface_init))

struct _SoupConverterWrapperPrivate
{
	GConverter *base_converter;
	SoupMessage *msg;
	gboolean started;
};

static void
soup_converter_wrapper_finalize (GObject *object)
{
	SoupConverterWrapperPrivate *priv = SOUP_CONVERTER_WRAPPER (object)->priv;

	if (priv->base_converter)
		g_object_unref (priv->base_converter);

	G_OBJECT_CLASS (soup_converter_wrapper_parent_class)->finalize (object);
}


static void
soup_converter_wrapper_set_property (GObject      *object,
				     guint         prop_id,
				     const GValue *value,
				     GParamSpec   *pspec)
{
	SoupConverterWrapperPrivate *priv = SOUP_CONVERTER_WRAPPER (object)->priv;

	switch (prop_id) {
	case PROP_BASE_CONVERTER:
		priv->base_converter = g_value_dup_object (value);
		break;

	case PROP_MESSAGE:
		priv->msg = g_value_dup_object (value);
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_converter_wrapper_get_property (GObject    *object,
				     guint       prop_id,
				     GValue     *value,
				     GParamSpec *pspec)
{
	SoupConverterWrapperPrivate *priv = SOUP_CONVERTER_WRAPPER (object)->priv;

	switch (prop_id) {
	case PROP_BASE_CONVERTER:
		g_value_set_object (value, priv->base_converter);
		break;

	case PROP_MESSAGE:
		g_value_set_object (value, priv->msg);
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_converter_wrapper_init (SoupConverterWrapper *converter)
{
	converter->priv = G_TYPE_INSTANCE_GET_PRIVATE (converter,
						       SOUP_TYPE_CONVERTER_WRAPPER,
						       SoupConverterWrapperPrivate);
}

static void
soup_converter_wrapper_class_init (SoupConverterWrapperClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (SoupConverterWrapperPrivate));

	gobject_class->finalize = soup_converter_wrapper_finalize;
	gobject_class->get_property = soup_converter_wrapper_get_property;
	gobject_class->set_property = soup_converter_wrapper_set_property;

	g_object_class_install_property (gobject_class,
					 PROP_BASE_CONVERTER,
					 g_param_spec_object ("base-converter",
							      "Base GConverter",
							      "GConverter to wrap",
							      G_TYPE_CONVERTER,
							      G_PARAM_READWRITE |
							      G_PARAM_CONSTRUCT_ONLY |
							      G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (gobject_class,
					 PROP_MESSAGE,
					 g_param_spec_object ("message",
							      "Message",
							      "Associated SoupMessage",
							      SOUP_TYPE_MESSAGE,
							      G_PARAM_READWRITE |
							      G_PARAM_CONSTRUCT_ONLY |
							      G_PARAM_STATIC_STRINGS));
}

GConverter *
soup_converter_wrapper_new (GConverter  *base_converter,
			    SoupMessage *msg)
{
	return g_object_new (SOUP_TYPE_CONVERTER_WRAPPER,
			     "base-converter", base_converter,
			     "message", msg,
			     NULL);
}

static void
soup_converter_wrapper_reset (GConverter *converter)
{
	SoupConverterWrapperPrivate *priv = SOUP_CONVERTER_WRAPPER (converter)->priv;

	if (priv->base_converter)
		g_converter_reset (priv->base_converter);
}

static GConverterResult
soup_converter_wrapper_convert (GConverter *converter,
				const void *inbuf,
				gsize       inbuf_size,
				void       *outbuf,
				gsize       outbuf_size,
				GConverterFlags flags,
				gsize      *bytes_read,
				gsize      *bytes_written,
				GError    **error)
{
	SoupConverterWrapperPrivate *priv = SOUP_CONVERTER_WRAPPER (converter)->priv;

	if (priv->base_converter) {
		GConverterResult result;
		GError *my_error = NULL;

		result = g_converter_convert (priv->base_converter,
					      inbuf, inbuf_size,
					      outbuf, outbuf_size,
					      flags, bytes_read, bytes_written,
					      &my_error);
		if (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA) &&
		    !priv->started) {
			g_object_unref (priv->base_converter);
			priv->base_converter = NULL;
			goto pass_through;
		}

		if (result != G_CONVERTER_ERROR && !priv->started) {
			SoupMessageFlags flags = soup_message_get_flags (priv->msg);
			soup_message_set_flags (priv->msg, flags | SOUP_MESSAGE_CONTENT_DECODED);
			priv->started = TRUE;
		}

		return result;
	}

 pass_through:
	if (outbuf_size == 0) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_NO_SPACE,
			     "No space");
		return G_CONVERTER_ERROR;
	}

	if (outbuf_size >= inbuf_size) {
		memcpy (outbuf, inbuf, inbuf_size);
		*bytes_read = *bytes_written = inbuf_size;
		if (flags & G_CONVERTER_INPUT_AT_END)
			return G_CONVERTER_FINISHED;
		else if (flags & G_CONVERTER_FLUSH)
			return G_CONVERTER_FLUSHED;
		else
			return G_CONVERTER_CONVERTED;
	} else {
		memcpy (outbuf, inbuf, outbuf_size);
		*bytes_read = *bytes_written = outbuf_size;
		return G_CONVERTER_CONVERTED;
	}
}

static void
soup_converter_wrapper_iface_init (GConverterIface *iface)
{
	iface->convert = soup_converter_wrapper_convert;
	iface->reset = soup_converter_wrapper_reset;
}
