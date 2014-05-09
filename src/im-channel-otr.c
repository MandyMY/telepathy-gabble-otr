/*
 * Copyright (C) 2014 Collabora Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "config.h"
#include "im-channel-otr.h"

#include <glib/gi18n.h>

#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/privkey.h>

#include "_gdbus/Channel_Interface_OTR1.h"

#define DEBUG_FLAG GABBLE_DEBUG_IM
#include "connection.h"
#include "debug.h"
#include "presence-cache.h"
#include "util.h"

#define FINGERPRINT_LEN 20
#define OTR_PRIV_KEY "otr-priv"
#define GET_PRIV(self) g_object_get_data (G_OBJECT (self), OTR_PRIV_KEY)

typedef struct
{
  otrl_instag_t instag;
  OtrlMessageEvent last_msg_event;
  GabbleGDBusChannelInterfaceOTR1 *skeleton;
} OtrPrivate;

static OtrlUserState userstate = NULL;
static OtrlMessageAppOps *ui_ops_p = NULL;

static void
otr_private_free (OtrPrivate *priv)
{
  g_object_unref (priv->skeleton);
  g_slice_free (OtrPrivate, priv);
}

static gchar *
dup_filename (const gchar *basename)
{
  return g_build_filename (g_get_user_data_dir (), "telepathy", basename, NULL);
}

static gchar *
dup_instag_filename (void)
{
  return dup_filename ("otr-instag");
}

static gchar *
dup_privkey_filename (void)
{
  return dup_filename ("otr-privkey");
}
static gchar *
dup_fingerprint_filename (void)
{
  return dup_filename ("otr-fingerprint");
}

static const gchar *
get_self_id (GabbleIMChannel *self)
{
  TpBaseChannel *base_chan = (TpBaseChannel *) self;
  TpBaseConnection *base_conn = tp_base_channel_get_connection (base_chan);
  TpHandleRepoIface *contact_repo = tp_base_connection_get_handles (base_conn,
      TP_HANDLE_TYPE_CONTACT);

  return tp_handle_inspect (contact_repo,
      tp_base_connection_get_self_handle (base_conn));
}

static const gchar *
get_target_id (GabbleIMChannel *self)
{
  return _gabble_im_channel_get_peer_jid (self);
}

static void
inject_message (GabbleIMChannel *self,
    const gchar *message)
{
  TpBaseChannel *base_chan = (TpBaseChannel *) self;
  TpBaseConnection *base_conn = tp_base_channel_get_connection (base_chan);
  WockyPorter *porter;
  WockyStanza *stanza;
  WockyNode *node;
  gchar *id;

  id = gabble_generate_id ();
  stanza = wocky_stanza_build (WOCKY_STANZA_TYPE_MESSAGE,
      WOCKY_STANZA_SUB_TYPE_CHAT,
      NULL, get_target_id (self),
      '@', "id", id,
      '*', &node,
      NULL);
  g_free (id);

  wocky_node_add_child_with_content (node, "body", message);

  porter = gabble_connection_dup_porter ((GabbleConnection *) base_conn);
  wocky_porter_send_async (porter, stanza, NULL, NULL, NULL);
  g_object_unref (porter);
  g_object_unref (stanza);
}

static void notify (GabbleIMChannel *self,
    OtrlMessageEvent msg_event,
    const gchar *format, ...) G_GNUC_PRINTF (3, 4);

static void
notify (GabbleIMChannel *self,
    OtrlMessageEvent msg_event,
    const gchar *format,
    ...)
{
  TpBaseChannel *base_chan = (TpBaseChannel *) self;
  TpBaseConnection *base_conn = tp_base_channel_get_connection (base_chan);
  va_list args;
  TpMessage *message;
  gchar *text;

  va_start (args, format);
  text = g_strdup_vprintf (format, args);
  va_end (args);

  message = tp_cm_message_new_text (base_conn,
      tp_base_channel_get_target_handle (base_chan),
      TP_CHANNEL_TEXT_MESSAGE_TYPE_NOTICE, text);
  tp_message_set_uint32 (message, 0, "otr-msg-event", msg_event);

  /* FIXME: There should be no sender for a notification, but setting handle to
   * 0 makes empathy crash atm. */
  tp_message_mixin_take_received (G_OBJECT (self), message);

  g_free (text);
}

typedef enum
{
  TRUST_LEVEL_NOT_PRIVATE,
  TRUST_LEVEL_UNVERIFIED,
  TRUST_LEVEL_PRIVATE,
  TRUST_LEVEL_FINISHED
} TrustLevel;

static GVariant *
fp_raw_to_variant (guchar *fp_raw)
{
  if (fp_raw != NULL && fp_raw[0] != '\0')
    {
      gchar display_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

      otrl_privkey_hash_to_human (display_fp, fp_raw);
      return g_variant_new ("(s@ay)", display_fp,
          g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, fp_raw,
              FINGERPRINT_LEN, sizeof (guchar)));
    }

  return g_variant_new ("(say)", "", NULL);
}

static GVariant *
fp_to_variant (Fingerprint *fp)
{
  return fp_raw_to_variant (fp != NULL ? fp->fingerprint : NULL);
}

static void
update_properties (GabbleIMChannel *self)
{
  OtrPrivate *priv = GET_PRIV (self);
  ConnContext *context;
  TrustLevel level = TRUST_LEVEL_NOT_PRIVATE;
  Fingerprint *their_fp = NULL;
  guchar our_fp_raw[FINGERPRINT_LEN];

  context = otrl_context_find (userstate, get_target_id (self),
      get_self_id (self), "xmpp", priv->instag, 0, NULL, NULL, NULL);

  if (context != NULL)
    {
      if (context->msgstate == OTRL_MSGSTATE_ENCRYPTED)
        {
          their_fp = context->active_fingerprint;

          if (otrl_context_is_fingerprint_trusted (their_fp))
            level = TRUST_LEVEL_PRIVATE;
          else
            level = TRUST_LEVEL_UNVERIFIED;
        }
      else if (context->msgstate == OTRL_MSGSTATE_FINISHED)
        {
          level = TRUST_LEVEL_FINISHED;
        }
    }

  otrl_privkey_fingerprint_raw (userstate, our_fp_raw, get_self_id (self),
      "xmpp");

  gabble_gdbus_channel_interface_otr1_set_trust_level (priv->skeleton, level);
  gabble_gdbus_channel_interface_otr1_set_remote_fingerprint (priv->skeleton,
      fp_to_variant (their_fp));
  gabble_gdbus_channel_interface_otr1_set_local_fingerprint (priv->skeleton,
      fp_raw_to_variant (our_fp_raw));
}

static OtrlPolicy
otr_policy (void *opdata,
    ConnContext *context)
{
  return OTRL_POLICY_MANUAL;
}

static void
otr_create_privkey (void *opdata,
    const gchar *accountname,
    const gchar *protocol)
{
  gchar *filename;

  filename = dup_privkey_filename ();
  otrl_privkey_generate (userstate, filename, accountname, protocol);
  g_free (filename);
}

static gint
otr_is_logged_in (void *opdata,
    const gchar *accountname,
    const gchar *protocol,
    const gchar *recipient)
{
  GabbleIMChannel *self = opdata;
  TpBaseChannel *base_chan = (TpBaseChannel *) self;
  TpBaseConnection *base_conn = tp_base_channel_get_connection (base_chan);
  TpHandleRepoIface *contact_repo = tp_base_connection_get_handles (base_conn,
      TP_HANDLE_TYPE_CONTACT);
  GabbleConnection *conn = (GabbleConnection *) base_conn;
  GabblePresence *presence;
  TpHandle contact;

  contact = tp_handle_lookup (contact_repo, recipient, NULL, NULL);
  if (contact == 0)
    return -1;

  presence = gabble_presence_cache_get (conn->presence_cache, contact);
  if (presence == NULL)
    return -1;

  return (presence->status > GABBLE_PRESENCE_LAST_UNAVAILABLE) ? 1 : 0;
}

static void
otr_inject_message (void *opdata,
    const gchar *accountname,
    const gchar *protocol,
    const gchar *recipient,
    const gchar *message)
{
  inject_message (opdata, message);
}

static void
otr_update_context_list (void *opdata)
{
  update_properties (opdata);
}

static void
otr_new_fingerprint (void *opdata,
    OtrlUserState us,
    const gchar *accountname,
    const gchar *protocol,
    const gchar *username,
    guchar fingerprint[FINGERPRINT_LEN])
{
  update_properties (opdata);
}

static void
otr_write_fingerprints (void *opdata)
{
  gchar *filename;

  filename = dup_fingerprint_filename ();
  otrl_privkey_write_fingerprints (userstate, filename);
  g_free (filename);
}

static void
otr_gone_secure (void *opdata,
    ConnContext *context)
{
  update_properties (opdata);
}

static void
otr_gone_insecure (void *opdata,
    ConnContext *context)
{
  update_properties (opdata);
}

static void
otr_still_secure (void *opdata,
    ConnContext *context,
    gint is_reply)
{
  update_properties (opdata);
}

static gint
otr_max_message_size (void *opdata,
    ConnContext *context)
{
  return 0;
}

static const gchar *
otr_error_message (void *opdata,
    ConnContext *context,
    OtrlErrorCode err_code)
{
  gchar *err_msg = NULL;

  /* Those messages are sent to the other end. We can't translate them since
   * we don't know if the other end speaks the same language as user's current
   * locale. So that's "international English". */
  switch (err_code)
    {
      case OTRL_ERRCODE_NONE:
        break;
      case OTRL_ERRCODE_ENCRYPTION_ERROR:
        err_msg = g_strdup ("Error occurred encrypting message.");
        break;
      case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE:
        if (context)
          {
            err_msg = g_strdup_printf ("You sent encrypted data to %s, who"
                " wasn't expecting it.", context->accountname);
          }
        break;
      case OTRL_ERRCODE_MSG_UNREADABLE:
        err_msg = g_strdup ("You transmitted an unreadable encrypted message.");
        break;
      case OTRL_ERRCODE_MSG_MALFORMED:
        err_msg = g_strdup ("You transmitted a malformed data message.");
        break;
    }

  return err_msg;
}

static void
otr_error_message_free (void *opdata,
    const gchar *err_msg)
{
  g_free ((gchar *) err_msg);
}

static const gchar *
otr_resent_msg_prefix (void *opdata,
    ConnContext *context)
{
  return g_strdup ("[resent]");
}

static void
otr_resent_msg_prefix_free (void *opdata,
    const gchar *prefix)
{
  g_free ((gchar *) prefix);
}

static void
otr_handle_msg_event (void *opdata,
    OtrlMessageEvent msg_event,
    ConnContext *context,
    const gchar *message,
    gcry_error_t err)
{
  GabbleIMChannel *self = opdata;
  OtrPrivate *priv = GET_PRIV (self);

  switch (msg_event)
    {
      case OTRL_MSGEVENT_NONE:
        break;

      case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
        notify (self, msg_event, "Unencrypted messages to this recipient are "
            "not allowed. Attempting to start a private conversation.\n\nYour "
            "message will be retransmitted when the private conversation "
            "starts.");
        break;

      case OTRL_MSGEVENT_ENCRYPTION_ERROR:
        notify (self, msg_event, "An error occurred when encrypting your "
            "message and not sent.");
        break;

      case OTRL_MSGEVENT_CONNECTION_ENDED:
        notify (self, msg_event, "Your message was not sent because %s closed "
            "their connection. Either close your private connection, or "
            "refresh it.",
            context->username);
        break;

      case OTRL_MSGEVENT_SETUP_ERROR:
        if (!err)
          err = GPG_ERR_INV_VALUE;

        switch (gcry_err_code (err))
          {
            case GPG_ERR_INV_VALUE:
              notify (self, msg_event, "Error setting up private conversation: "
                  "Malformed message received");
              break;
            default:
              notify (self, msg_event, "Error setting up private conversation: "
                  "%s", gcry_strerror (err));
              break;
          }
        break;

      case OTRL_MSGEVENT_MSG_REFLECTED:
        notify (self, msg_event, "You are either trying to talk to yourself, "
                "or someone is reflecting your messages back "
                "at you.");
        break;

      case OTRL_MSGEVENT_MSG_RESENT:
        notify (self, msg_event, "The last message to %s was resent.",
            context->username);
        break;

      case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
        notify (self, msg_event, "The encrypted message received from %s is "
            "unreadable, as you are not currently communicating privately.",
            context->username);
        break;

      case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
        notify (self, msg_event, "We received an unreadable encrypted message "
            "from %s.", context->username);
        break;

      case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
        notify (self, msg_event, "We received a malformed data message from %s.",
            context->username);
        break;

      case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
        DEBUG ("Heartbeat received from %s", context->username);
        break;

      case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
        DEBUG ("Heartbeat sent to %s", context->accountname);
        break;

      case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
        notify (self, msg_event, "OTR Error: %s", message);
        break;

      case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
        notify (self, msg_event, "The following message received from %s was "
            "*not* encrypted: %s", context->username, message);
        break;

      case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
        DEBUG ("Unrecognized OTR message received from %s.", context->username);
        break;

      case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
        if (priv->last_msg_event == msg_event)
          break;

        notify (self, msg_event, "%s has sent a message intended for a "
            "different session. If you are logged in multiple times, another "
            "session may have received the message.", context->username);
        break;
    }

  priv->last_msg_event = msg_event;
}

static void
otr_create_instag (void *opdata,
    const gchar *accountname,
    const gchar *protocol)
{
  gchar *filename;

  filename = dup_instag_filename ();
  otrl_instag_generate (userstate, filename, accountname, protocol);
  g_free (filename);
}

static gboolean
timeout_cb (gpointer user_data)
{
  otrl_message_poll (userstate, ui_ops_p, NULL);

  return G_SOURCE_CONTINUE;
}

static void
otr_timer_control (void *opdata,
    guint interval)
{
  static guint timeout_id = 0;

  if (timeout_id != 0)
    {
      g_source_remove (timeout_id);
      timeout_id = 0;
    }

  if (interval > 0)
    timeout_id = g_timeout_add_seconds (interval, timeout_cb, NULL);
}

static OtrlMessageAppOps ui_ops =
{
  otr_policy,
  otr_create_privkey,
  otr_is_logged_in,
  otr_inject_message,
  otr_update_context_list,
  otr_new_fingerprint,
  otr_write_fingerprints,
  otr_gone_secure,
  otr_gone_insecure,
  otr_still_secure,
  otr_max_message_size,
  NULL, /* account_name */
  NULL, /* account_name_free */
  NULL, /* received_symkey */
  otr_error_message,
  otr_error_message_free,
  otr_resent_msg_prefix,
  otr_resent_msg_prefix_free,
  NULL, /* handle_smp_event */
  otr_handle_msg_event,
  otr_create_instag,
  NULL,      /* convert_data */
  NULL,      /* convert_data_free */
  otr_timer_control
};

static void
global_init (void)
{
  gchar *filename;

  if (userstate != NULL)
    return;

  OTRL_INIT;
  ui_ops_p = &ui_ops;

  userstate = otrl_userstate_create ();

  filename = dup_filename (NULL);
  g_mkdir_with_parents (filename, 0700);
  g_free (filename);

  filename = dup_privkey_filename ();
  otrl_privkey_read (userstate, filename);
  g_free (filename);

  filename = dup_instag_filename ();
  otrl_instag_read (userstate, filename);
  g_free (filename);

  filename = dup_fingerprint_filename ();
  otrl_privkey_read_fingerprints (userstate, filename, NULL, NULL);
  g_free (filename);
}

static gboolean
handle_initialize_cb (GabbleGDBusChannelInterfaceOTR1 *skeleton,
    GDBusMethodInvocation *invocation,
    GabbleIMChannel *self)
{
  gchar *msg;

  msg = otrl_proto_default_query_msg (get_self_id (self), OTRL_POLICY_MANUAL);
  inject_message (self, msg);
  free (msg);

  gabble_gdbus_channel_interface_otr1_complete_initialize (skeleton,
      invocation);

  return TRUE;
}

static gboolean
handle_stop_cb (GabbleGDBusChannelInterfaceOTR1 *skeleton,
    GDBusMethodInvocation *invocation,
    GabbleIMChannel *self)
{
  OtrPrivate *priv = GET_PRIV (self);

  otrl_message_disconnect (userstate, ui_ops_p, self, get_self_id (self),
      "xmpp", get_target_id (self), priv->instag);

  gabble_gdbus_channel_interface_otr1_complete_stop (skeleton,
      invocation);

  return TRUE;
}

static gboolean
handle_trust_fingerprint_cb (GabbleGDBusChannelInterfaceOTR1 *skeleton,
    GDBusMethodInvocation *invocation,
    GVariant *fp_variant,
    gboolean trust,
    GabbleIMChannel *self)
{
  OtrPrivate *priv = GET_PRIV (self);
  ConnContext *context;
  const guchar *fp_data;
  Fingerprint *fp;

  context = otrl_context_find (userstate, get_target_id (self),
      get_self_id (self), "xmpp", priv->instag, 0, NULL, NULL, NULL);
  if (context == NULL)
    {
      g_dbus_method_invocation_return_error_literal (invocation, G_DBUS_ERROR,
          G_DBUS_ERROR_FAILED, "Couldn't find OTR context");
      return TRUE;
    }

  fp_data = g_variant_get_data (fp_variant);
  fp = otrl_context_find_fingerprint (context, (guchar *) fp_data, 0, NULL);
  if (fp == NULL)
    {
      g_dbus_method_invocation_return_error_literal (invocation, G_DBUS_ERROR,
          G_DBUS_ERROR_INVALID_ARGS, "Couldn't find fingerprint");
      return TRUE;
    }

  otrl_context_set_trust (fp, trust ? "verified" : "");
  otr_write_fingerprints (self);
  update_properties (self);

  gabble_gdbus_channel_interface_otr1_complete_trust_fingerprint (skeleton,
      invocation);

  return TRUE;
}

static void
unown_name_id (gpointer user_data)
{
  g_bus_unown_name (GPOINTER_TO_UINT (user_data));
}

static void
ensure_own_name (TpBaseConnection *base_conn,
    GDBusConnection *dbus)
{
  guint id;
  gchar *bus_name;

  /* This is a hack that will go away in tp1.0: we need to own a name with that
   * GDBusConnection.
   */

  id = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (base_conn),
      "otr-own-name-id"));
  if (id != 0)
    return;

  bus_name = g_strconcat (tp_base_connection_get_bus_name (base_conn),
      ".OTR", NULL);
  id = g_bus_own_name_on_connection (dbus, bus_name,
      G_BUS_NAME_OWNER_FLAGS_NONE, NULL, NULL, NULL, NULL);
  g_object_set_data_full (G_OBJECT (base_conn), "otr-own-name-id",
      GUINT_TO_POINTER (id), unown_name_id);
  g_free (bus_name);
}

void
gabble_im_channel_otr_init (GabbleIMChannel *self)
{
  TpBaseChannel *base_chan = (TpBaseChannel *) self;
  TpBaseConnection *base_conn = tp_base_channel_get_connection (base_chan);
  OtrPrivate *priv;
  GDBusConnection *dbus;

  global_init ();

  priv = g_slice_new0 (OtrPrivate);
  priv->instag = OTRL_INSTAG_BEST;
  priv->last_msg_event = OTRL_MSGEVENT_NONE;
  priv->skeleton = gabble_gdbus_channel_interface_otr1_skeleton_new ();
  g_object_set_data_full (G_OBJECT (self), OTR_PRIV_KEY, priv,
     (GDestroyNotify) otr_private_free);

  g_signal_connect (priv->skeleton, "handle-initialize",
      G_CALLBACK (handle_initialize_cb), self);
  g_signal_connect (priv->skeleton, "handle-stop",
      G_CALLBACK (handle_stop_cb), self);
  g_signal_connect (priv->skeleton, "handle-trust-fingerprint",
      G_CALLBACK (handle_trust_fingerprint_cb), self);
  update_properties (self);

  dbus = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, NULL);
  g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->skeleton),
      dbus, tp_base_channel_get_object_path (base_chan), NULL);
  ensure_own_name (base_conn, dbus);
  g_object_unref (dbus);
}

void
gabble_im_channel_otr_close (GabbleIMChannel *self)
{
  OtrPrivate *priv = GET_PRIV (self);

  otrl_message_disconnect (userstate, ui_ops_p, self, get_self_id (self),
      "xmpp", get_target_id (self), priv->instag);
}

gboolean
gabble_im_channel_otr_sending (GabbleIMChannel *self,
    WockyStanza *stanza,
    GError **error)
{
  OtrPrivate *priv = GET_PRIV (self);
  WockyNode *node;
  const gchar *content;
  gchar *new_content;
  gcry_error_t err;

  node = wocky_stanza_get_top_node (stanza);
  content = wocky_node_get_content_from_child (node, "body");

  err = otrl_message_sending (userstate, ui_ops_p, self,
      get_self_id (self), "xmpp", get_target_id (self),
      priv->instag, content, NULL, &new_content,
      OTRL_FRAGMENT_SEND_ALL_BUT_LAST, NULL,
      NULL, NULL);

  if (err)
    {
      g_set_error_literal (error, TP_ERROR, TP_ERROR_ENCRYPTION_ERROR,
          gcry_strerror (err));
      return FALSE;
    }

  if (new_content != NULL)
    {
      node = wocky_node_get_child (node, "body");
      wocky_node_set_content (node, new_content);
    }

  otrl_message_free (new_content);

  return TRUE;
}

gboolean
gabble_im_channel_otr_receiving (GabbleIMChannel *self,
    TpMessage *message)
{
  ConnContext *context;
  OtrlTLV *tlvs = NULL;
  gchar *content;
  gchar *new_content;
  gboolean ignore;

  content = tp_message_to_text (message, NULL);
  ignore = otrl_message_receiving (userstate, ui_ops_p, self,
      get_self_id (self), "xmpp", get_target_id (self), content,
      &new_content, &tlvs, &context, NULL, NULL);
  g_free (content);

  if (otrl_tlv_find (tlvs, OTRL_TLV_DISCONNECTED) != NULL)
    update_properties (self);
  otrl_tlv_free(tlvs);

  if (!ignore)
    {
      if (new_content != NULL)
        tp_message_set_string (message, 1, "content", new_content);

      if (context->active_fingerprint != NULL)
        {
          gchar display_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

          otrl_privkey_hash_to_human (display_fp,
              context->active_fingerprint->fingerprint);
          tp_message_set_string (message, 0, "otr-sender-fingerprint",
              display_fp);
        }
    }

  otrl_message_free (new_content);

  return ignore;
}
