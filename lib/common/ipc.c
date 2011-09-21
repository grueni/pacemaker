/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

#include <crm_internal.h>

#include <sys/param.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/cluster.h>

xmlNode *
xmlfromIPC(crm_ipcc_connection * ch, int timeout)
{
    xmlNode *xml = NULL;
    HA_Message *msg = NULL;

#if HAVE_MSGFROMIPC_TIMEOUT
    int ipc_rc = IPC_OK;

    msg = msgfromIPC_timeout(ch, MSG_ALLOWINTR, timeout, &ipc_rc);

    if (ipc_rc == IPC_TIMEOUT) {
        crm_warn("No message received in the required interval (%ds)", timeout);
        return NULL;

    } else if (ipc_rc == IPC_BROKEN) {
        crm_debug("Peer disconnected");
        return NULL;

    } else if (ipc_rc != IPC_OK) {
        crm_err("msgfromIPC_timeout failed: rc=%d", ipc_rc);
        return NULL;

    } else if (msg == NULL) {
        crm_err("Empty reply from msgfromIPC_timeout");
        return NULL;
    }
#else
    static gboolean do_show_error = TRUE;

    if (timeout && do_show_error) {
        crm_err("Timeouts are not supported by the current heartbeat libraries");
        do_show_error = FALSE;
    }

    msg = msgfromIPC_noauth(ch);
    if (msg == NULL) {
        crm_debug("Empty reply from msgfromIPC_noauth");
        return NULL;
    }
#endif

    xml = convert_ha_message(NULL, msg, __FUNCTION__);
    CRM_CHECK(xml != NULL, crm_err("Invalid ipc message"));
    crm_msg_del(msg);
    return xml;
}

static int
xml2ipcchan(xmlNode * m, crm_ipcc_connection * ch)
{
    HA_Message *msg = NULL;
    IPC_Message *imsg = NULL;

    if (m == NULL || ch == NULL) {
        crm_err("Invalid msg2ipcchan argument");
        errno = EINVAL;
        return HA_FAIL;
    }

    msg = convert_xml_message(m);
    if ((imsg = hamsg2ipcmsg(msg, ch)) == NULL) {
        crm_err("hamsg2ipcmsg() failure");
        crm_msg_del(msg);
        return HA_FAIL;
    }
    crm_msg_del(msg);

    if (ch->ops->send(ch, imsg) != IPC_OK) {
        if (ch->ch_status == IPC_CONNECT) {
            snprintf(ch->failreason, MAXFAILREASON,
                     "send failed,farside_pid=%d, sendq length=%ld(max is %ld)",
                     ch->farside_pid, (long)ch->send_queue->current_qlen,
                     (long)ch->send_queue->max_qlen);
        }
        imsg->msg_done(imsg);
        return HA_FAIL;
    }
    return HA_OK;
}

/* frees msg */
gboolean
send_ipc_message(crm_ipcc_connection * ipc_client, xmlNode * msg)
{
    gboolean all_is_good = TRUE;
    int fail_level = LOG_WARNING;

    if (ipc_client != NULL && ipc_client->conntype == IPC_CLIENT) {
        fail_level = LOG_ERR;
    }

    if (msg == NULL) {
        crm_err("cant send NULL message");
        all_is_good = FALSE;

    } else if (ipc_client == NULL) {
        crm_err("cant send message without an IPC Channel");
        all_is_good = FALSE;

    } else if (ipc_client->ops->get_chan_status(ipc_client) != IPC_CONNECT) {
        do_crm_log(fail_level, "IPC Channel to %d is not connected", (int)ipc_client->farside_pid);
        all_is_good = FALSE;
    }

    if (all_is_good && xml2ipcchan(msg, ipc_client) != HA_OK) {
        do_crm_log(fail_level, "Could not send IPC message to %d", (int)ipc_client->farside_pid);
        all_is_good = FALSE;

        if (ipc_client->ops->get_chan_status(ipc_client) != IPC_CONNECT) {
            do_crm_log(fail_level,
                       "IPC Channel to %d is no longer connected", (int)ipc_client->farside_pid);

        } else if (ipc_client->conntype == IPC_CLIENT) {
            if (ipc_client->send_queue->current_qlen >= ipc_client->send_queue->max_qlen) {
                crm_err("Send queue to %d (size=%d) full.",
                        ipc_client->farside_pid, (int)ipc_client->send_queue->max_qlen);
            }
        }
    }
    /* crm_log_xml(all_is_good?LOG_MSG:LOG_WARNING,"IPC[outbound]",msg); */

    return all_is_good;
}

gboolean
send_ipcs_message(crm_ipcs_connection * ipc_client, xmlNode * msg)
{
    gboolean all_is_good = TRUE;
    int fail_level = LOG_WARNING;

    if (ipc_client != NULL && ipc_client->conntype == IPC_CLIENT) {
        fail_level = LOG_ERR;
    }

    if (msg == NULL) {
        crm_err("cant send NULL message");
        all_is_good = FALSE;

    } else if (ipc_client == NULL) {
        crm_err("cant send message without an IPC Channel");
        all_is_good = FALSE;

    } else if (ipc_client->ops->get_chan_status(ipc_client) != IPC_CONNECT) {
        do_crm_log(fail_level, "IPC Channel to %d is not connected", (int)ipc_client->farside_pid);
        all_is_good = FALSE;
    }

    if (all_is_good && xml2ipcchan(msg, ipc_client) != HA_OK) {
        do_crm_log(fail_level, "Could not send IPC message to %d", (int)ipc_client->farside_pid);
        all_is_good = FALSE;

        if (ipc_client->ops->get_chan_status(ipc_client) != IPC_CONNECT) {
            do_crm_log(fail_level,
                       "IPC Channel to %d is no longer connected", (int)ipc_client->farside_pid);

        } else if (ipc_client->conntype == IPC_CLIENT) {
            if (ipc_client->send_queue->current_qlen >= ipc_client->send_queue->max_qlen) {
                crm_err("Send queue to %d (size=%d) full.",
                        ipc_client->farside_pid, (int)ipc_client->send_queue->max_qlen);
            }
        }
    }
    /* crm_log_xml(all_is_good?LOG_MSG:LOG_WARNING,"IPC[outbound]",msg); */

    return all_is_good;
}

void
default_ipc_connection_destroy(gpointer user_data)
{
    return;
}


#ifdef LIBQB_IPC
struct gio_to_qb_poll {
	int32_t is_used;
	GIOChannel *channel;
	int32_t events;
	void * data;
	qb_ipcs_dispatch_fn_t fn;
	enum qb_loop_priority p;
};

static qb_array_t *gio_map;

static gboolean
gio_read_socket (GIOChannel *gio, GIOCondition condition, gpointer data)
{
    struct gio_to_qb_poll *adaptor = (struct gio_to_qb_poll *)data;
    gint fd = g_io_channel_unix_get_fd(gio);

    return (adaptor->fn(fd, condition, adaptor->data) == 0);
}

static int32_t pcmk_ipcs_dispatch_add(enum qb_loop_priority p, int32_t fd, int32_t evts,
                                 void *data, qb_ipcs_dispatch_fn_t fn)
{
    struct gio_to_qb_poll *adaptor;
    GIOChannel *channel;
    int32_t res = 0;

    res = qb_array_grow(gio_map, fd + 1);
    if (res < 0) {
        return res;
    }
    res = qb_array_index(gio_map, fd, (void**)&adaptor);
    if (res < 0) {
        return res;
    }
    if (adaptor->is_used) {
        return -EEXIST;
    }

    channel = g_io_channel_unix_new(fd);
    if (!channel) {
        return -ENOMEM;
    }

    adaptor->channel = channel;
    adaptor->fn = fn;
    adaptor->events = evts;
    adaptor->data = data;
    adaptor->p = p;
    adaptor->is_used = QB_TRUE;

    g_io_add_watch(channel, evts, gio_read_socket, adaptor);
    return 0;
}

static int32_t pcmk_ipcs_dispatch_del(int32_t fd)
{
    struct gio_to_qb_poll *adaptor;
    if (qb_array_index(gio_map, fd, (void**)&adaptor) == 0) {
        g_io_channel_unref(adaptor->channel);
        adaptor->is_used = QB_FALSE;
    }
    return 0;
}



static int32_t s1_connection_accept_fn(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
#if 0
    if (uid == 0 && gid == 0) {
        crm_trace("authenticated connection");
        return 1;
    }
    crm_err("BAD user!");
    return 0;
#else
    return 0;
#endif
}


static void s1_connection_created_fn(qb_ipcs_connection_t *c)
{
    struct qb_ipcs_stats srv_stats;

    qb_ipcs_stats_get(s1, &srv_stats, QB_FALSE);
    crm_trace("Connection created > active:%d > closed:%d",
              srv_stats.active_connections,
              srv_stats.closed_connections);
}

static int32_t s1_msg_process_fn(qb_ipcs_connection_t *c, void *data, size_t size)
{
    struct qb_ipc_request_header *req_pt = (struct qb_ipc_request_header *)data;
    struct qb_ipc_response_header response;
    ssize_t res;

    crm_trace("msg:%d, size:%d", req_pt->id, req_pt->size);
    response.size = sizeof(struct qb_ipc_response_header);
    response.id = 13;
    response.error = 0;
    if (blocking) {
        res = qb_ipcs_response_send(c, &response, sizeof(response));
        if (res < 0) {
            crm_perror(LOG_ERR, "qb_ipcs_response_send");
        }
    }
    if (events) {
        res = qb_ipcs_event_send(c, &response, sizeof(response));
        if (res < 0) {
            crm_perror(LOG_ERR, "qb_ipcs_event_send");
        }
    }
    return 0;
}

static int32_t s1_connection_closed_fn(qb_ipcs_connection_t *c)
{
    struct qb_ipcs_connection_stats stats;
    struct qb_ipcs_stats srv_stats;

    qb_ipcs_stats_get(s1, &srv_stats, QB_FALSE);

    qb_ipcs_connection_stats_get(c, &stats, QB_FALSE);

    crm_trace(" Connection to pid:%d destroyed > active:%d > closed:%d",
              stats.client_pid,
              srv_stats.active_connections,
              srv_stats.closed_connections);

    crm_trace(" Requests     %"PRIu64, stats.requests);
    crm_trace(" Responses    %"PRIu64, stats.responses);
    crm_trace(" Events       %"PRIu64, stats.events);
    crm_trace(" Send retries %"PRIu64, stats.send_retries);
    crm_trace(" Recv retries %"PRIu64, stats.recv_retries);
    crm_trace(" FC state     %d", stats.flow_control_state);
    crm_trace(" FC count     %"PRIu64, stats.flow_control_count);
    return 0;
}

static void s1_connection_destroyed_fn(qb_ipcs_connection_t *c)
{
    crm_trace("connection about to be freed");
}

#endif

int
init_server_ipc_comms(char *channel_name,
                      gboolean(*connect) (crm_ipcc_connection * newclient, gpointer user_data),
                      void (*destroy) (gpointer user_data))
{
#ifdef LIBQB_IPC
    struct qb_ipcs_service_handlers sh = {
        .connection_accept = ipc_server_connection_accept_fn,
        .connection_created = ipc_server_connection_created_fn,
        .msg_process = ipc_server_msg_process_fn,
        .connection_destroyed = ipc_server_connection_destroyed_fn,
        .connection_closed = ipc_server_connection_closed_fn,
    };
    struct qb_ipcs_poll_handlers glib_ph = {
        .job_add = NULL, /* FIXME */
        .dispatch_add = pcmk_ipcs_dispatch_add,
        .dispatch_mod = NULL,
        .dispatch_del = pcmk_ipcs_dispatch_del,
    };

    qb_ipcs_service_t *ipc_server = NULL;
    enum crm_ais_msg_types sender = text2msg_type(crm_system_name);

    if(gio_map == NULL) {
        gio_map = qb_array_create(64, sizeof(struct gio_to_qb_poll));
    }
    
    ipc_server = qb_ipcs_create(channel_name, sender, QB_IPC_SOCKET, &sh);
    if (ipc_server == 0) {
        crm_perror(LOG_ERR, "qb_ipcs_create");
        return -1;
    }

    /* qb_ipcs_context_set(struct qb_ipcs_connection *c, channel_name); */
    qb_ipcs_poll_handlers_set(ipc_server, &glib_ph);
    qb_ipcs_run(ipc_server);

    res = qb_ipcs_run(ipc_server);

#else
/* the clients wait channel is the other source of events.
     * This source delivers the clients connection events.
     * listen to this source at a relatively lower priority.
     */

    char commpath[SOCKET_LEN];
    IPC_WaitConnection *wait_ch;

    sprintf(commpath, CRM_STATE_DIR "/%s", channel_name);

    wait_ch = wait_channel_init(commpath);

    if (wait_ch == NULL) {
        return 1;
    }

    G_main_add_IPC_WaitConnection(G_PRIORITY_LOW, wait_ch, NULL, FALSE,
                                  channel_client_connect, channel_name, channel_connection_destroy);

    crm_debug_3("Listening on: %s", commpath);
#endif
    return 0;
}

GCHSource *
init_client_ipc_comms(const char *channel_name,
                      gboolean(*dispatch) (crm_ipcc_connection * source_data, gpointer user_data),
                      void *client_data, crm_ipcc_connection ** ch)
{
    crm_ipcc_connection *a_ch = NULL;
    GCHSource *the_source = NULL;
    void *callback_data = client_data;

    a_ch = init_client_ipc_comms_nodispatch(channel_name);
    if (ch != NULL) {
        *ch = a_ch;
        if (callback_data == NULL) {
            callback_data = a_ch;
        }
    }

    if (a_ch == NULL) {
        crm_warn("Setup of client connection failed," " not adding channel to mainloop");

        return NULL;
    }

    if (dispatch == NULL) {
        crm_warn("No dispatch method specified..."
                 "maybe you meant init_client_ipc_comms_nodispatch()?");
    } else {
        crm_debug_3("Adding dispatch method to channel");

        the_source = G_main_add_IPC_Channel(G_PRIORITY_HIGH, a_ch, FALSE, dispatch, callback_data,
                                            default_ipc_connection_destroy);
    }

    return the_source;
}

crm_ipcc_connection *
init_client_ipc_comms_nodispatch(const char *channel_name)
{
    crm_ipcc_connection *ch;
    GHashTable *attrs;
    static char path[] = IPC_PATH_ATTR;

    char *commpath = NULL;
    int local_socket_len = 2;   /* 2 = '/' + '\0' */

    local_socket_len += strlen(channel_name);
    local_socket_len += strlen(CRM_STATE_DIR);

    crm_malloc0(commpath, local_socket_len);

    sprintf(commpath, CRM_STATE_DIR "/%s", channel_name);
    commpath[local_socket_len - 1] = '\0';
    crm_debug("Attempting to talk on: %s", commpath);

    attrs = g_hash_table_new(crm_str_hash, g_str_equal);
    g_hash_table_insert(attrs, path, commpath);

    ch = ipc_channel_constructor(IPC_ANYTYPE, attrs);
    g_hash_table_destroy(attrs);

    if (ch == NULL) {
        crm_err("Could not access channel on: %s", commpath);
        crm_free(commpath);
        return NULL;

    } else if (ch->ops->initiate_connection(ch) != IPC_OK) {
        crm_debug("Could not init comms on: %s", commpath);
        ch->ops->destroy(ch);
        crm_free(commpath);
        return NULL;
    }

    ch->ops->set_recv_qlen(ch, 512);
    ch->ops->set_send_qlen(ch, 512);
    ch->should_send_block = TRUE;

    crm_debug_3("Processing of %s complete", commpath);

    crm_free(commpath);
    return ch;
}

IPC_WaitConnection *
wait_channel_init(char daemonsocket[])
{
    IPC_WaitConnection *wait_ch;
    mode_t mask;
    char path[] = IPC_PATH_ATTR;
    GHashTable *attrs;

    attrs = g_hash_table_new(crm_str_hash, g_str_equal);
    g_hash_table_insert(attrs, path, daemonsocket);

    mask = umask(0);
    wait_ch = ipc_wait_conn_constructor(IPC_ANYTYPE, attrs);
    if (wait_ch == NULL) {
        crm_perror(LOG_ERR, "Can't create wait channel of type %s", IPC_ANYTYPE);
        exit(1);
    }
    mask = umask(mask);

    g_hash_table_destroy(attrs);

    return wait_ch;
}

gboolean
is_ipc_empty(crm_ipcc_connection * ch)
{
    if (ch == NULL) {
        return TRUE;

    } else if (ch->send_queue->current_qlen == 0 && ch->recv_queue->current_qlen == 0) {
        return TRUE;
    }
    return FALSE;
}

void
send_hello_message(crm_ipcc_connection * ipc_client,
                   const char *uuid,
                   const char *client_name, const char *major_version, const char *minor_version)
{
    xmlNode *hello_node = NULL;
    xmlNode *hello = NULL;

    if (uuid == NULL || strlen(uuid) == 0
        || client_name == NULL || strlen(client_name) == 0
        || major_version == NULL || strlen(major_version) == 0
        || minor_version == NULL || strlen(minor_version) == 0) {
        crm_err("Missing fields, Hello message will not be valid.");
        return;
    }

    hello_node = create_xml_node(NULL, XML_TAG_OPTIONS);
    crm_xml_add(hello_node, "major_version", major_version);
    crm_xml_add(hello_node, "minor_version", minor_version);
    crm_xml_add(hello_node, "client_name", client_name);
    crm_xml_add(hello_node, "client_uuid", uuid);

    crm_debug_4("creating hello message");
    hello = create_request(CRM_OP_HELLO, hello_node, NULL, NULL, client_name, uuid);

    send_ipc_message(ipc_client, hello);
    crm_debug_4("hello message sent");

    free_xml(hello_node);
    free_xml(hello);
}

gboolean
process_hello_message(xmlNode * hello,
                      char **uuid, char **client_name, char **major_version, char **minor_version)
{
    const char *local_uuid;
    const char *local_client_name;
    const char *local_major_version;
    const char *local_minor_version;

    *uuid = NULL;
    *client_name = NULL;
    *major_version = NULL;
    *minor_version = NULL;

    if (hello == NULL) {
        return FALSE;
    }

    local_uuid = crm_element_value(hello, "client_uuid");
    local_client_name = crm_element_value(hello, "client_name");
    local_major_version = crm_element_value(hello, "major_version");
    local_minor_version = crm_element_value(hello, "minor_version");

    if (local_uuid == NULL || strlen(local_uuid) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "uuid");
        return FALSE;

    } else if (local_client_name == NULL || strlen(local_client_name) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "client name");
        return FALSE;

    } else if (local_major_version == NULL || strlen(local_major_version) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "major version");
        return FALSE;

    } else if (local_minor_version == NULL || strlen(local_minor_version) == 0) {
        crm_err("Hello message was not valid (field %s not found)", "minor version");
        return FALSE;
    }

    *uuid = crm_strdup(local_uuid);
    *client_name = crm_strdup(local_client_name);
    *major_version = crm_strdup(local_major_version);
    *minor_version = crm_strdup(local_minor_version);

    crm_debug_3("Hello message ok");
    return TRUE;
}

xmlNode *
create_request_adv(const char *task, xmlNode * msg_data,
                   const char *host_to, const char *sys_to,
                   const char *sys_from, const char *uuid_from, const char *origin)
{
    char *true_from = NULL;
    xmlNode *request = NULL;
    char *reference = generateReference(task, sys_from);

    if (uuid_from != NULL) {
        true_from = generate_hash_key(sys_from, uuid_from);
    } else if (sys_from != NULL) {
        true_from = crm_strdup(sys_from);
    } else {
        crm_err("No sys from specified");
    }

    /* host_from will get set for us if necessary by CRMd when routed */
    request = create_xml_node(NULL, __FUNCTION__);
    crm_xml_add(request, F_CRM_ORIGIN, origin);
    crm_xml_add(request, F_TYPE, T_CRM);
    crm_xml_add(request, F_CRM_VERSION, CRM_FEATURE_SET);
    crm_xml_add(request, F_CRM_MSG_TYPE, XML_ATTR_REQUEST);
    crm_xml_add(request, XML_ATTR_REFERENCE, reference);
    crm_xml_add(request, F_CRM_TASK, task);
    crm_xml_add(request, F_CRM_SYS_TO, sys_to);
    crm_xml_add(request, F_CRM_SYS_FROM, true_from);

    /* HOSTTO will be ignored if it is to the DC anyway. */
    if (host_to != NULL && strlen(host_to) > 0) {
        crm_xml_add(request, F_CRM_HOST_TO, host_to);
    }

    if (msg_data != NULL) {
        add_message_xml(request, F_CRM_DATA, msg_data);
    }
    crm_free(reference);
    crm_free(true_from);

    return request;
}

ha_msg_input_t *
new_ha_msg_input(xmlNode * orig)
{
    ha_msg_input_t *input_copy = NULL;

    crm_malloc0(input_copy, sizeof(ha_msg_input_t));
    input_copy->msg = orig;
    input_copy->xml = get_message_xml(input_copy->msg, F_CRM_DATA);
    return input_copy;
}

void
delete_ha_msg_input(ha_msg_input_t * orig)
{
    if (orig == NULL) {
        return;
    }
    free_xml(orig->msg);
    crm_free(orig);
}

xmlNode *
validate_crm_message(xmlNode * msg, const char *sys, const char *uuid, const char *msg_type)
{
    const char *to = NULL;
    const char *type = NULL;
    const char *crm_msg_reference = NULL;
    xmlNode *action = NULL;
    const char *true_sys;
    char *local_sys = NULL;

    if (msg == NULL) {
        return NULL;
    }

    to = crm_element_value(msg, F_CRM_SYS_TO);
    type = crm_element_value(msg, F_CRM_MSG_TYPE);

    crm_msg_reference = crm_element_value(msg, XML_ATTR_REFERENCE);
    action = msg;
    true_sys = sys;

    if (uuid != NULL) {
        local_sys = generate_hash_key(sys, uuid);
        true_sys = local_sys;
    }

    if (to == NULL) {
        crm_info("No sub-system defined.");
        action = NULL;
    } else if (true_sys != NULL && strcasecmp(to, true_sys) != 0) {
        crm_debug_3("The message is not for this sub-system (%s != %s).", to, true_sys);
        action = NULL;
    }

    crm_free(local_sys);

    if (type == NULL) {
        crm_info("No message type defined.");
        return NULL;

    } else if (msg_type != NULL && strcasecmp(msg_type, type) != 0) {
        crm_info("Expecting a (%s) message but received a (%s).", msg_type, type);
        action = NULL;
    }

    if (crm_msg_reference == NULL) {
        crm_info("No message crm_msg_reference defined.");
        action = NULL;
    }
/*
 	if(action != NULL) 
		crm_debug_3(
		       "XML is valid and node with message type (%s) found.",
		       type);
	crm_debug_3("Returning node (%s)", crm_element_name(action));
*/

    return action;
}

/*
 * This method adds a copy of xml_response_data
 */
xmlNode *
create_reply_adv(xmlNode * original_request, xmlNode * xml_response_data, const char *origin)
{
    xmlNode *reply = NULL;

    const char *host_from = crm_element_value(original_request, F_CRM_HOST_FROM);
    const char *sys_from = crm_element_value(original_request, F_CRM_SYS_FROM);
    const char *sys_to = crm_element_value(original_request, F_CRM_SYS_TO);
    const char *type = crm_element_value(original_request, F_CRM_MSG_TYPE);
    const char *operation = crm_element_value(original_request, F_CRM_TASK);
    const char *crm_msg_reference = crm_element_value(original_request, XML_ATTR_REFERENCE);

    if (type == NULL) {
        crm_err("Cannot create new_message," " no message type in original message");
        CRM_ASSERT(type != NULL);
        return NULL;
#if 0
    } else if (strcasecmp(XML_ATTR_REQUEST, type) != 0) {
        crm_err("Cannot create new_message," " original message was not a request");
        return NULL;
#endif
    }
    reply = create_xml_node(NULL, __FUNCTION__);
    crm_xml_add(reply, F_CRM_ORIGIN, origin);
    crm_xml_add(reply, F_TYPE, T_CRM);
    crm_xml_add(reply, F_CRM_VERSION, CRM_FEATURE_SET);
    crm_xml_add(reply, F_CRM_MSG_TYPE, XML_ATTR_RESPONSE);
    crm_xml_add(reply, XML_ATTR_REFERENCE, crm_msg_reference);
    crm_xml_add(reply, F_CRM_TASK, operation);

    /* since this is a reply, we reverse the from and to */
    crm_xml_add(reply, F_CRM_SYS_TO, sys_from);
    crm_xml_add(reply, F_CRM_SYS_FROM, sys_to);

    /* HOSTTO will be ignored if it is to the DC anyway. */
    if (host_from != NULL && strlen(host_from) > 0) {
        crm_xml_add(reply, F_CRM_HOST_TO, host_from);
    }

    if (xml_response_data != NULL) {
        add_message_xml(reply, F_CRM_DATA, xml_response_data);
    }

    return reply;
}
