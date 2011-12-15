/* 
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <crm/common/xml.h>
#include <crm/msg_xml.h>
#include <crm/stonith-ng.h>
#include <crm/stonith-ng-internal.h>
#include <internal.h>

#ifdef HAVE_JSON
#include <json-glib/json-glib.h>

static gboolean
is_valid_name(const char *name, const char *type)
{
    if(strchr(name, '\t') || strchr(name, ' ')) {
        crm_err("No whitespace allowed in %s: '%s'", name, type);
        return FALSE;
    }
    return TRUE;
}

gboolean
process_config_file (const char *filename)
{
    GList *dlist = NULL;
    GList *device = NULL;
    GError *error = NULL;

    JsonObject *root = NULL; 
    JsonParser *parser = NULL;
    JsonObject *devices = NULL;

    const char *st_options[] = {
        "pcmk_host_check",
        "pcmk_reboot_action",
        "pcmk_poweroff_action",
        "pcmk_list_action",
        "pcmk_monitor_action",
        "pcmk_status_action"
    };

    g_type_init ();
    parser = json_parser_new ();
    json_parser_load_from_file (parser, filename, &error);

    if (error) {
        crm_err("Unable to parse `%s': %s", filename, error->message);
        g_error_free (error);
        g_object_unref (parser);
        return FALSE;
    }

    root = json_node_get_object(json_parser_get_root (parser));

    if(!json_object_has_member(root, "devices")) {
        g_object_unref (parser);
        return FALSE;
    }

    devices = json_object_get_object_member (root, "devices");
    dlist = json_object_get_members (devices);

    for (device = dlist; device != NULL; device = device->next) {
        int lpc;
        const char *name = NULL;
        const gchar *id = device->data;

        JsonObject *node = json_object_get_object_member (devices, id);
        const gchar *type = json_object_get_string_member(node, "type");

        xmlNode *data = create_xml_node(NULL, F_STONITH_DEVICE);
        xmlNode *args = create_xml_node(data, XML_TAG_ATTRS);

        if(!id) {
            crm_err("Device has no name");
            continue;

        } else if(is_valid_name(id, "device id") == FALSE) {
            continue;

        } else if(!type) {
            crm_err("Device %s has no type", id);
            continue;
        }

        crm_info("Registering device: %s of type %s", id, type);

        crm_xml_add(data, XML_ATTR_ID, id);
        crm_xml_add(data, "origin", __FUNCTION__);
        crm_xml_add(data, "agent", type);
        crm_xml_add(data, "namespace", "stonith-ng");

        for(lpc = 0; lpc < DIMOF(st_options); lpc++) {
            name = st_options[lpc];
            if(json_object_has_member(node, name)) {
                if(JSON_NODE_HOLDS_VALUE(json_object_get_member(node, name))) {
                    const gchar *value = json_object_get_string_member (node, name);
                    hash2field((gpointer) name, (gpointer) value, args);

                } else {
                    crm_err("%s must contain a simple value", name);
                }
            }
        }

        name = "pcmk_host_list";
        if(json_object_has_member(node, name)) {
            JsonArray *hlist = json_object_get_array_member(node, name);

            char *value = NULL;
            int max = 1024, offset = 0;
            int length = json_array_get_length(hlist);

            for (lpc = 0; lpc < length; lpc++) {
                const char *tmp = json_array_get_string_element(hlist, lpc);
                crm_realloc(value, offset + strlen(tmp) + 2);
                offset += snprintf(value + offset, max - offset, " %s", tmp);
            }
            hash2field((gpointer) name, (gpointer) value, args);
            crm_free(value);
        }

        name = "pcmk_host_map";
        if(json_object_has_member(node, name)) {
            char *value = NULL;
            int max = 1024, offset = 0;

            GList *hlist, *host;
            JsonObject *map = json_object_get_object_member (node, name);

            hlist = json_object_get_members (map);
            for (host = hlist; host != NULL; host = host->next) {
                const gchar *port = NULL;
                const char *uname = host->data;
                if(JSON_NODE_HOLDS_VALUE(json_object_get_member(map, uname))) {
                    port = json_object_get_string_member (map, uname);
                }

                if(!port) {
                    crm_err("Invalid host name mapping for %s", uname);
                    continue;
                }

                crm_realloc(value, offset + strlen(uname) + strlen(port) + 3);
                offset += snprintf(value + offset, max - offset, "%s:%s;", uname, port);
            }
            hash2field((gpointer) name, (gpointer) value, args);
            crm_free(value);
        }

        if(json_object_has_member(node, "parameters")) {
            GList *plist, *param;
            JsonObject *options = json_object_get_object_member (node, "parameters");
            plist = json_object_get_members (options);
            for (param = plist; param != NULL; param = param->next) {
                const char *name = param->data;

                if(is_valid_name(name, "parameter names") == FALSE) {
                    continue;

                } else if(JSON_NODE_HOLDS_VALUE(json_object_get_member(options, name))) {
                    const gchar *value = json_object_get_string_member (options, name);
                    hash2field((gpointer) name, (gpointer) value, args);

                } else {
                    crm_err("%s must contain a simple value", name);
                }
            }
        }

        crm_log_xml_debug(data, id);
        stonith_device_register(data);
        free_xml(data);
    }

    g_object_unref (parser);
    return TRUE;
}

#endif
