/* 
 * Copyright (C) 2011 Andrew Beekhof <andrew@beekhof.net>
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
#include <crm/pengine/api.h>

extern void cleanup_alloc_calculations(pe_working_set_t * data_set);
extern xmlNode *do_calculations(pe_working_set_t * data_set, xmlNode * xml_input, ha_time_t * now);

pe_working_set_t *pengine_create(void)
{
    pe_working_set_t *data_set = NULL;
    crm_malloc0(data_set, sizeof(pe_working_set_t));
    set_working_set_defaults(data_set);
    return data_set;
}

void pengine_cleanup(pe_working_set_t * data_set)
{
    cleanup_alloc_calculations(data_set);
}

void pengine_destroy(pe_working_set_t * data_set)
{
    cleanup_alloc_calculations(data_set);
    crm_free(data_set);
}

int pengine_status_text(pe_working_set_t * data_set, const char *input_string)
{
    xmlNode *xml = string2xml(input_string);
    return pengine_status_xml(data_set, xml);
}

int pengine_run_text(pe_working_set_t * data_set, const char *input_string)
{
    xmlNode *xml = string2xml(input_string);
    return pengine_run_xml(data_set, xml);
}

const char *pengine_graph_text(pe_working_set_t * data_set)
{
    return dump_xml_unformatted(data_set->graph);
}

/* xml_input is owned by data_set after the call */
int pengine_status_xml(pe_working_set_t * data_set, xmlNode *xml_input)
{
    pengine_cleanup(data_set);
    data_set->input = xml_input;
    
    return cluster_status(data_set);
}

/* xml_input is owned by data_set after the call */
int pengine_run_xml(pe_working_set_t * data_set, xmlNode *xml_input)
{
    pengine_cleanup(data_set);
    if(do_calculations(data_set, xml_input, NULL) != NULL) {
        return 1;
    }
    return 0;
}

xmlNode *pengine_graph_xml(pe_working_set_t * data_set)
{
    return data_set->graph;
}

char *pengine_bucket_for_object(pe_working_set_t * data_set, char *object_id, int calculated)
{
    resource_t *rsc = pe_find_resource(data_set->resources, object_id);
    if(rsc == NULL) {
        return NULL;
    }

    if(calculated && rsc->allocated_to) {
        return crm_strdup(rsc->allocated_to->details->uname);
    } else if(!calculated && rsc->running_on) {
        node_t *n = rsc->running_on->data;
        return crm_strdup(n->details->uname);
    }
    
    return NULL;
}

