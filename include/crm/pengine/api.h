/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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
#ifndef PENGINE_API__H
#  define PENGINE_API__H
#include <crm/pengine/status.h>
#include <crm/common/xml.h>

pe_working_set_t *pengine_create(void);
void pengine_cleanup(pe_working_set_t * data_set);
void pengine_destroy(pe_working_set_t * data_set);

int pengine_status_text(pe_working_set_t * data_set, const char *input_string);
int pengine_run_text(pe_working_set_t * data_set, const char *xml_input);
const char *pengine_graph_text(pe_working_set_t * data_set);

int pengine_status_xml(pe_working_set_t * data_set, xmlNode *xml_input);
int pengine_run_xml(pe_working_set_t * data_set, xmlNode *xml_input);
xmlNode *pengine_graph_xml(pe_working_set_t * data_set);

char *pengine_bucket_for_object(pe_working_set_t * data_set, char *object_id, int calculated);

#endif
