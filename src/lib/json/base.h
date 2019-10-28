#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file lib/json/base.h
 * @brief Implements the evaluation and parsing functions for the FreeRADIUS version of jpath.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2015 The FreeRADIUS Server Project
 */
RCSIDH(json_h, "$Id$")

#include "config.h"

#ifdef HAVE_JSON
#  if defined(HAVE_JSONMC_JSON_H)
#    include <json-c/json.h>
#  elif defined(HAVE_JSON_JSON_H)
#    include <json/json.h>
#  else
#    error "Need json-c headers"
#  endif
#  include "json_missing.h"

#  include <freeradius-devel/server/base.h>

/* jpath .c */
typedef struct fr_jpath_node fr_jpath_node_t;

size_t		fr_jpath_escape_func(UNUSED REQUEST *request, char *out, size_t outlen,
				     char const *in, UNUSED void *arg);

int		fr_jpath_evaluate_leaf(TALLOC_CTX *ctx, fr_value_box_t **out,
				       fr_type_t dst_type, fr_dict_attr_t const *dst_enumv,
				       json_object *root, fr_jpath_node_t const *jpath);

char		*fr_jpath_asprint(TALLOC_CTX *ctx, fr_jpath_node_t const *head);

ssize_t		fr_jpath_parse(TALLOC_CTX *ctx, fr_jpath_node_t **head, char const *in, size_t inlen);

/* json.c */
int		fr_json_object_to_value_box(TALLOC_CTX *ctx, fr_value_box_t *out, json_object *object,
					    fr_dict_attr_t const *enumv, bool tainted);

json_object	*json_object_from_value_box(TALLOC_CTX *ctx, fr_value_box_t const *data);

char		*fr_json_from_string(TALLOC_CTX *ctx, char const *s, bool include_quotes);

size_t    	fr_json_from_pair(char *out, size_t outlen, VALUE_PAIR const *vp);

void		fr_json_version_print(void);

const char	*fr_json_afrom_pair_list(TALLOC_CTX *ctx, VALUE_PAIR **vps, const char *prefix);
#endif
