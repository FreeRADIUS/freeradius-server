/*
 *   This program is is free software; you can redistribute it and/or modify
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
 * @file jpath.c
 * @brief Implements the evaluation and parsing functions for the FreeRADIUS version of jpath.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015  Network RADIUS SARL <info@networkradius.com>
 * @copyright 2015  The FreeRADIUS Server Project
 */
#ifndef _FR_JSON_H
#define _FR_JSON_H
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

#  include <freeradius-devel/radiusd.h>

/* jpath .c */
typedef struct fr_jpath_node fr_jpath_node_t;

size_t		fr_jpath_escape_func(UNUSED REQUEST *request, char *out, size_t outlen,
				     char const *in, UNUSED void *arg);

int		fr_jpath_evaluate_leaf(TALLOC_CTX *ctx, value_data_t **out,
				       PW_TYPE dst_type, DICT_ATTR const *dst_enumv,
				       json_object *root, fr_jpath_node_t const *jpath);

char		*fr_jpath_aprints(TALLOC_CTX *ctx, fr_jpath_node_t const *head);

ssize_t		fr_jpath_parse(TALLOC_CTX *ctx, fr_jpath_node_t **head, char const *in, size_t inlen);

/* json.c */
int		fr_json_object_to_value_data(TALLOC_CTX *ctx, value_data_t *out, json_object *object,
					     PW_TYPE dst_type, DICT_ATTR const *dst_enumv);

size_t    	fr_json_from_pair(char *out, size_t outlen, VALUE_PAIR const *vp);
#endif
#endif /* _FR_JSON_H */
