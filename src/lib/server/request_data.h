#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/request_data.h
 * @brief Request data management functions.
 *
 * @copyright 2019 The FreeRADIUS server project
 */
RCSIDH(request_data_h, "$Id$")

#include <freeradius-devel/server/request.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct request_data_s request_data_t;

void		request_data_list_init(fr_dlist_head_t *data);

#define request_data_add(_request, _unique_ptr, _unique_int, _opaque, _free_on_replace, _free_on_parent, _persist) \
		_request_data_add(_request, _unique_ptr, _unique_int, NULL, _opaque,  \
				  _free_on_replace, _free_on_parent, _persist, __FILE__, __LINE__)

#define request_data_talloc_add(_request, _unique_ptr, _unique_int, _type, _opaque, _free_on_replace, _free_on_parent, _persist) \
		_request_data_add(_request, _unique_ptr, _unique_int, STRINGIFY(_type), _opaque, \
				  _free_on_replace, _free_on_parent, _persist, __FILE__, __LINE__)

int		_request_data_add(REQUEST *request, void const *unique_ptr, int unique_int, char const *type, void *opaque,
				  bool free_on_replace, bool free_on_parent, bool persist, char const *file, int line);

void		*request_data_get(REQUEST *request, void const *unique_ptr, int unique_int);

void		*request_data_reference(REQUEST *request, void const *unique_ptr, int unique_int);

int		request_data_by_persistance(fr_dlist_head_t *out, REQUEST *request, bool persist);

int		request_data_by_persistance_reparent(TALLOC_CTX *ctx, fr_dlist_head_t *out,
						     REQUEST *request, bool persist);

int		request_data_by_persistance_count(REQUEST *request, bool persist);

void		request_data_restore(REQUEST *request, fr_dlist_head_t *in);

void		request_data_persistable_free(REQUEST *request);

void		request_data_list_dump(REQUEST *request, fr_dlist_head_t *head);

void		request_data_dump(REQUEST *request);

int		request_data_store_in_parent(REQUEST *request, void const *unique_ptr, int unique_int);

int		request_data_restore_to_child(REQUEST *request, void const *unique_ptr, int unique_int);

#ifdef WITH_VERIFY_PTR
bool		request_data_persistable(request_data_t *rd);

bool		request_data_verify_parent(TALLOC_CTX *parent, fr_dlist_head_t *entry);
#endif

int		request_data_clear(REQUEST *request);

#ifdef __cplusplus
}
#endif
