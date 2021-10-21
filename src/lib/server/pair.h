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
 * @file lib/server/pair.h
 * @brief Server pair manipulation macros
 *
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2018 The FreeRADIUS server project
 */
RCSIDH(server_pair_h, "$Id$")

/** Allocate and append a fr_pair_t to the request list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_append_request(_attr, _da) fr_pair_append_by_da(request->request_ctx, _attr, &request->request_pairs, _da)

/** Allocate and append a fr_pair_t to reply list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_append_reply(_attr, _da) fr_pair_append_by_da(request->reply_ctx, _attr, &request->reply_pairs, _da)

/** Allocate and append a fr_pair_t to the control list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_append_control(_attr, _da) fr_pair_append_by_da(request->control_ctx, _attr, &request->control_pairs, _da)

/** Allocate and append a fr_pair_t to session-state list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_append_session_state(_attr, _da) fr_pair_append_by_da(request->session_state_ctx, _attr, &request->session_state_pairs, _da)

/** Allocate and prepend a fr_pair_t to the request list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_prepend_request(_attr, _da) fr_pair_prepend_by_da(request->request_ctx, _attr, &request->request_pairs, _da)

/** Allocate and prepend a fr_pair_t to reply list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_prepend_reply(_attr, _da) fr_pair_prepend_by_da(request->reply_ctx, _attr, &request->reply_pairs, _da)

/** Allocate and prepend a fr_pair_t to the control list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_prepend_control(_attr, _da) fr_pair_prepend_by_da(request->control_ctx, _attr, &request->control_pairs, _da)

/** Allocate and prepend a fr_pair_t to session-state list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_prepend_session_state(_attr, _da) fr_pair_prepend_by_da(request->session_state_ctx, _attr, &request->session_state_pairs, _da)

/** Return or allocate a fr_pair_t in the request list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_request(_attr, _da) fr_pair_update_by_da(request->request_ctx, _attr, &request->request_pairs, _da, 0)

/** Return or allocate a fr_pair_t in the reply list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_reply(_attr, _da) fr_pair_update_by_da(request->reply_ctx, _attr, &request->reply_pairs, _da, 0)

/** Return or allocate a fr_pair_t in the control list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_control(_attr, _da) fr_pair_update_by_da(request->control_ctx, _attr, &request->control_pairs, _da, 0)

/** Return or allocate a fr_pair_t in the session_state list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_session_state(_attr, _da) fr_pair_update_by_da(request->session_state_ctx, _attr, &request->session_state_pairs, _da, 0)

/** Delete one or move fr_pair_t in a list
 *
 * @param[in] _list		to delete the pair from.
 * @param[in] _pair_or_da	To delete.  May be a #fr_pair_t or #fr_dict_attr_t.
 */
#define pair_delete(_list, _pair_or_da) \
	_Generic((_pair_or_da), \
		 fr_dict_attr_t const *		: fr_pair_delete_by_da(_list, UNCONST(fr_dict_attr_t *, _pair_or_da)),	\
		 fr_dict_attr_t *		: fr_pair_delete_by_da(_list, UNCONST(fr_dict_attr_t *, _pair_or_da)),	\
		 fr_pair_t *			: fr_pair_delete(_list, UNCONST(fr_pair_t *, _pair_or_da))		\
	)

/** Delete a fr_pair_t in the request list
 *
 * @param[in] _pair_or_da	To delete.  May be a #fr_pair_t or #fr_dict_attr_t.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_request(_pair_or_da) pair_delete(&request->request_pairs, _pair_or_da)

/** Delete a fr_pair_t in the reply list
 *
 * @param[in] _pair_or_da	To delete.  May be a #fr_pair_t or #fr_dict_attr_t.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_reply(_pair_or_da) pair_delete(&request->reply_pairs, _pair_or_da)

/** Delete a fr_pair_t in the control list
 *
 * @param[in] _pair_or_da	To delete.  May be a #fr_pair_t or #fr_dict_attr_t.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_control(_pair_or_da) pair_delete(&request->control_pairs, _pair_or_da)

/** Delete a fr_pair_t in the session_state list
 *
 * @param[in] _pair_or_da	To delete.  May be a #fr_pair_t or #fr_dict_attr_t.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_session_state(_pair_or_da) pair_delete(&request->session_state_pairs, _pair_or_da)
