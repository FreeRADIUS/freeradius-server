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
 * @copyright 2018 The FreeRADIUS server project
 */
RCSIDH(server_pair_h, "$Id$")

/** Allocate a VALUE_PAIR in the request list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_add_request(_attr, _da) fr_pair_add_by_da(request->packet, _attr, &request->packet->vps, _da)

/** Allocate a VALUE_PAIR in the reply list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_add_reply(_attr, _da) fr_pair_add_by_da(request->reply, _attr, &request->reply->vps, _da)

/** Allocate a VALUE_PAIR in the control list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_add_control(_attr, _da) fr_pair_add_by_da(request, _attr, &request->control, _da)

/** Allocate a VALUE_PAIR in the session-state list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_add_session_state(_attr, _da) fr_pair_add_by_da(request->state_ctx, _attr, &request->state, _da)

/** Return or allocate a VALUE_PAIR in the request list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_request(_attr, _da) fr_pair_update_by_da(request->packet, _attr, &request->packet->vps, _da)

/** Return or allocate a VALUE_PAIR in the reply list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_reply(_attr, _da) fr_pair_update_by_da(request->reply, _attr, &request->reply->vps, _da)

/** Return or allocate a VALUE_PAIR in the control list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_control(_attr, _da) fr_pair_update_by_da(request, _attr, &request->control, _da)

/** Return or allocate a VALUE_PAIR in the session_state list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_session_state(_attr, _da) fr_pair_update_by_da(request->state_ctx, _attr, &request->state, _da)

/** Delete a VALUE_PAIR in a list
 *
 * @param[in] _list	to delete the pair from.
 * @param[in] _pair	May be a VALUE_PAIR or fr_dict_attr_t.
 */
#define pair_delete(_list, _pair) \
	_Generic((_pair), \
		 fr_dict_attr_t const *		: fr_pair_delete_by_da(_list, (fr_dict_attr_t const *)_pair),	\
		 fr_dict_attr_t *		: fr_pair_delete_by_da(_list, (fr_dict_attr_t const *)_pair),	\
		 VALUE_PAIR *			: fr_pair_delete(_list, (VALUE_PAIR const *)_pair)		\
	)

/** Delete a VALUE_PAIR in the request list
 *
 * @param[in] _pair	#fr_dict_attr_t of the pair(s) to be deleted.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_request(_pair) pair_delete(&request->packet->vps, _pair)


/** Delete a VALUE_PAIR in the reply list
 *
 * @param[in] _pair	#fr_dict_attr_t of the pair(s) to be deleted.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_reply(_pair) pair_delete(&request->reply->vps, _pair)

/** Delete a VALUE_PAIR in the control list
 *
 * @param[in] _pair	#fr_dict_attr_t of the pair(s) to be deleted.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_control(_pair) pair_delete(&request->control, _pair)

/** Delete a VALUE_PAIR in the session_state list
 *
 * @param[in] _pair	#fr_dict_attr_t of the pair(s) to be deleted.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_session_state(_pair) pair_delete(&request->state, _pair)

