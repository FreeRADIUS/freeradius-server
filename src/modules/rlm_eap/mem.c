/*
 * mem.c  Memory allocation, deallocation stuff.
 *
 * Version:     $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * @copyright 2000,2001,2006  The FreeRADIUS server project
 * @copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */

RCSID("$Id$")

#include <stdio.h>
#include "rlm_eap.h"

/*
 * Allocate a new eap_packet_t
 */
eap_round_t *eap_round_alloc(eap_session_t *eap_session)
{
	eap_round_t	*eap_round;

	eap_round = talloc_zero(eap_session, eap_round_t);
	if (!eap_round) return NULL;

	eap_round->response = talloc_zero(eap_round, eap_packet_t);
	if (!eap_round->response) {
		talloc_free(eap_round);
		return NULL;
	}
	eap_round->request = talloc_zero(eap_round, eap_packet_t);
	if (!eap_round->request) {
		talloc_free(eap_round);
		return NULL;
	}

	return eap_round;
}

static int _eap_session_free(eap_session_t *eap_session)
{
	REQUEST *request = eap_session->request;

	if (eap_session->identity) {
		talloc_free(eap_session->identity);
		eap_session->identity = NULL;
	}

#ifdef WITH_VERIFY_PTR
	if (eap_session->prev_round) (void)fr_cond_assert(talloc_parent(eap_session->prev_round) == eap_session);
	if (eap_session->this_round) (void)fr_cond_assert(talloc_parent(eap_session->this_round) == eap_session);
#endif

	/*
	 *	Give helpful debug messages if:
	 *
	 *	we're debugging TLS sessions, which don't finish,
	 *	and which aren't deleted early due to a likely RADIUS
	 *	retransmit which nukes our ID, and therefore our state.
	 */
	if (((request && RDEBUG_ENABLED) || (!request && DEBUG_ENABLED)) &&
	    (eap_session->tls && !eap_session->finished && (time(NULL) > (eap_session->updated + 3)))) {
		ROPTIONAL(RWDEBUG, WARN, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		ROPTIONAL(RWDEBUG, WARN, "!! EAP session %016" PRIxPTR " did not finish!                   !!",
			  (uintptr_t)eap_session);
		ROPTIONAL(RWDEBUG, WARN, "!! See http://wiki.freeradius.org/guide/Certificate_Compatibility !!");
		ROPTIONAL(RWDEBUG, WARN, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	}

	ROPTIONAL(RDEBUG4, DEBUG4, "Freeing eap_session_t %p", eap_session);

	return 0;
}

/** Allocate a new eap_session_t
 *
 * Allocates a new eap_session_t, and inserts it into the REQUEST_DATA_EAP_SESSION index
 * of the request.
 *
 * @note The eap_session_t will remove itself from the #REQUEST_DATA_EAP_SESSION index
 *	if it is freed.  This is to simplify management of the request data entry.
 *
 * @param inst This session belongs to.
 * @param request That generated this eap_session_t.
 * @return
 *	- A new #eap_session_t on success.
 *	- NULL on failure.
 */
eap_session_t *eap_session_alloc(rlm_eap_t const *inst, REQUEST *request)
{
	eap_session_t	*eap_session;

	eap_session = talloc_zero(NULL, eap_session_t);
	if (!eap_session) {
		ERROR("Failed allocating eap_session");
		return NULL;
	}
	eap_session->inst = inst;
	eap_session->request = request;
	eap_session->updated = request->packet->timestamp.tv_sec;

	talloc_set_destructor(eap_session, _eap_session_free);

	return eap_session;
}
