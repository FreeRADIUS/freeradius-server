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
 * Copyright 2000,2001,2006  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
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
		eap_round_free(&eap_round);
		return NULL;
	}
	eap_round->request = talloc_zero(eap_round, eap_packet_t);
	if (!eap_round->request) {
		eap_round_free(&eap_round);
		return NULL;
	}

	return eap_round;
}

void eap_round_free(eap_round_t **eap_round_p)
{
	eap_round_t *eap_round;

	if (!eap_round_p) return;

	eap_round = *eap_round_p;
	if (!eap_round) return;

	if (eap_round->response) talloc_free(eap_round->response);
	if (eap_round->request) talloc_free(eap_round->request);

	talloc_free(eap_round);
	*eap_round_p = NULL;
}

static int _eap_session_free(eap_session_t *eap_session)
{
	REQUEST *request = eap_session->request;

	if (eap_session->identity) {
		talloc_free(eap_session->identity);
		eap_session->identity = NULL;
	}

	if (eap_session->prev_round) eap_round_free(&(eap_session->prev_round));
	if (eap_session->this_round) eap_round_free(&(eap_session->this_round));

	/*
	 *	Give helpful debug messages if:
	 *
	 *	we're debugging TLS sessions, which don't finish,
	 *	and which aren't deleted early due to a likely RADIUS
	 *	retransmit which nukes our ID, and therefore our stare.
	 */
	if (fr_debug_lvl && eap_session->tls && !eap_session->finished &&
	    (time(NULL) > (eap_session->request->timestamp + 3))) {
		RWARN("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		RWARN("!! EAP session with state 0x%02x%02x%02x%02x%02x%02x%02x%02x did not finish!   !!",
		      eap_session->state[0], eap_session->state[1],
		      eap_session->state[2], eap_session->state[3],
		      eap_session->state[4], eap_session->state[5],
		      eap_session->state[6], eap_session->state[7]);

		RWARN("!! Please read http://wiki.freeradius.org/guide/Certificate_Compatibility     !!");
		RWARN("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	}

	RDEBUG4("Freeing eap_session_t %p", eap_session);

	return 0;
}

/*
 * Allocate a new eap_session_t
 */
eap_session_t *eap_session_alloc(rlm_eap_t *inst)
{
	eap_session_t	*eap_session;

	eap_session = talloc_zero(NULL, eap_session_t);
	if (!eap_session) {
		ERROR("Failed allocating eap_session");
		return NULL;
	}
	eap_session->inst = inst;

	/* Doesn't need to be inside the critical region */
	talloc_set_destructor(eap_session, _eap_session_free);

	return eap_session;
}
