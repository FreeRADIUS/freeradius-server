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
EAP_DS *eap_ds_alloc(eap_session_t *eap_session)
{
	EAP_DS	*eap_ds;

	eap_ds = talloc_zero(eap_session, EAP_DS);
	if (!eap_ds) return NULL;
	eap_ds->response = talloc_zero(eap_ds, eap_packet_t);
	if (!eap_ds->response) {
		eap_ds_free(&eap_ds);
		return NULL;
	}
	eap_ds->request = talloc_zero(eap_ds, eap_packet_t);
	if (!eap_ds->request) {
		eap_ds_free(&eap_ds);
		return NULL;
	}

	return eap_ds;
}

void eap_ds_free(EAP_DS **eap_ds_p)
{
	EAP_DS *eap_ds;

	if (!eap_ds_p) return;

	eap_ds = *eap_ds_p;
	if (!eap_ds) return;

	if (eap_ds->response) talloc_free(eap_ds->response);
	if (eap_ds->request) talloc_free(eap_ds->request);

	talloc_free(eap_ds);
	*eap_ds_p = NULL;
}

static int _eap_eap_session_free(eap_session_t *eap_session)
{
	if (eap_session->identity) {
		talloc_free(eap_session->identity);
		eap_session->identity = NULL;
	}

	if (eap_session->prev_eap_ds) eap_ds_free(&(eap_session->prev_eap_ds));
	if (eap_session->eap_ds) eap_ds_free(&(eap_session->eap_ds));

	if ((eap_session->opaque) && (eap_session->free_opaque)) {
		eap_session->free_opaque(eap_session->opaque);
		eap_session->opaque = NULL;
	}

	eap_session->opaque = NULL;
	eap_session->free_opaque = NULL;

	if (eap_session->cert_vps) fr_pair_list_free(&eap_session->cert_vps);

	/*
	 *	Give helpful debug messages if:
	 *
	 *	we're debugging TLS sessions, which don't finish,
	 *	and which aren't deleted early due to a likely RADIUS
	 *	retransmit which nukes our ID, and therefore our stare.
	 */
	if (fr_debug_lvl && eap_session->tls && !eap_session->finished &&
	    (time(NULL) > (eap_session->timestamp + 3))) {
		WARN("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		WARN("!! EAP session with state 0x%02x%02x%02x%02x%02x%02x%02x%02x did not finish!                  !!",
		     eap_session->state[0], eap_session->state[1],
		     eap_session->state[2], eap_session->state[3],
		     eap_session->state[4], eap_session->state[5],
		     eap_session->state[6], eap_session->state[7]);

		WARN("!! Please read http://wiki.freeradius.org/guide/Certificate_Compatibility     !!");
		WARN("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	}

	talloc_free(eap_session);

	return 0;
}

/*
 * Allocate a new eap_session_t
 */
eap_session_t *eap_eap_session_alloc(rlm_eap_t *inst)
{
	eap_session_t	*eap_session;

	eap_session = talloc_zero(NULL, eap_session_t);
	if (!eap_session) {
		ERROR("Failed allocating eap_session");
		return NULL;
	}
	eap_session->inst_holder = inst;

	/* Doesn't need to be inside the critical region */
	talloc_set_destructor(eap_session, _eap_eap_session_free);

	return eap_session;
}
