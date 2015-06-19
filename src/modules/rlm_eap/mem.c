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
EAP_DS *eap_ds_alloc(eap_handler_t *handler)
{
	EAP_DS	*eap_ds;

	eap_ds = talloc_zero(handler, EAP_DS);
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

static int _eap_handler_free(eap_handler_t *handler)
{
	if (handler->identity) {
		talloc_free(handler->identity);
		handler->identity = NULL;
	}

	if (handler->prev_eap_ds) eap_ds_free(&(handler->prev_eap_ds));
	if (handler->eap_ds) eap_ds_free(&(handler->eap_ds));

	if ((handler->opaque) && (handler->free_opaque)) {
		handler->free_opaque(handler->opaque);
		handler->opaque = NULL;
	}

	handler->opaque = NULL;
	handler->free_opaque = NULL;

	if (handler->certs) pairfree(&handler->certs);

	/*
	 *	Give helpful debug messages if:
	 *
	 *	we're debugging TLS sessions, which don't finish,
	 *	and which aren't deleted early due to a likely RADIUS
	 *	retransmit which nukes our ID, and therefore our stare.
	 */
	if (fr_debug_lvl && handler->tls && !handler->finished &&
	    (time(NULL) > (handler->timestamp + 3))) {
		WARN("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		WARN("!! EAP session with state 0x%02x%02x%02x%02x%02x%02x%02x%02x did not finish!                  !!",
		     handler->state[0], handler->state[1],
		     handler->state[2], handler->state[3],
		     handler->state[4], handler->state[5],
		     handler->state[6], handler->state[7]);

		WARN("!! Please read http://wiki.freeradius.org/guide/Certificate_Compatibility     !!");
		WARN("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	}

	talloc_free(handler);
	
	return 0;
}

/*
 * Allocate a new eap_handler_t
 */
eap_handler_t *eap_handler_alloc(rlm_eap_t *inst)
{
	eap_handler_t	*handler;

	handler = talloc_zero(NULL, eap_handler_t);
	if (!handler) {
		ERROR("Failed allocating handler");
		return NULL;
	}
	handler->inst_holder = inst;

	/* Doesn't need to be inside the critical region */
	talloc_set_destructor(handler, _eap_handler_free);

	return handler;
}
