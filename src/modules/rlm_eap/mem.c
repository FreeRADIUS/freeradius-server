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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000,2001  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */
#include <stdio.h>
#include "rlm_eap.h"

static const char rcsid[] = "$Id$";

/*
 * Allocate a new EAP_PACKET
 */
EAP_PACKET *eap_packet_alloc(void)
{
	EAP_PACKET   *rp;

	rp = rad_malloc(sizeof(EAP_PACKET));
	memset(rp, 0, sizeof(EAP_PACKET));
	return rp;
}

/*
 * Free EAP_PACKET
 */
void eap_packet_free(EAP_PACKET **eap_packet_ptr)
{
	EAP_PACKET *eap_packet;

	if (!eap_packet_ptr) return;
	eap_packet = *eap_packet_ptr;
	if (!eap_packet) return;

   	if (eap_packet->type.data) {
		/*
		 * This is just a pointer in the packet
		 * so we do not free it but we NULL it
		free(eap_packet->type.data);
		*/
		eap_packet->type.data = NULL;
	}

	if (eap_packet->packet) {
		free(eap_packet->packet);
		eap_packet->packet = NULL;
	}

	free(eap_packet);

	*eap_packet_ptr = NULL;
}

/*
 * Allocate a new EAP_PACKET
 */
EAP_DS *eap_ds_alloc(void)
{
	EAP_DS	*eap_ds;
        
	eap_ds = rad_malloc(sizeof(EAP_DS));
	memset(eap_ds, 0, sizeof(EAP_DS));
	if ((eap_ds->response = eap_packet_alloc()) == NULL) {
		eap_ds_free(&eap_ds);
		return NULL;
	}
	if ((eap_ds->request = eap_packet_alloc()) == NULL) {
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

	if (eap_ds->response) eap_packet_free(&(eap_ds->response));
	if (eap_ds->request) eap_packet_free(&(eap_ds->request));

	free(eap_ds);
	*eap_ds_p = NULL;
}

/*
 * Allocate a new EAP_HANDLER
 */
EAP_HANDLER *eap_handler_alloc(void)
{
	EAP_HANDLER	*handler;
        
	handler = rad_malloc(sizeof(EAP_HANDLER));
	memset(handler, 0, sizeof(EAP_HANDLER));
	return handler;
}

void eap_handler_free(EAP_HANDLER **handler_p)
{
        EAP_HANDLER *handler;

	if ((handler_p == NULL) || (*handler_p == NULL))
		return;

	handler = *handler_p;
	if (handler->identity) {
		free(handler->identity);
		handler->identity = NULL;
	}

	if (handler->prev_eapds) eap_ds_free(&(handler->prev_eapds));
	if (handler->eap_ds) eap_ds_free(&(handler->eap_ds));

	if ((handler->opaque) && (handler->free_opaque)) {
		handler->free_opaque(handler->opaque);
		handler->opaque = NULL;
	}
	else if ((handler->opaque) && (handler->free_opaque == NULL))
                radlog(L_ERR, "Possible memory leak ...");

	handler->opaque = NULL;
	handler->free_opaque = NULL;
	handler->next = NULL;

	free(handler);
	*handler_p = NULL;
}

void eaptype_free(EAP_TYPES *i)
{
	if (i->type->detach) (i->type->detach)(i->type_data);
	i->type_data = NULL;
	if (i->handle) lt_dlclose(i->handle);
}

void eaplist_free(rlm_eap_t *inst)
{
	int i;

	/*
	 *	The sessions are split out into an array, which makes
	 *	looking them up a bit faster.
	 */
	for (i = 0; i < 256; i++) {
		EAP_HANDLER *node, *next;

		if (inst->sessions[i]) continue;

		node = inst->sessions[i];
		while (node) {
			next = node->next;
			eap_handler_free(&node);
			node = next;
		}
		
		inst->sessions[i] = NULL;
	}
}

/*
 *	Add a handler to the set of active sessions.
 *
 *	Since we're adding it to the list, we guess that this means
 *	the packet needs a State attribute.  So add one.
 */
int eaplist_add(rlm_eap_t *inst, EAP_HANDLER *handler)
{
	EAP_HANDLER	**last;
	VALUE_PAIR	*state;

	rad_assert(handler != NULL);
	rad_assert(handler->request != NULL);

	/*
	 *	Generate State, since we've been asked to add it to
	 *	the list.
	 */
	state = generate_state(handler->request->timestamp);
	pairadd(&(handler->request->reply->vps), state);
		
	/*
	 *	Create a unique 'key' for the handler, based
	 *	on State, Client-IP-Address, and EAP ID.
	 */
	rad_assert(state->length == EAP_STATE_LEN);

	memcpy(handler->state, state->strvalue, sizeof(handler->state));
	handler->src_ipaddr = handler->request->packet->src_ipaddr;
	handler->eap_id = handler->eap_ds->request->id;

#ifdef HAVE_PTHREAD_H
	/*
	 *	Playing with a data structure shared among threads
	 *	means that we need a lock, to avoid conflict.
	 */
	pthread_mutex_lock(&(inst->session_mutex));
#endif

	/*
	 *	We key the array based on the challenge, which is
	 *	a random number.  This "fans out" the sessions, and
	 *	helps to minimize the amount of work we've got to do
	 *	under heavy load.
	 */
	last = &(inst->sessions[state->strvalue[0]]);

	while (*last) last = &((*last)->next);
	
	*last = handler;

	/*
	 *	The time at which this request was made was the time
	 *	at which it was received by the RADIUS server.
	 */
	handler->timestamp = handler->request->timestamp;
	handler->status = 1;
	handler->next = NULL;

#ifdef HAVE_PTHREAD_H
	/*
	 *	Now that we've finished mucking with the list,
	 *	unlock it.
	 */
	pthread_mutex_unlock(&(inst->session_mutex));
#endif

	/*
	 *	We don't need this any more.
	 */
	handler->request = NULL;

	return 1;
}

/*
 *	Find a a previous EAP-Request sent by us, which matches
 *	the current EAP-Response.
 *
 *	Then, release the handle from the list, and return it to
 *	the caller.
 *
 *	Also since we fill the eap_ds with the present EAP-Response we
 *	got to free the prev_eapds & move the eap_ds to prev_eapds
 */
EAP_HANDLER *eaplist_find(rlm_eap_t *inst, REQUEST *request,
			  eap_packet_t *eap_packet)
{
	EAP_HANDLER	*node, *next;
	VALUE_PAIR	*state;
	EAP_HANDLER	**first,  **last;

	/*
	 *	We key the sessions off of the 'state' attribute, so it
	 *	must exist.
	 */
	state = pairfind(request->packet->vps, PW_STATE);
	if (!state ||
	    (state->length != EAP_STATE_LEN)) {
		return NULL;
	}

#ifdef HAVE_PTHREAD_H
	/*
	 *	Playing with a data structure shared among threads
	 *	means that we need a lock, to avoid conflict.
	 */
	pthread_mutex_lock(&(inst->session_mutex));
#endif

	last = first = &(inst->sessions[state->strvalue[0]]);

	for (node = *first; node; node = next) {
		next = node->next;

		/*
		 *	If the time on this entry has expired, 
		 *	delete it.  We do this while walking the list,
		 *	in order to spread out the work of deleting old
		 *	sessions.
		 */
		if ((request->timestamp - node->timestamp) > inst->timer_limit) {
			*last = next;
			eap_handler_free(&node);
			continue;
		}

		/*
		 *	Find the previous part of the same conversation,
		 *	keying off of the EAP ID, the client IP, and
		 *	the State attribute.
		 *
		 *	If we've found a conversation, then we don't
		 *	have to check entries later in the list for
		 *	timeout, as they're guaranteed to be newer than
		 *	the one we found.
		 */
		if ((node->eap_id == eap_packet->id) &&
		    (node->src_ipaddr == request->packet->src_ipaddr) &&
		    (memcmp(node->state, state->strvalue, state->length) == 0)) {
			/*
			 *	Check against replays.  The client can
			 *	re-play a State attribute verbatim, so
			 *	we wish to ensure that the attribute falls
			 *	within the valid time window, which is
			 *	the second at which it was sent out.
			 */
			if (verify_state(state, node->timestamp) != 0) {
				radlog(L_ERR, "rlm_eap: State verification failed.");
				node = NULL;
				break;
			}
			
			DEBUG2("  rlm_eap: Request found, released from the list");
			/*
			 *	detach the node from the list
			 */
			*last = next;
			node->next = NULL;

			/*
			 *	Don't bother updating handler->request, etc.
			 *	eap_handler() will do that for us.
			 */

			/*
			 *	Remember what the previous request was.
			 */
			eap_ds_free(&(node->prev_eapds));
			node->prev_eapds = node->eap_ds;
			node->eap_ds = NULL;

			/*
			 *	Stop here.
			 */
			break;
		} else  {
			last = &(node->next);
		}
	}

#ifdef HAVE_PTHREAD_H
	pthread_mutex_unlock(&(inst->session_mutex));
#endif

	if (!node) {
		DEBUG2("  rlm_eap: Request not found in the list");
	}
	return node;
}
