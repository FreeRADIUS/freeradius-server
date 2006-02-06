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

void eap_handler_free(EAP_HANDLER *handler)
{
	if (!handler)
		return;

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

	free(handler);
}

void eaptype_free(EAP_TYPES *i)
{
	if (i->type->detach) (i->type->detach)(i->type_data);
	i->type_data = NULL;
	if (i->handle) lt_dlclose(i->handle);
}


void eaplist_free(rlm_eap_t *inst)
{
	EAP_HANDLER *node, *next;

       	for (node = inst->session_head; node != NULL; node = next) {
		next = node->next;
		eap_handler_free(node);
	}

	inst->session_head = inst->session_tail = NULL;
}

/*
 *	Add a handler to the set of active sessions.
 *
 *	Since we're adding it to the list, we guess that this means
 *	the packet needs a State attribute.  So add one.
 */
int eaplist_add(rlm_eap_t *inst, EAP_HANDLER *handler)
{
	int		status;
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

	/*
	 *	The time at which this request was made was the time
	 *	at which it was received by the RADIUS server.
	 */
	handler->timestamp = handler->request->timestamp;
	handler->status = 1;

	memcpy(handler->state, state->strvalue, sizeof(handler->state));
	handler->src_ipaddr = handler->request->packet->src_ipaddr;
	handler->eap_id = handler->eap_ds->request->id;

	/*
	 *	We don't need this any more.
	 */
	handler->request = NULL;

	/*
	 *	Playing with a data structure shared among threads
	 *	means that we need a lock, to avoid conflict.
	 */
	pthread_mutex_lock(&(inst->session_mutex));

	/*
	 *	Big-time failure.
	 */
	status = rbtree_insert(inst->session_tree, handler);

	if (status) {
		EAP_HANDLER *prev;

		prev = inst->session_tail;
		if (prev) {
			prev->next = handler;
			handler->prev = prev;
		} else {
			inst->session_head = inst->session_tail = handler;
		}
	}

	/*
	 *	Now that we've finished mucking with the list,
	 *	unlock it.
	 */
	pthread_mutex_unlock(&(inst->session_mutex));

	if (!status) {
		radlog(L_ERR, "rlm_eap: Failed to remember handler!");
		eap_handler_free(handler);
		return 0;
	}

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
	int		i;
	VALUE_PAIR	*state;
	rbnode_t	*node;
	EAP_HANDLER	*handler, myHandler;

	/*
	 *	We key the sessions off of the 'state' attribute, so it
	 *	must exist.
	 */
	state = pairfind(request->packet->vps, PW_STATE);
	if (!state ||
	    (state->length != EAP_STATE_LEN)) {
		return NULL;
	}

	myHandler.src_ipaddr = request->packet->src_ipaddr;
	myHandler.eap_id = eap_packet->id;
	memcpy(myHandler.state, state->strvalue, sizeof(myHandler.state));

	/*
	 *	Playing with a data structure shared among threads
	 *	means that we need a lock, to avoid conflict.
	 */
	pthread_mutex_lock(&(inst->session_mutex));

	/*
	 *	Check the first few handlers in the list, and delete
	 *	them if they're too old.  We don't need to check them
	 *	all, as incoming requests will quickly cause older
	 *	handlers to be deleted.
	 *
	 */
	for (i = 0; i < 2; i++) {
		handler = inst->session_head;
		if (handler &&
		    ((request->timestamp - handler->timestamp) > inst->timer_limit)) {
			node = rbtree_find(inst->session_tree, handler);
			rad_assert(node != NULL);
			rbtree_delete(inst->session_tree, node);
			
			inst->session_head = handler->next;
			if (handler->next) handler->next->prev = NULL;
			eap_handler_free(handler);
		}
	}

	handler = NULL;
	node = rbtree_find(inst->session_tree, &myHandler);
	if (node) {
		handler = rbtree_node2data(inst->session_tree, node);

		/*
		 *	Check against replays.  The client can re-play
		 *	a State attribute verbatim, so we wish to
		 *	ensure that the attribute falls within the
		 *	valid time window, which is the second at
		 *	which it was sent out.
		 *
		 *	Hmm... I'm not sure that this step is
		 *	necessary, or even that it does anything.
		 */
		if (verify_state(state, handler->timestamp) != 0) {
			handler = NULL;
		} else {
			/*
			 *	It's OK, delete it from the tree.
			 */
			rbtree_delete(inst->session_tree, node);

			/*
			 *	And unsplice it from the linked list.
			 */
			if (handler->prev) {
				handler->prev->next = handler->next;
			} else {
				inst->session_head = NULL;
			}
			if (handler->next) {
				handler->next->prev = handler->prev;
			} else {
				inst->session_tail = NULL;
			}
			handler->prev = handler->next = NULL;
		}
	}

	pthread_mutex_unlock(&(inst->session_mutex));

	/*
	 *	Not found.
	 */
	if (!node) {
		DEBUG2("  rlm_eap: Request not found in the list");
		return NULL;
	}

	/*
	 *	Found, but state verification failed.
	 */
	if (!handler) {
		radlog(L_ERR, "rlm_eap: State verification failed.");
		return NULL;
	}

	DEBUG2("  rlm_eap: Request found, released from the list");

	/*
	 *	Remember what the previous request was.
	 */
	eap_ds_free(&(handler->prev_eapds));
	handler->prev_eapds = handler->eap_ds;
	handler->eap_ds = NULL;
	
	return handler;
}
