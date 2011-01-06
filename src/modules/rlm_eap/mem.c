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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <stdio.h>
#include "rlm_eap.h"

#ifdef HAVE_PTHREAD_H
#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

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
		 *	There's no packet, OR the type data isn't
		 *	pointing inside of the packet: free it.
		 */
		if ((eap_packet->packet == NULL) ||
		    (eap_packet->type.data != (eap_packet->packet + 5))) {
			free(eap_packet->type.data);
		}
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
EAP_HANDLER *eap_handler_alloc(rlm_eap_t *inst)
{
	EAP_HANDLER	*handler;

	handler = rad_malloc(sizeof(EAP_HANDLER));
	memset(handler, 0, sizeof(EAP_HANDLER));

	if (inst->handler_tree) {
		PTHREAD_MUTEX_LOCK(&(inst->handler_mutex));
		rbtree_insert(inst->handler_tree, handler);
		PTHREAD_MUTEX_UNLOCK(&(inst->handler_mutex));
	
	}
	return handler;
}

void eap_handler_free(rlm_eap_t *inst, EAP_HANDLER *handler)
{
	if (!handler)
		return;

	if (inst->handler_tree) {
		PTHREAD_MUTEX_LOCK(&(inst->handler_mutex));
		rbtree_deletebydata(inst->handler_tree, handler);
		PTHREAD_MUTEX_UNLOCK(&(inst->handler_mutex));
	}

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

	if (handler->certs) pairfree(&handler->certs);

	free(handler);
}


typedef struct check_handler_t {
	rlm_eap_t	*inst;
	EAP_HANDLER	*handler;
	int		trips;
} check_handler_t;

static void check_handler(void *data)
{
	int do_warning = FALSE;
	uint8_t state[8];
	check_handler_t *check = data;

	if (!check) return;

	if (!check->inst || !check->handler) {
		free(check);
		return;
	}

	if (!check->inst->handler_tree) goto done;

	PTHREAD_MUTEX_LOCK(&(check->inst->handler_mutex));
	if (!rbtree_finddata(check->inst->handler_tree, check->handler)) {
		goto done;
	}

	/*
	 *	The session has continued *after* this packet.
	 *	Don't do a warning.
	 */
	if (check->handler->trips > check->trips) {
		goto done;
	}

	/*
	 *	No TLS means no warnings.
	 */
	if (!check->handler->tls) goto done;

	/*
	 *	If we're being deleted early, it's likely because we
	 *	received a transmit from the client that re-uses the
	 *	same RADIUS Id, which forces the current packet to be
	 *	deleted.  In that case, ignore the error.
	 */
	if (time(NULL) < (check->handler->timestamp + 3)) goto done;

	if (!check->handler->finished) {
		do_warning = TRUE;
		memcpy(state, check->handler->state, sizeof(state));
	}

done:
	PTHREAD_MUTEX_UNLOCK(&(check->inst->handler_mutex));
	free(check);

	if (do_warning) {
		DEBUG("WARNING: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		DEBUG("WARNING: !! EAP session for state 0x%02x%02x%02x%02x%02x%02x%02x%02x did not finish!",
		      state[0], state[1],
		      state[2], state[3],
		      state[4], state[5],
		      state[6], state[7]);

		DEBUG("WARNING: !! Please read http://wiki.freeradius.org/Certificate_Compatibility");
		DEBUG("WARNING: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	}
}

void eaptype_free(EAP_TYPES *i)
{
	if (i->type->detach) (i->type->detach)(i->type_data);
	i->type_data = NULL;
	if (i->handle) lt_dlclose(i->handle);
	free(i);
}


void eaplist_free(rlm_eap_t *inst)
{
	EAP_HANDLER *node, *next;

       	for (node = inst->session_head; node != NULL; node = next) {
		next = node->next;
		eap_handler_free(inst, node);
	}

	inst->session_head = inst->session_tail = NULL;
}

/*
 *	Return a 32-bit random number.
 */
static uint32_t eap_rand(fr_randctx *ctx)
{
	uint32_t num;

	num = ctx->randrsl[ctx->randcnt++];
	if (ctx->randcnt >= 256) {
		ctx->randcnt = 0;
		fr_isaac(ctx);
	}

	return num;
}


static EAP_HANDLER *eaplist_delete(rlm_eap_t *inst, EAP_HANDLER *handler)
{
	rbnode_t *node;

	node = rbtree_find(inst->session_tree, handler);
	if (!node) return NULL;

	handler = rbtree_node2data(inst->session_tree, node);

	/*
	 *	Delete old handler from the tree.
	 */
	rbtree_delete(inst->session_tree, node);
	
	/*
	 *	And unsplice it from the linked list.
	 */
	if (handler->prev) {
		handler->prev->next = handler->next;
	} else {
		inst->session_head = handler->next;
	}
	if (handler->next) {
		handler->next->prev = handler->prev;
	} else {
		inst->session_tail = handler->prev;
	}
	handler->prev = handler->next = NULL;

	return handler;
}


static void eaplist_expire(rlm_eap_t *inst, time_t timestamp)
{
	int i;
	EAP_HANDLER *handler;

	/*
	 *	Check the first few handlers in the list, and delete
	 *	them if they're too old.  We don't need to check them
	 *	all, as incoming requests will quickly cause older
	 *	handlers to be deleted.
	 *
	 */
	for (i = 0; i < 3; i++) {
		handler = inst->session_head;
		if (!handler) break;

		/*
		 *	Expire entries from the start of the list.
		 *	They should be the oldest ones.
		 */
		if ((timestamp - handler->timestamp) > inst->timer_limit) {
			rbnode_t *node;
			node = rbtree_find(inst->session_tree, handler);
			rad_assert(node != NULL);
			rbtree_delete(inst->session_tree, node);

			/*
			 *	handler == inst->session_head
			 */
			inst->session_head = handler->next;
			if (handler->next) {
				handler->next->prev = NULL;
			} else {
				inst->session_head = NULL;
				inst->session_tail = NULL;
			}
			eap_handler_free(inst, handler);
		}
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
	int		status = 0;
	VALUE_PAIR	*state;
	REQUEST		*request = handler->request;

	rad_assert(handler != NULL);
	rad_assert(request != NULL);

	/*
	 *	Generate State, since we've been asked to add it to
	 *	the list.
	 */
	state = pairmake("State", "0x00", T_OP_EQ);
	if (!state) return 0;

	/*
	 *	The time at which this request was made was the time
	 *	at which it was received by the RADIUS server.
	 */
	handler->timestamp = request->timestamp;
	handler->status = 1;

	handler->src_ipaddr = request->packet->src_ipaddr;
	handler->eap_id = handler->eap_ds->request->id;

	/*
	 *	Playing with a data structure shared among threads
	 *	means that we need a lock, to avoid conflict.
	 */
	PTHREAD_MUTEX_LOCK(&(inst->session_mutex));

	/*
	 *	If we have a DoS attack, discard new sessions.
	 */
	if (rbtree_num_elements(inst->session_tree) >= inst->max_sessions) {
		status = -1;
		eaplist_expire(inst, handler->timestamp);
		goto done;
	}

	/*
	 *	Create a unique content for the State variable.
	 *	It will be modified slightly per round trip, but less so
	 *	than in 1.x.
	 */
	if (handler->trips == 0) {
		int i;

		for (i = 0; i < 4; i++) {
			uint32_t lvalue;

			lvalue = eap_rand(&inst->rand_pool);

			memcpy(handler->state + i * 4, &lvalue,
			       sizeof(lvalue));
		}		
	}

	memcpy(state->vp_octets, handler->state, sizeof(handler->state));
	state->length = EAP_STATE_LEN;

	/*
	 *	Add some more data to distinguish the sessions.
	 */
	state->vp_octets[4] = handler->trips ^ handler->state[0];
	state->vp_octets[5] = handler->eap_id ^ handler->state[1];
	state->vp_octets[6] = handler->eap_type ^ handler->state[2];

	/*
	 *	and copy the state back again.
	 */
	memcpy(handler->state, state->vp_octets, sizeof(handler->state));

	/*
	 *	Big-time failure.
	 */
	status = rbtree_insert(inst->session_tree, handler);

	/*
	 *	Catch Access-Challenge without response.
	 */
	if (inst->handler_tree) {
		check_handler_t *check = rad_malloc(sizeof(*check));

		check->inst = inst;
		check->handler = handler;
		check->trips = handler->trips;
		request_data_add(request, inst, 0, check, check_handler);
	}

	if (status) {
		EAP_HANDLER *prev;

		prev = inst->session_tail;
		if (prev) {
			prev->next = handler;
			handler->prev = prev;
			handler->next = NULL;
			inst->session_tail = handler;
		} else {
			inst->session_head = inst->session_tail = handler;
			handler->next = handler->prev = NULL;
		}
	}

	/*
	 *	Now that we've finished mucking with the list,
	 *	unlock it.
	 */
 done:

	/*
	 *	We don't need this any more.
	 */
	if (status > 0) handler->request = NULL;

	PTHREAD_MUTEX_UNLOCK(&(inst->session_mutex));

	if (status <= 0) {
		pairfree(&state);

		if (status < 0) {
			static time_t last_logged = 0;

			if (last_logged < handler->timestamp) {
				last_logged = handler->timestamp;
				radlog(L_ERR, "rlm_eap: Too many open sessions.  Try increasing \"max_sessions\" in the EAP module configuration");
			}				       
		} else {
			radlog(L_ERR, "rlm_eap: Internal error: failed to store handler");
		}
		return 0;
	}

	pairadd(&(request->reply->vps), state);

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
	VALUE_PAIR	*state;
	EAP_HANDLER	*handler, myHandler;

	/*
	 *	We key the sessions off of the 'state' attribute, so it
	 *	must exist.
	 */
	state = pairfind(request->packet->vps, PW_STATE, 0);
	if (!state ||
	    (state->length != EAP_STATE_LEN)) {
		return NULL;
	}

	myHandler.src_ipaddr = request->packet->src_ipaddr;
	myHandler.eap_id = eap_packet->id;
	memcpy(myHandler.state, state->vp_strvalue, sizeof(myHandler.state));

	/*
	 *	Playing with a data structure shared among threads
	 *	means that we need a lock, to avoid conflict.
	 */
	PTHREAD_MUTEX_LOCK(&(inst->session_mutex));

	eaplist_expire(inst, request->timestamp);

	handler = eaplist_delete(inst, &myHandler);
	PTHREAD_MUTEX_UNLOCK(&(inst->session_mutex));

	/*
	 *	Might not have been there.
	 */
	if (!handler) {
		radlog(L_ERR, "rlm_eap: No EAP session matching the State variable.");
		return NULL;
	}

	if (handler->trips >= 50) {
		RDEBUG2("More than 50 authentication packets for this EAP session.  Aborted.");
		eap_handler_free(inst, handler);
		return NULL;
	}
	handler->trips++;

	RDEBUG2("Request found, released from the list");

	/*
	 *	Remember what the previous request was.
	 */
	eap_ds_free(&(handler->prev_eapds));
	handler->prev_eapds = handler->eap_ds;
	handler->eap_ds = NULL;

	return handler;
}
