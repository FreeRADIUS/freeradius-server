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

/*
 *      Allocate a new EAP_PACKET
 */
EAP_PACKET *eap_packet_alloc(void)
{
	EAP_PACKET   *rp;

	rp = rad_malloc(sizeof(EAP_PACKET));
	memset(rp, 0, sizeof(EAP_PACKET));
	return rp;
}

/*
 *      Free EAP_PACKET
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
 *      Allocate a new EAP_PACKET
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
 *      Allocate a new EAP_HANDLER
 */
EAP_HANDLER *eap_handler_alloc(void)
{
	EAP_HANDLER	*handler;
        
	if ((handler = malloc(sizeof(EAP_HANDLER))) == NULL) {
		radlog(L_ERR, "out of memory");
		return NULL;
	}
	handler = rad_malloc(sizeof(EAP_HANDLER));
	return handler;
}

void eap_handler_free(EAP_HANDLER **handler_p)
{
        EAP_HANDLER *handler;

	if ((handler_p == NULL) || (*handler_p == NULL))
		return;
        handler = *handler_p;

	if (handler->id) {
		free(handler->id);
		handler->id = NULL;
	}

	if (handler->identity) {
		free(handler->identity);
		handler->identity = NULL;
	}

	if (handler->username) pairfree(&(handler->username));
	if (handler->configured) pairfree(&(handler->configured));

	if (handler->prev_eapds) eap_ds_free(&(handler->prev_eapds));
	if (handler->eap_ds) eap_ds_free(&(handler->eap_ds));

	if ((handler->opaque) && (handler->free_opaque))
		handler->free_opaque(&handler->opaque);
	else if ((handler->opaque) && (handler->free_opaque == NULL))
                radlog(L_ERR, "Possible memory leak ...");

	handler->opaque = NULL;
	handler->free_opaque = NULL;
	handler->next = NULL;

	*handler_p = NULL;
}

void eaptype_freelist(EAP_TYPES **i)
{
        EAP_TYPES       *c, *next;

        c = *i;
        while (c) {
                next = c->next;
                if(c->type->detach) (c->type->detach)(&(c->type_stuff));
		if (c->handle) lt_dlclose(c->handle);
                free(c);
                c = next;
        }
        *i = NULL;
}

void eaplist_free(EAP_HANDLER **list)
{
	EAP_HANDLER *node, *next;
	if (!list) return;
	node = *list;

	while (node) {
		next = node->next;
		eap_handler_free(&node);
		node = next;
	}

	*list = NULL;
}

int eaplist_add(EAP_HANDLER **list, EAP_HANDLER *node)
{
	EAP_HANDLER	**last;

	if (node == NULL) return 0;
	
	last = list;
	while (*last) last = &((*last)->next);
	
	node->timestamp = time(NULL);
	node->status = 1;
	node->next = NULL;

	*last = node;
	return 1;
}

/*
 * List should contain only recent packets with life < x seconds.
 */
void eaplist_clean(EAP_HANDLER **first, time_t limit)
{
	time_t  now;
        EAP_HANDLER *node, *next;
        EAP_HANDLER **last = first;

	now = time(NULL);

	for (node = *first; node; node = next) {
		next = node->next;
		if ((now - node->timestamp) > limit) {
			radlog(L_INFO, "rlm_eap:  list_clean deleted one item");
			*last = next;
			eap_handler_free(&node);
		} else  {
			last = &(node->next);
		}
	}
}

/*
 * If the present EAP-Response is a reply to the previous
 * EAP-Request sent by us, then return the EAP_HANDLER
 * only after releasing from the eaplist
 * Also since we fill the eap_ds with the present EAP-Response
 * we got to free the prev_eapds & move the eap_ds to prev_eapds
 */
EAP_HANDLER *eaplist_isreply(EAP_HANDLER **first, unsigned char id[])
{
        EAP_HANDLER *node, *next, *ret = NULL;
        EAP_HANDLER **last = first;

	for (node = *first; node; node = next) {
		next = node->next;
		if (memcmp(node->id, id, id[0]) == 0) {
			radlog(L_INFO, "rlm_eap: Request found, released from the list");
			/* detach the node from the list */
			*last = next;
			node->next = NULL;

			/* clean up the unwanted stuff before returning */
			eap_ds_free(&(node->prev_eapds));
			node->prev_eapds = node->eap_ds;
			node->eap_ds = NULL;

			ret = node;
			break;
		} else  {
			last = &(node->next);
		}
	}

	if (!ret) {
		radlog(L_INFO, "rlm_eap: Request not found in the list");
	}
	return ret;
}

EAP_HANDLER *eaplist_findhandler(EAP_HANDLER *list, unsigned char id[])
{
	EAP_HANDLER *node;
	node = list;
	
	while (node) {
		/*
		 * Match is identified by the same IDs 
		 */
		if (memcmp(node->id, id, id[0]) == 0) {
			radlog(L_INFO, "rlm_eap: EAP Handler found in the list ");
			return node;
		}
		node = node->next;
	}
	return NULL;
}
