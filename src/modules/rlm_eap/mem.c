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
#include "eap.h"

/*
 *      Allocate a new EAP_PACKET.  Guaranteed to succeed.
 */
EAP_PACKET *eap_packet_alloc(void)
{
        EAP_PACKET   *rp;

        rp = rad_malloc(sizeof(EAP_PACKET));
        memset(rp, 0, sizeof(EAP_PACKET));
        return rp;
}

/*
 *      Free a EAP_PACKET
 */
void eap_packet_free(EAP_PACKET **eap_packet_ptr)
{
        EAP_PACKET *eap_packet;

        if (!eap_packet_ptr) return;
        eap_packet = *eap_packet_ptr;
	if (!eap_packet) return;

        if (eap_packet->typedata) free(eap_packet->typedata);
        if (eap_packet->rad_vps) pairfree(&(eap_packet->rad_vps));

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
	eap_ds->response = eap_packet_alloc();
	eap_ds->request = eap_packet_alloc();

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

	if (eap_ds->username) pairfree(&(eap_ds->username));
	if (eap_ds->password) pairfree(&(eap_ds->password));

	free(eap_ds);
	*eap_ds_p = NULL;
}

void free_type_list(EAP_TYPES **i)
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

void node_free(EAP_LIST **node)
{
	if (node == NULL) return;
	if (*node == NULL) return;
	if ((*node)->eap_ds) eap_ds_free(&((*node)->eap_ds));

	(*node)->next = NULL;
	free(*node);
	*node = NULL;
}

void list_free(EAP_LIST **list)
{
	EAP_LIST *node, *next;

	if (!list) return;
	node = *list;

	while (node) {
		next = node->next;
		node_free(&node);
		node = next;
	}

	*list = NULL;
}

int list_add(EAP_LIST **list, EAP_DS *eap_ds)
{
	EAP_LIST	*node, **last;

	if (!eap_ds) return 0;
	
	last = list;
	while (*last) *last = (*last)->next;
	
	eap_ds->timestamp = time(NULL);
	eap_ds->finished = 1;

	node = malloc(sizeof(EAP_LIST));
	if (!node) {
                radlog(L_ERR, "rlm_eap: out of memory");
		return 0;
	}

	node->next = NULL;
	node->eap_ds = eap_ds;

	*last = node;
	return 1;
}

/*
 * List should contain only recent packets with life < X seconds.
 */
void list_clean(EAP_LIST **first, time_t limit)
{
	time_t  now;
        EAP_LIST *node, *next;
        EAP_LIST **last = first;

	now = time(NULL);

	for (node = *first; node; node = next) {
		next = node->next;
		if ((now - node->eap_ds->timestamp) > limit) {
			radlog(L_INFO, "rlm_eap:  list_clean deleted one item");
			*last = next;
			node_free(&node);
		} else  {
			last = &(node->next);
		}
	}
}

void remove_item(EAP_LIST **first, EAP_LIST *item)
{
	time_t  now;
        EAP_LIST *node, *next;
        EAP_LIST **last = first;

	now = time(NULL);

	for (node = *first; node; node = next) {
		next = node->next;
		if (node == item) {
			radlog(L_INFO, "rlm_eap:  remove_item deleted one item");
			*last = next;
			node_free(&node);
		} else  {
			last = &(node->next);
		}
	}
}
