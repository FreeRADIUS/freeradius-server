/*
 * request_list.c	Hide the handling of the REQUEST list from
 *			the main server.
 *
 * Version:	$Id$
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
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <stdlib.h>
#include <string.h>

#include "radiusd.h"
#include "rad_assert.h"
#include "request_list.h"
#include "radius_snmp.h"


/*
 *  We keep the incoming requests in an array, indexed by ID.
 *
 *  Each array element contains a linked list of containers of 
 *  active requests, a count of the number of requests, and a time 
 *  at which the first request in the list must be serviced.
 */

typedef struct REQNODE {
	struct REQNODE *prev, *next;
	REQUEST *req;
} REQNODE;

typedef struct REQUESTINFO {
	REQNODE *first_request;
	REQNODE *last_request;
	int request_count;
	time_t last_cleaned_list;
} REQUESTINFO;

static REQUESTINFO	request_list[256];

/*
 *	Initialize the request list.
 */
int rl_init(void)
{
	int i;

	/*
	 *	Initialize the request_list[] array.
	 */
	for (i = 0; i < 256; i++) {
		request_list[i].first_request = NULL;
		request_list[i].last_request = NULL;
		request_list[i].request_count = 0;
		request_list[i].last_cleaned_list = 0;
	}
	
	return 0;
}

/*
 *	Delete a particular request.
 */
void rl_delete(REQUEST *request)
{
	int id;
	REQNODE *prev, *next;

	prev = ((REQNODE *) request->container)->prev;
	next = ((REQNODE *) request->container)->next;
	
	id = request->packet->id;

	if (prev == NULL) {
		request_list[id].first_request = next;
	} else {
		prev->next = next;
	}

	if (next == NULL) {
		request_list[id].last_request = prev;
	} else {
		next->prev = prev;
	}
	
	free(request->container);

#ifdef WITH_SNMP
	/*
	 *	Update the SNMP statistics.
	 *
	 *	Note that we do NOT do this in rad_respond(),
	 *	as that function is called from child threads.
	 *	Instead, we update the stats when a request is
	 *	deleted, because only the main server thread calls
	 *	this function...
	 */
	if (mainconfig.do_snmp) {
		switch (request->reply->code) {
		case PW_AUTHENTICATION_ACK:
		  rad_snmp.auth.total_responses++;
		  rad_snmp.auth.total_access_accepts++;
		  break;

		case PW_AUTHENTICATION_REJECT:
		  rad_snmp.auth.total_responses++;
		  rad_snmp.auth.total_access_rejects++;
		  break;

		case PW_ACCESS_CHALLENGE:
		  rad_snmp.auth.total_responses++;
		  rad_snmp.auth.total_access_challenges++;
		  break;

		case PW_ACCOUNTING_RESPONSE:
		  rad_snmp.acct.total_responses++;
		  break;

		default:
			break;
		}
	}
#endif


	request_free(&request);
	request_list[id].request_count--;
}

/*
 *	Add a request to the request list.
 */
void rl_add(REQUEST *request)
{
	int id = request->packet->id;
	REQNODE *node;

	rad_assert(request->container == NULL);

	request->container = rad_malloc(sizeof(REQNODE));
	node = (REQNODE *) request->container;
	node->req = request;

	node->prev = NULL;
	node->next = NULL;

	if (!request_list[id].first_request) {
		rad_assert(request_list[id].request_count == 0);

		request_list[id].first_request = node;
		request_list[id].last_request = node;
	} else {
		rad_assert(request_list[id].request_count != 0);

		node->prev = request_list[id].last_request;
		request_list[id].last_request->next = node;
		request_list[id].last_request = node;
	}

	request_list[id].request_count++;
}

/*
 *	Look up a particular request, using:
 *
 *	Request ID, request code, source IP, source port, 
 *
 *	Note that we do NOT use the request vector to look up requests.
 *
 *	We MUST NOT have two requests with identical (id/code/IP/port), and
 *	different vectors.  This is a serious error!
 */
REQUEST *rl_find(RADIUS_PACKET *packet)
{
	REQNODE *curreq;

	for (curreq = request_list[packet->id].first_request;
			curreq != NULL ;
			curreq = ((REQNODE *)curreq->req->container)->next) {
		if ((curreq->req->packet->code == packet->code) &&
		    (curreq->req->packet->src_ipaddr == packet->src_ipaddr) &&
		    (curreq->req->packet->src_port == packet->src_port)) {
			return curreq->req;
		}
	}

	return NULL;
}

/*
 *	Look up a particular request, using:
 *
 *	Request Id, request code, source IP, source port,
 *
 *	Note that we do NOT use the request vector to look up requests.
 *
 *	We MUST NOT have two requests with identical (id/code/IP/port), and
 *	different vectors.  This is a serious error!
 */
REQUEST *rl_find_proxy(RADIUS_PACKET *packet)
{
	REQNODE *curreq = NULL;
	int id;
	
	/*
	 *	The Proxy RADIUS Id is completely independent
	 *	of the original request Id.  We've got to root through
	 *	*all* requests, in order to find it.
	 *
	 *	FIXME: Maybe we want to use the original packet Id
	 *	as the Proxy-State?
	 */
	for (id = 0; (id < 256) && (curreq == NULL); id++) {
		for (curreq = request_list[id].first_request;
		     curreq != NULL ;
		     curreq = curreq->next) {
			if (curreq->req->proxy &&
			    (curreq->req->proxy->id == packet->id) &&
			    (curreq->req->proxy->dst_ipaddr == packet->src_ipaddr) &&
			    (curreq->req->proxy->dst_port == packet->src_port)) {
				return curreq->req;
			}
		} /* loop over all requests for this id. */
	} /* loop over all id's... this is horribly inefficient */

	return NULL;
}
/*
 *	Walk over all requests, performing a callback for each request.
 */
int rl_walk(RL_WALK_FUNC walker, void *data)
{
	int id, rcode;
	REQNODE *curreq, *next;

	/*
	 *	Walk over all 256 ID's.
	 */
	for (id = 0; id < 256; id++) {

		/*
		 *	Walk over the request list for each ID.
		 */
		for (curreq = request_list[id].first_request;
				curreq != NULL ;
				curreq = next) {
			/*
			 *	The callback MIGHT delete the current
			 *	request, so we CANNOT depend on curreq->next
			 *	to be there, when going to the next element
			 *	in the 'for' loop.
			 */
			next = curreq->next;

			rcode = walker(curreq->req, data);
			if (rcode != RL_WALK_CONTINUE) {
				return rcode;
			}
		}
	}

	return 0;
}

/*
 *	Walk from one request to the next.
 */
REQUEST *rl_next(REQUEST *request)
{
	int id, start_id;
	int count;

	/*
	 *	If we were passed a request, then go to the "next" one.
	 */
	if (request != NULL) {
		rad_assert(request->magic == REQUEST_MAGIC);

		/*
		 *	It has a "next", return it.
		 */
		if (((REQNODE *)request->container)->next != NULL) {
			return ((REQNODE *)request->container)->next->req;
		} else {
			/*
			 *	No "next", increment the ID, and look
			 *	at that one.
			 */
			start_id = request->packet->id + 1;
			start_id &= 0xff;
			count = 255;
		}
	} else {
		/*
		 *	No input request, start looking at ID 0.
		 */
		start_id = 0;
		count = 256;
	}

	/*
	 *	Check all ID's, wrapping around at 255.
	 */
	for (id = start_id; id < (start_id + count); id++) {

		/*
		 *	This ID has a request, return it.
		 */
		if (request_list[id & 0xff].first_request != NULL) {
			rad_assert(request_list[id&0xff].first_request->req != request);

			return request_list[id & 0xff].first_request->req;
		}
	}

	/*
	 *	No requests at all in the list. Nothing to do.
	 */
	DEBUG2("rl_next:  returning NULL");
	return NULL;
}

/*
 *	Return the number of requests in the request list.
 */
int rl_num_requests(void)
{
	int id;
	int request_count = 0;

	for (id = 0; id < 256; id++) {
		request_count += request_list[id].request_count;
	}
	
	return request_count;
}
