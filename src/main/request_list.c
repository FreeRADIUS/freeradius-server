/*
 * request_list.c	Hide the handling of the REQUEST list from
 *			the main server.
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include	<stdlib.h>
#include	<string.h>
#include	<assert.h>

#include	"radiusd.h"
#include	"request_list.h"

REQUEST_LIST	request_list[256];

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
	REQUEST *prev, *next;

	prev = request->prev;
	next = request->next;
	
	id = request->packet->id;

	if (!prev) {
		request_list[id].first_request = next;
	} else {
		prev->next = next;
	}

	if (!next) {
		request_list[id].last_request = prev;
	} else {
		next->prev = prev;
	}
	
	request_free(&request);
	request_list[id].request_count--;
}

/*
 *	Add a request to the request list.
 */
void rl_add(REQUEST *request)
{
	int id = request->packet->id;

	request->prev = NULL;
	request->next = NULL;

	if (!request_list[id].first_request) {
		assert(request_list[id].request_count == 0);

		request_list[id].first_request = request;
		request_list[id].last_request = request;
	} else {
		assert(request_list[id].request_count != 0);

		request->prev = request_list[id].last_request;
		request_list[id].last_request->next = request;
		request_list[id].last_request = request;
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
REQUEST *rl_find(REQUEST *request)
{
	REQUEST *curreq;

	for (curreq = request_list[request->packet->id].first_request;
	     curreq != NULL ;
	     curreq = curreq->next) {
		if ((curreq->packet->code == request->packet->code) &&
		    (curreq->packet->src_ipaddr == request->packet->src_ipaddr) &&
		    (curreq->packet->src_port == request->packet->src_port)) {
			break;
		}
	}

	return curreq;
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
REQUEST *rl_find_proxy(REQUEST *request)
{
	REQUEST *curreq = NULL;
	int id;
	
	for (id = 0; (id < 256) && (curreq == NULL); id++) {
		for (curreq = request_list[request->packet->id].first_request;
		     curreq != NULL ;
		     curreq = curreq->next) {
			if (curreq->proxy &&
			    (curreq->proxy->id == request->packet->id) &&
			    (curreq->proxy->dst_ipaddr == request->packet->src_ipaddr) &&
			    (curreq->proxy->dst_port == request->packet->src_port)) {
				
				break;
			}
		} /* loop over all requests for this id. */
	} /* loop over all id's... this is horribly inefficient */

	return curreq;
}
/*
 *	Walk over all requests, performing a callback for each request.
 */
int rl_walk(RL_WALK_FUNC walker, void *data)
{
	int id, rcode;
	REQUEST *curreq, *next;;

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

			rcode = walker(curreq, data);
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

	/*
	 *	If we were passed a request, then go to the "next" one.
	 */
	if (request) {
		assert(request->magic == REQUEST_MAGIC);

		/*
		 *	It has a "next", return it.
		 */
		if (request->next) {
			return request->next;
		} else {
			/*
			 *	No "next", increment the ID, and look
			 *	at that one.
			 */
			start_id = request->packet->id + 1;
			start_id &= 0xff;
		}
	} else {
		/*
		 *	No input request, start looking at ID 0.
		 */
		start_id = 0;
	}

	/*
	 *	Check all ID's, wrapping around at 255.
	 */
	for (id = start_id; id < (start_id + 256); id++) {

		/*
		 *	This ID has a request, return it.
		 */
		if (request_list[id & 0xff].first_request) {
			if(request != request_list[id & 0xff].first_request) {
				return request_list[id & 0xff].first_request;
			}
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
