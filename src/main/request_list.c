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

	id = request->packet->id;

	if (!request->prev) {
		request_list[id].first_request = request->next;
	} else {
		request->prev->next = request->next;
	}

	if (!request->next) {
		/*
		 *	Update tail pointer.
		 */
	} else {
		request->next->prev = request->prev;
	}
	
	request_free(request);
	request_list[id].request_count--;
}

/*
 *	Add a request to the request list.
 */
void rl_add(REQUEST *request)
{
	int id;
	REQUEST *curreq;

	id = request->packet->id;
	request->prev = NULL;
	request->next = NULL;

	if (!request_list[id].first_request) {
		request_list[id].first_request = request;
	} else {
		for (curreq = request_list[id].first_request ;
		     curreq->next != NULL ;
		     curreq = curreq->next)
			/* do nothing */ ;
		
		curreq->next = request;
		request->prev = curreq;
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
