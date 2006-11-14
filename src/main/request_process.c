/*
 * proxy.c	Proxy stuff.
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Chris Parker <cparker@starnetusa.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>

#include <sys/socket.h>

#ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>


/*
 *	Reprocess the request in possibly a child thread, only through
 *	a subsection of the post-proxy section of radiusd.conf.
 */
static int process_post_proxy_fail(REQUEST *request)
{
	VALUE_PAIR *vps;

	/*
	 *
	 */


	/*
	 *	Hmm... this code is copied from below, which isn't good,
	 *	and is similar to the code in rad_respond.
	 */
	switch (request->packet->code) {
		/*
		 *  Accounting requests, etc. get dropped on the floor.
		 */
	default:
	case PW_ACCOUNTING_REQUEST:
	case PW_STATUS_SERVER:
		break;
		
		/*
		 *  Authentication requests get their Proxy-State
		 *  attributes copied over, and an otherwise blank
		 *  reject message sent.
		 */
	case PW_AUTHENTICATION_REQUEST:
		request->reply->code = PW_AUTHENTICATION_REJECT;
		
		/*
		 *  Perform RFC limitations on outgoing replies.
		 */
		rfc_clean(request->reply);
		
		/*
		 *  Need to copy Proxy-State from request->packet->vps
		 */
		vps = paircopy2(request->packet->vps, PW_PROXY_STATE);
		if (vps != NULL)
			pairadd(&(request->reply->vps), vps);
		break;
	}
	
	/*
	 *	Send the reply.  The sender takes care of quenching
	 *	packets.
	 */
	request->listener->send(request->listener, request);

	return 0;		/* ignored for now */
}


/*
 *  Perform any RFC specified cleaning of outgoing replies
 */
void rfc_clean(RADIUS_PACKET *packet)
{
	VALUE_PAIR *vps = NULL;

	switch (packet->code) {
		/*
		 *	In the default case, we just move all of the
		 *	attributes over.
		 */
	default:
		vps = packet->vps;
		packet->vps = NULL;
		break;

		/*
		 *	Accounting responses can only contain
		 *	Proxy-State and VSA's.  Note that we do NOT
		 *	move the Proxy-State attributes over, as the
		 *	Proxy-State attributes in this packet are NOT
		 *	the right ones to use.  The reply function
		 *	takes care of copying those attributes from
		 *	the original request, which ARE the right ones
		 *	to use.
		 */
	case PW_ACCOUNTING_RESPONSE:
		pairmove2(&vps, &(packet->vps), PW_VENDOR_SPECIFIC);
		break;

		/*
		 *	Authentication REJECT's can have only
		 *	EAP-Message, Message-Authenticator
		 *	Reply-Message and Proxy-State.
		 *
		 *	We delete everything other than these.
		 *	Proxy-State is added below, just before the
		 *	reply is sent.
		 */
	case PW_AUTHENTICATION_REJECT:
		pairmove2(&vps, &(packet->vps), PW_EAP_MESSAGE);
		pairmove2(&vps, &(packet->vps), PW_MESSAGE_AUTHENTICATOR);
		pairmove2(&vps, &(packet->vps), PW_REPLY_MESSAGE);
		break;
	}

	/*
	 *	Move the newly cleaned attributes over.
	 */
	pairfree(&packet->vps);
	packet->vps = vps;

	/*
	 *	FIXME: Perform other, more generic sanity checks.
	 */
}


/*
 *	For debugging
 */
static const LRAD_NAME_NUMBER request_fail_reason[] = {
	{ "no threads available to handle the request",
	  REQUEST_FAIL_NO_THREADS },

	{ "malformed RADIUS packet",
	  REQUEST_FAIL_DECODE},

	{ "pre-proxying failed",
	  REQUEST_FAIL_PROXY},

	{ "sending of the proxy packet failed",
	  REQUEST_FAIL_PROXY_SEND},

	{ "failure to be told how to respond",
	  REQUEST_FAIL_NO_RESPONSE},

	{ "no response from the home server",
	  REQUEST_FAIL_HOME_SERVER},
	
	{ "no response from the home server after multiple tries",
	  REQUEST_FAIL_HOME_SERVER2},
	
	{ "no response from the home server for a long period of time",
	  REQUEST_FAIL_HOME_SERVER3},

	{ "we were told to reject the request",
	  REQUEST_FAIL_NORMAL_REJECT},

	{ NULL, REQUEST_FAIL_UNKNOWN }
};


/*
 *  Reject a request, by sending a trivial reply packet.
 */
 void request_reject(REQUEST *request, request_fail_t reason)
{
	VALUE_PAIR *vps;

	/*
	 *	Already rejected.  Don't do anything.
	 */
	if (request->options & RAD_REQUEST_OPTION_REJECTED) {
		return;
	}

	DEBUG2("Server rejecting request %d due to %s.",
	       request->number, lrad_int2str(request_fail_reason,
					     reason, "unknown"));

	/*
	 *	Remember that it was rejected.
	 */
	request->options |= RAD_REQUEST_OPTION_REJECTED;

	switch (reason) {
	case REQUEST_FAIL_NO_THREADS:
		DEBUG("WARNING: We recommend that you fix any TIMEOUT errors, or increase the value for \"max_servers\".");
		break;

	case REQUEST_FAIL_DECODE:
		DEBUG("WARNING: Someone may be attacking your RADIUS server.");
		break;

	case REQUEST_FAIL_NO_RESPONSE:
		DEBUG("WARNING: You did not configure the server to accept, or reject the user.  Double-check Auth-Type.");
		break;

		/*
		 *	If the home server goes down for some reason,
		 *	we want to be able to know when.  We do this
		 *	by calling a sub-section of the post_proxy section,
		 *	and processing any modules we find there.
		 *
		 *	Note that this subsection CAN edit the response
		 *	to the NAS.
		 */
	case REQUEST_FAIL_HOME_SERVER: /* Hmm... we may want only one */
	case REQUEST_FAIL_HOME_SERVER2:
	case REQUEST_FAIL_HOME_SERVER3:
		/*
		 *	Conditionally disable the home server we sent
		 *	packets to.
		 */
		realm_disable(request);
		
		/*
		 *	Not supposed to re-process it, 
		 */
		if (mainconfig.proxy_fail_type) {
			DICT_VALUE	*val;

			val = dict_valbyname(PW_POST_PROXY_TYPE, mainconfig.proxy_fail_type);
			if (!val) {
				DEBUG("ERROR: No such post-proxy type of \"%s\", cancelling post-proxy-failure call.", mainconfig.proxy_fail_type);
				return;
			}
			
			request->options |= RAD_REQUEST_OPTION_REPROCESS;
			
			thread_pool_addrequest(request, process_post_proxy_fail);
			return;
		}
		break;

	case REQUEST_FAIL_SERVER_TIMEOUT:
		radlog(L_ERR, "TIMEOUT for request %d in module %s, component %s",
		       request->number,
		       request->module ? request->module : "<server core>",
		       request->component ? request->component : "<server core>");
		request->options |= RAD_REQUEST_OPTION_STOP_NOW;
		break;

	default:		/* no additional messages, or things to do */
		break;
	}

	switch (request->packet->code) {
		/*
		 *  Accounting requests, etc. get dropped on the floor.
		 */
		default:
		case PW_ACCOUNTING_REQUEST:
		case PW_STATUS_SERVER:
			break;

		/*
		 *  Authentication requests get their Proxy-State
		 *  attributes copied over, and an otherwise blank
		 *  reject message sent.
		 */
		case PW_AUTHENTICATION_REQUEST:
			request->reply->code = PW_AUTHENTICATION_REJECT;

			/*
			 *  Perform RFC limitations on outgoing replies.
			 */
			rfc_clean(request->reply);

			/*
			 *  Need to copy Proxy-State from request->packet->vps
			 */
			vps = paircopy2(request->packet->vps, PW_PROXY_STATE);
			if (vps != NULL)
				pairadd(&(request->reply->vps), vps);
			break;
	}

	/*
	 *	Reject the request.  The sender will take care of delaying
	 *	or quenching rejects.
	 */
	request->listener->send(request->listener, request);
}


/*
 *  Respond to a request packet.
 *
 *  Maybe we reply, maybe we don't.
 *  Maybe we proxy the request to another server, or else maybe
 *  we replicate it to another server.
 */
int rad_respond(REQUEST *request, RAD_REQUEST_FUNP fun)
{
	RADIUS_PACKET *packet, *original;
	const char *secret;
	int finished = FALSE;

	rad_assert(request->magic == REQUEST_MAGIC);

	/*
	 *	Don't decode the packet if it's an internal "fake"
	 *	request.  Instead, just skip ahead to processing it.
	 */
	if ((request->options & RAD_REQUEST_OPTION_FAKE_REQUEST) != 0) {
		goto skip_decode;
	}

	/*
	 *	Re-process the request.
	 */
	if ((request->options & RAD_REQUEST_OPTION_REPROCESS) != 0) {
		goto skip_decode;
	}

	/*
	 *  Put the decoded packet into it's proper place.
	 */
	if (request->proxy_reply != NULL) {
		packet = request->proxy_reply;
		secret = request->proxysecret;
		original = request->proxy;
	} else {
		packet = request->packet;
		secret = request->secret;
		original = NULL;
	}

	/*
	 *  Decode the packet, verifying it's signature,
	 *  and parsing the attributes into structures.
	 *
	 *  Note that we do this CPU-intensive work in
	 *  a child thread, not the master.  This helps to
	 *  spread the load a little bit.
	 *
	 *  Internal requests (ones that never go on the
	 *  wire) have ->data==NULL (data is the wire
	 *  format) and don't need to be "decoded"
	 */
	if (packet->data) {
		int decoderesult;

		/*
		 *	Fails verification: silently discard it.
		 */
		decoderesult = rad_verify(packet, original, secret);
		if (decoderesult < 0) {
			radlog(L_ERR, "%s Dropping packet without response.", librad_errstr);
			/* Since accounting packets get this set in
			 * request_reject but no response is sent...
			 */
			request->options |= RAD_REQUEST_OPTION_REJECTED;
			goto finished_request;
		}

		/*
		 *	Can't decode it.  This usually means we're out
		 *	of memory.
		 */
		decoderesult = rad_decode(packet, original, secret);
		if (decoderesult < 0) {
			radlog(L_ERR, "%s", librad_errstr);
			request_reject(request, REQUEST_FAIL_DECODE);
			goto finished_request;
		}
	}

	/*
	 *  For proxy replies, remove non-allowed
	 *  attributes from the list of VP's.
	 */
	if (request->proxy) {
		int rcode;
		rcode = proxy_receive(request);
		switch (rcode) {
                default:  /* Don't Do Anything */
			break;
                case RLM_MODULE_FAIL:
			/* on error just continue with next request */
			goto next_request;
                case RLM_MODULE_HANDLED:
			/* if this was a replicated request, mark it as
			 * finished first, because it was postponed
			 */
			goto finished_request;
		}

	} else {
		/*
		 *	This is the initial incoming request which
		 *	we're processing.
		 *
		 *	Some requests do NOT get cached, as they
		 *	CANNOT possibly have duplicates.  Set the
		 *	magic option here.
		 *
		 *	Status-Server messages are easy to generate,
		 *	so we toss them as soon as we see a reply.
		 *
		 *	Accounting-Request packets WITHOUT an
		 *	Acct-Delay-Time attribute are NEVER
		 *	duplicated, as RFC 2866 Section 4.1 says that
		 *	the Acct-Delay-Time MUST be updated when the
		 *	packet is re-sent, which means the packet
		 *	changes, so it MUST have a new identifier and
		 *	Request Authenticator.  */
		if ((request->packet->code == PW_STATUS_SERVER) ||
		    ((request->packet->code == PW_ACCOUNTING_REQUEST) &&
		     (pairfind(request->packet->vps, PW_ACCT_DELAY_TIME) == NULL))) {
			request->options |= RAD_REQUEST_OPTION_DONT_CACHE;
		}
	}

 skip_decode:
	/*
	 *	We should have a User-Name attribute now.
	 */
	if (request->username == NULL) {
		request->username = pairfind(request->packet->vps,
				PW_USER_NAME);
	}

	(*fun)(request);

	/*
	 *	If the request took too long to process, don't do
	 *	anything else.
	 */
	if (request->options & RAD_REQUEST_OPTION_STOP_NOW) {
		finished = TRUE;
		goto postpone_request;
	}

	/*
	 *	If the request took too long to process, don't do
	 *	anything else.
	 */
	if (request->options & RAD_REQUEST_OPTION_REJECTED) {
		finished = TRUE;
		goto postpone_request;
	}

	/*
	 *	Status-Server requests NEVER get proxied.
	 */
	if (mainconfig.proxy_requests) {
		if ((request->packet->code != PW_STATUS_SERVER) &&
		    ((request->options & RAD_REQUEST_OPTION_PROXIED) == 0)) {
			int rcode;

			/*
			 *	Try to proxy this request.
			 */
			rcode = proxy_send(request);

			switch (rcode) {
			default:
				break;

			/*
			 *  There was an error trying to proxy the request.
			 *  Drop it on the floor.
			 */
			case RLM_MODULE_FAIL:
				DEBUG2("Error trying to proxy request %d: Rejecting it", request->number);
				request_reject(request, REQUEST_FAIL_PROXY);
				goto finished_request;
				break;

			/*
			 *  The pre-proxy module has decided to reject
			 *  the request.  Do so.
			 */
			case RLM_MODULE_REJECT:
				DEBUG2("Request %d rejected in proxy_send.", request->number);
				request_reject(request, REQUEST_FAIL_PROXY_SEND);
				goto finished_request;
				break;

			/*
			 *  If the proxy code has handled the request,
			 *  then postpone more processing, until we get
			 *  the reply packet from the home server.
			 */
			case RLM_MODULE_HANDLED:
				goto postpone_request;
				break;
			}

			/*
			 *  Else rcode==RLM_MODULE_NOOP
			 *  and the proxy code didn't do anything, so
			 *  we continue handling the request here.
			 */
		}
	} else if ((request->packet->code == PW_AUTHENTICATION_REQUEST) &&
		   (request->reply->code == 0)) {
		/*
		 *  We're not configured to reply to the packet,
		 *  and we're not proxying, so the DEFAULT behaviour
		 *  is to REJECT the user.
		 */
		request_reject(request, REQUEST_FAIL_NO_RESPONSE);
		goto finished_request;
	}

	/*
	 *  If we have a reply to send, copy the Proxy-State
	 *  attributes from the request to the tail of the reply,
	 *  and send the packet.
	 */
	rad_assert(request->magic == REQUEST_MAGIC);
	if (request->reply->code != 0) {
		VALUE_PAIR *vp = NULL;

		/*
		 *	Perform RFC limitations on outgoing replies.
		 */
		rfc_clean(request->reply);

		/*
		 *	Need to copy Proxy-State from request->packet->vps
		 */
		vp = paircopy2(request->packet->vps, PW_PROXY_STATE);
		if (vp) pairadd(&(request->reply->vps), vp);
	}

	/*
	 *	ALWAYS call the sender to send the reply.  The sender
	 *	will take care of doing the appropriate work to
	 *	suppress packets which aren't supposed to be sent over
	 *	the wire, or to be delayed.
	 */
	request->listener->send(request->listener, request);

	/*
	 *  We're done processing the request, set the
	 *  request to be finished, clean up as necessary,
	 *  and forget about the request.
	 */

finished_request:

	/*
	 *	Don't decode the packet if it's an internal "fake"
	 *	request.  Instead, just skip ahead to processing it.
	 */
	if ((request->options & RAD_REQUEST_OPTION_FAKE_REQUEST) != 0) {
		goto skip_free;
	}

	/*
	 *  We're done handling the request.  Free up the linked
	 *  lists of value pairs.  This might take a long time,
	 *  so it's more efficient to do it in a child thread,
	 *  instead of in the main handler when it eventually
	 *  gets around to deleting the request.
	 *
	 *  Also, no one should be using these items after the
	 *  request is finished, and the reply is sent.  Cleaning
	 *  them up here ensures that they're not being used again.
	 *
	 *  Hmm... cleaning them up in the child thread also seems
	 *  to make the server run more efficiently!
	 *
	 *  If we've delayed the REJECT, then do NOT clean up the request,
	 *  as we haven't created the REJECT message yet.
	 */
	if ((request->options & RAD_REQUEST_OPTION_DELAYED_REJECT) == 0) {
		if (request->packet) {
			pairfree(&request->packet->vps);
			request->username = NULL;
			request->password = NULL;
		}

		/*
		 *  If we've sent a reply to the NAS, then this request is
		 *  pretty much finished, and we have no more need for any
		 *  of the value-pair's in it, including the proxy stuff.
		 */
		if (request->reply->code != 0) {
			pairfree(&request->reply->vps);
		}
	}

	pairfree(&request->config_items);
	if (request->proxy) {
		pairfree(&request->proxy->vps);
	}
	if (request->proxy_reply) {
		pairfree(&request->proxy_reply->vps);
	}

 skip_free:
	DEBUG2("Finished request %d", request->number);
	finished = TRUE;

	/*
	 *  Go to the next request, without marking
	 *  the current one as finished.
	 *
	 *  Hmm... this may not be the brightest thing to do.
	 */
next_request:
	DEBUG2("Going to the next request");

postpone_request:
	return finished;
}
