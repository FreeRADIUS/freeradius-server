/*
 * util.c	Various utility functions.
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
 * Copyright 2000  The FreeRADIUS server project
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>

#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_UNISTD_H
#	include <unistd.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "radiusd.h"
#include "rad_assert.h"

/*
 *	The signal() function in Solaris 2.5.1 sets SA_NODEFER in
 *	sa_flags, which causes grief if signal() is called in the
 *	handler before the cause of the signal has been cleared.
 *	(Infinite recursion).
 *
 *	The same problem appears on HPUX, so we avoid it, if we can.
 *
 *	Using sigaction() to reset the signal handler fixes the problem,
 *	so where available, we prefer that solution.
 */
void (*reset_signal(int signo, void (*func)(int)))(int)
{
#ifdef HAVE_SIGACTION
	struct sigaction act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
#ifdef  SA_INTERRUPT		/* SunOS */
	act.sa_flags |= SA_INTERRUPT;
#endif
	if (sigaction(signo, &act, &oact) < 0)
		return SIG_ERR;
	return oact.sa_handler;
#else
	
	/*
	 *	re-set by calling the 'signal' function, which
	 *	may cause infinite recursion and core dumps due to
	 *	stack growth.
	 *
	 *	However, the system is too dumb to implement sigaction(),
	 *	so we don't have a choice.
	 */
	signal(signo, func);
#endif
}

/*
 *	Per-request data, added by modules...
 */
struct request_data_t {
	request_data_t	*next;
	
	void		*unique_ptr;
	int		unique_int;
	void		*opaque;
	void		(*free_opaque)(void *);
};

/*
 *	Add opaque data (with a "free" function) to a REQUEST.
 *
 *	The unique ptr is meant to be a malloc'd module configuration,
 *	and the unique integer allows the caller to have multiple
 *	opaque data associated with a REQUEST.
 */
int request_data_add(REQUEST *request,
		     void *unique_ptr, int unique_int,
		     void *opaque, void (*free_opaque)(void *))
{
	request_data_t *this, **last, *next;

	/*
	 *	Some simple sanity checks.
	 */
	if (!request || !opaque) return -1;

	this = next = NULL;
	for (last = &(request->data); *last != NULL; last = &((*last)->next)) {
		if (((*last)->unique_ptr == unique_ptr) &&
		    ((*last)->unique_int == unique_int)) {
			this = *last;

			next = this->next;

			if (this->opaque && /* free it, if necessary */
			    this->free_opaque)
				this->free_opaque(this->opaque);
			break;	/* replace the existing entry */
		}
	}

	if (!this) this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	this->next = next;
	this->unique_ptr = unique_ptr;
	this->unique_int = unique_int;
	this->opaque = opaque;
	this->free_opaque = free_opaque;

	*last = this;

	return 0;
}


/*
 *	Get opaque data from a request.
 */
void *request_data_get(REQUEST *request,
		       void *unique_ptr, int unique_int)
{
	request_data_t **last;

	for (last = &(request->data); *last != NULL; last = &((*last)->next)) {
		if (((*last)->unique_ptr == unique_ptr) &&
		    ((*last)->unique_int == unique_int)) {
			request_data_t *this = *last;
			void *ptr = this->opaque;

			/*
			 *	Remove the entry from the list, and free it.
			 */
			*last = this->next;
			free(this);
			return ptr; /* don't free it, the caller does that */
		}
	}

	return NULL;		/* wasn't found, too bad... */
}


/*
 *	Free a REQUEST struct.
 */
void request_free(REQUEST **request_ptr)
{
	REQUEST *request;

	if (request_ptr == NULL)
		return;

	request = *request_ptr;

	/*
	 *	If there's a thread currently active on this request,
	 *	blow up!
	 */
	rad_assert(request->child_pid == NO_SUCH_CHILD_PID);
	
	if (request->packet) 
		rad_free(&request->packet);

	if (request->proxy) 
		rad_free(&request->proxy);

	if (request->reply) 
		rad_free(&request->reply);

	if (request->proxy_reply) 
		rad_free(&request->proxy_reply);

	if (request->config_items) 
		pairfree(&request->config_items);

	request->username = NULL;
	request->password = NULL;

	if (request->data) {
		request_data_t *this, *next;

		for (this = request->data; this != NULL; this = next) {
			next = this->next;
			if (this->opaque && /* free it, if necessary */
			    this->free_opaque)
				this->free_opaque(this->opaque);
			free(this);
		}
		request->data = NULL;
	}

#ifndef NDEBUG
	request->magic = 0x01020304;	/* set the request to be nonsense */
	strcpy(request->secret, "REQUEST-DELETED");
	strcpy(request->proxysecret, "REQUEST-DELETED");
#endif
	free(request);

	*request_ptr = NULL;
}

/*
 *	Check a filename for sanity.
 *
 *	Allow only uppercase/lowercase letters, numbers, and '-_/.'
 */
int rad_checkfilename(const char *filename)
{
	if (strspn(filename, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/.") == strlen(filename)) {
		return 0;
	}

	return -1;
}

/*
 *	Create possibly many directories.
 *
 *	Note that the input directory name is NOT a constant!
 *	This is so that IF an error is returned, the 'directory' ptr
 *	points to the name of the file which caused the error.
 */
int rad_mkdir(char *directory, int mode)
{
	int rcode;
	char *p;
	struct stat st;

	/*
	 *	If the directory exists, don't do anything.
	 */
	if (stat(directory, &st) == 0) {
		return 0;
	}

	/*
	 *	Look for the LAST directory name.  Try to create that,
	 *	failing on any error.
	 */
	p = strrchr(directory, '/');
	if (p != NULL) {
		*p = '\0';
		rcode = rad_mkdir(directory, mode);

		/*
		 *	On error, we leave the directory name as the
		 *	one which caused the error.
		 */
		if (rcode < 0) {
			return rcode;
		}

		/*
		 *	Reset the directory delimiter, and go ask
		 *	the system to make the directory.
		 */
		*p = '/';
	} else {
		return 0;
	}

	/*
	 *	Having done everything successfully, we do the
	 *	system call to actually go create the directory.
	 */
	return mkdir(directory, mode);
}


/*
 *	Module malloc() call, which does stuff if the malloc fails.
 *
 *	This call ALWAYS succeeds!
 */
void *rad_malloc(size_t size)
{
	void *ptr = malloc(size);
	
	if (ptr == NULL) {
		radlog(L_ERR|L_CONS, "no memory");
		exit(1);
	}

	return ptr;
}

void xfree(const char *ptr)
{
	free((char *)ptr);
}

/*
 *	Logs an error message and aborts the program
 *
 */

void rad_assert_fail (const char *file, unsigned int line)
{
	radlog(L_ERR|L_CONS, "Assertion failed in %s, line %u", file, line);
	abort();
}


/*
 *	Create a new REQUEST data structure.
 */
REQUEST *request_alloc(void)
{
	REQUEST *request;

	request = rad_malloc(sizeof(REQUEST));
	memset(request, 0, sizeof(REQUEST));
#ifndef NDEBUG
	request->magic = REQUEST_MAGIC;
#endif
	request->proxy = NULL;
	request->reply = NULL;
	request->proxy_reply = NULL;
	request->config_items = NULL;
	request->username = NULL;
	request->password = NULL;
	request->timestamp = time(NULL);
	request->child_pid = NO_SUCH_CHILD_PID;
	request->container = NULL;
	request->options = RAD_REQUEST_OPTION_NONE;

	return request;
}


/*
 *	Create a new REQUEST, based on an old one.
 *
 *	This function allows modules to inject fake requests
 *	into the server, for tunneled protocols like TTLS & PEAP.
 */
REQUEST *request_alloc_fake(REQUEST *oldreq)
{
  REQUEST *request;

  request = request_alloc();

  request->number = oldreq->number;
  request->child_pid = NO_SUCH_CHILD_PID;
  request->options = RAD_REQUEST_OPTION_FAKE_REQUEST;

  request->packet = rad_alloc(0);
  rad_assert(request->packet != NULL);

  request->reply = rad_alloc(0);
  rad_assert(request->reply != NULL);

  /*
   *	Fill in the fake request packet.
   */
  request->packet->sockfd = -1;
  request->packet->src_ipaddr = htonl(INADDR_LOOPBACK);
  request->packet->dst_ipaddr = htonl(INADDR_LOOPBACK);
  request->packet->src_port = request->number >> 8;
  request->packet->dst_port = 0;

  /*
   *	This isn't STRICTLY required, as the fake request SHOULD NEVER
   *	be put into the request list.  However, it's still reasonable
   *	practice.
   */
  request->packet->id = request->number & 0xff;
  request->packet->code = oldreq->packet->code;
  request->timestamp = oldreq->timestamp;

  /*
   *	Fill in the fake reply, based on the fake request.
   */
  request->reply->sockfd = request->packet->sockfd;
  request->reply->dst_ipaddr = request->packet->src_ipaddr;
  request->reply->dst_port = request->packet->src_port;
  request->reply->id = request->packet->id;
  request->reply->code = 0; /* UNKNOWN code */

  return request;
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
		pairmove2(&vps, &(packet->vps), PW_VENDOR_SPECIFIC);
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
 *  Reject a request, by sending a trivial reply packet.
 */
 void request_reject(REQUEST *request)
{
	VALUE_PAIR *vps;

	/*
	 *	Already rejected.  Don't do anything.
	 */
	if (request->options & RAD_REQUEST_OPTION_REJECTED) {
		return;
	}
	
	DEBUG2("Server rejecting request %d.", request->number);
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
	 *  If a reply exists, send it.
	 */
	if (request->reply->code != 0) {
		/*
		 *	If we're not delaying authentication rejects,
		 *	then send the response immediately.  Otherwise,
		 *	mark the request as delayed, and do NOT send a
		 *	response.
		 */
		if (mainconfig.reject_delay == 0) {
			rad_send(request->reply, request->packet,
				 request->secret);
		} else {
			request->options |= RAD_REQUEST_OPTION_DELAYED_REJECT;
		}
	}

	/*
	 *	Remember that it was rejected.
	 */
	request->options |= RAD_REQUEST_OPTION_REJECTED;
}
