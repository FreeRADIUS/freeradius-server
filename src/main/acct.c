/*
 * acct.c	Accounting routines.
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
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2000  Alan Curry <pacman@world.std.com>
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <stdlib.h>
#include <string.h>

#include "radiusd.h"
#include "modules.h"


/*
 *	rad_accounting: call modules.
 *
 *	The return value of this function isn't actually used right now, so
 *	it's not entirely clear if it is returning the right things. --Pac.
 */
int rad_accounting(REQUEST *request)
{
	int		reply = RLM_MODULE_OK;

	if (!request->proxy) { /* Only need to do this once, before proxying */
		char		*exec_program;
		int		exec_wait;
		VALUE_PAIR	*vp;
		int		rcode;
		int		acct_type = 0;

		reply = module_preacct(request);
		if (reply != RLM_MODULE_NOOP &&
		    reply != RLM_MODULE_OK &&
		    reply != RLM_MODULE_UPDATED)
			return reply;
		
		/*
		 *	Do accounting, ONLY the first time through.
		 *	This is to ensure that we log the packet
		 *	immediately, even if the proxy never does.
		 */
		vp = pairfind(request->config_items, PW_ACCTTYPE);
		if (vp)
			acct_type = vp->lvalue;
		reply = module_accounting(acct_type,request);
		
		/*
		 *	See if we need to execute a program.
		 *	FIXME: somehow cache this info, and only execute the
		 *	program when we receive an Accounting-START packet.
		 *	Only at that time we know dynamic IP etc.
		 */
		exec_program = NULL;
		exec_wait = 0;
		if ((vp = pairfind(request->reply->vps, PW_EXEC_PROGRAM)) != NULL) {
			exec_wait = 0;
			exec_program = strdup((char *)vp->strvalue);
			pairdelete(&request->reply->vps, PW_EXEC_PROGRAM);
		}

		if ((vp = pairfind(request->reply->vps, PW_EXEC_PROGRAM_WAIT)) != NULL) {
			exec_wait = 1;
			exec_program = strdup((char *)vp->strvalue);
			pairdelete(&request->reply->vps, PW_EXEC_PROGRAM_WAIT);
		}
		
		/*
		 *	If we want to exec a program, but wait for it,
		 *	do it first before sending the reply, or
		 *	proxying the packet.
		 *
		 *	If we're NOT waiting, then also do this now, but
		 *	don't check the return code.
		 */
		if (exec_program) {
			/*
			 *	Wait for the answer.
			 *	Don't look for a user message.
			 *	Do look for returned VP's.
			 */
			rcode = radius_exec_program(exec_program, request,
						    exec_wait,
						    NULL, 0, TRUE);
			if (exec_wait) {
				if (rcode != 0) {
					free(exec_program);
					return reply;
				}
			}
		}

		if (exec_program) 
			free(exec_program);

		/*
		 *	Maybe one of the preacct modules has decided
		 *	that a proxy should be used. If so, get out of
		 *	here and send the proxied packet, but ONLY if
		 *	there isn't one already...
		 */
		if (pairfind(request->config_items, PW_PROXY_TO_REALM)) {
			return reply;
		}
	}

	/*
	 *	We get here IF we're not proxying, OR if we've
	 *	received the accounting reply from the end server,
	 *	THEN we can reply to the NAS.
	 */
	if (reply == RLM_MODULE_NOOP ||
	    reply == RLM_MODULE_OK ||
	    reply == RLM_MODULE_UPDATED) {

		/*
		 *	Now send back an ACK to the NAS.
		 */
		request->reply->code = PW_ACCOUNTING_RESPONSE;
	}

	return reply;
}

