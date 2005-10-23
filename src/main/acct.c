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

	/*
	 *	Run the modules only once, before proxying.
	 */
	if (!request->proxy) {
		VALUE_PAIR	*vp;
		int		acct_type;

		reply = module_preacct(request);
		if (reply != RLM_MODULE_NOOP &&
		    reply != RLM_MODULE_OK &&
		    reply != RLM_MODULE_HANDLED &&
		    reply != RLM_MODULE_UPDATED)
			return reply;

		/*
		 *	Do the data storage before proxying. This is to ensure
		 *	that we log the packet, even if the proxy never does.
		 *
		 *	In case the accounting module returns FAIL, it's still
		 *	useful to send the data to the proxy.
		 */
		vp = pairfind(request->config_items, PW_ACCT_TYPE);
		acct_type = vp ? vp->lvalue : 0;
		reply = module_accounting(acct_type, request);
		if (reply != RLM_MODULE_NOOP &&
		    reply != RLM_MODULE_OK &&
		    reply != RLM_MODULE_HANDLED &&
		    reply != RLM_MODULE_UPDATED &&
		    reply != RLM_MODULE_FAIL)
			return reply;

		/*
		 *	Maybe one of the preacct modules has decided
		 *	that a proxy should be used.
		 */
		if ((vp = pairfind(request->config_items, PW_PROXY_TO_REALM))) {
			REALM *realm;

			/*
			 *	Check whether Proxy-To-Realm is
			 *	a LOCAL realm.
			 */
			realm = realm_find(vp->vp_strvalue, TRUE);
			if (realm != NULL &&
			    realm->acct_ipaddr.af == AF_INET &&
			    realm->acct_ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_NONE)) {
				DEBUG("rad_accounting: Cancelling proxy to realm %s, as it is a LOCAL realm.", realm->realm);
				pairdelete(&request->config_items, PW_PROXY_TO_REALM);
			} else {
				/*
				 *	Don't reply to the NAS now because
				 *	we have to send the proxied packet
				 *	before that.
				 */
				return reply;
			}
		}
	}

	/*
	 *	We get here IF we're not proxying, OR if we've
	 *	received the accounting reply from the end server,
	 *	THEN we can reply to the NAS.
	 *      If the accounting module returns NOOP, the data
	 *      storage did not succeed, so radiusd should not send
	 *      Accounting-Response.
	 */
	if (reply == RLM_MODULE_OK ||
	    reply == RLM_MODULE_HANDLED ||
	    reply == RLM_MODULE_UPDATED) {

		/*
		 *	Now send back an ACK to the NAS.
		 */
		request->reply->code = PW_ACCOUNTING_RESPONSE;
	}

	return reply;
}
