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
	int		reply;

	if(!request->proxy) { /* Only need to do this once, before proxying */
		reply = module_preacct(request);
		if (reply != RLM_MODULE_NOOP &&
				reply != RLM_MODULE_OK &&
				reply != RLM_MODULE_UPDATED)
			return reply;
		
	}

	reply = RLM_MODULE_OK;

	/*
	 *	Do accounting
	 */
	reply = module_accounting(request);
	
	/*
	 *	Maybe one of the preacct modules has decided
	 *	that a proxy should be used. If so, get out of
	 *	here and send the packet.
	 */
	if(pairfind(request->config_items, PW_PROXY_TO_REALM)) {
	        return reply;
	}

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

