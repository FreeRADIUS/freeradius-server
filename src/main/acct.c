/*
 * acct.c	Accounting routines.
 *
 * Version:	$Id$
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include	<stdlib.h>
#include	<string.h>

#include	"radiusd.h"
#include	"modules.h"


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
		
		/*
		 *	Maybe one of the preacct modules has decided
		 *	that a proxy should be used. If so, get out of
		 *	here and send the packet.
		 */
		if(pairfind(request->config_items, PW_PROXY_TO_REALM))
			return reply;
	}

	reply = RLM_MODULE_OK;
	if (!request->proxy) {
		/*
		 *	Keep the radutmp file in sync.
		 */
		radutmp_add(request);

		/*
		 *	Do accounting and if OK, reply.
		 */
		reply = module_accounting(request);
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

