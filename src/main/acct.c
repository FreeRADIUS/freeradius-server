/*
 * acct.c	Accounting routines.
 *
 * Version:	$Id$
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<stdlib.h>
#include	<string.h>

#include	"radiusd.h"
#include	"modules.h"


/*
 *	rad_accounting: call modules.
 */
int rad_accounting(REQUEST *request)
{
	int		reply;

	/*
	 *	FIXME: Prefix= and Suffix= support needs to be added!
	 *
	 *	We need to get the Prefix= and Suffix= things from
	 *	the users file to apply.
	 *	In 1.5.4.3, we used presuf_setup() but that is
	 *	not possible anymore. Perhaps we need an extra
	 *	module entry point for this ?
	 */
	/* Like preacct? */

	if(!request->proxy) { /* Only need to do this once, before proxying */
	  reply = module_preacct(request);
	  if (reply != RLM_MODULE_OK)
		  return RLM_MODULE_FAIL;

	  /* Maybe one of the preacct modules has decided that a proxy should
	   * be used. If so, get out of here and send the packet. */
	  if(pairfind(request->config_items, PW_PROXY_TO_REALM))
		  return 0;
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
	if (reply == RLM_MODULE_OK) {
		/*
		 *	Now send back an ACK to the NAS.
		 */
		request->reply->code = PW_ACCOUNTING_RESPONSE;
		reply = RLM_MODULE_OK;
	}

	return reply;
}

