/*
 * acct.c	Accounting routines.
 *
 * Version:	@(#)acct.c  2.12  07-Aug-1999  miquels@cistron.nl
 */
char acct_sccsid[] =
"@(#)acct.c	2.12 Copyright 1999 Cistron Internet Services B.V.";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/time.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<errno.h>

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
	  if(reply!=RLM_PRAC_OK)
		  return RLM_ACCT_FAIL;

	  /* Maybe one of the preacct modules has decided that a proxy should
	   * be used. If so, get out of here and send the packet. */
	  if(pairfind(request->config_items, PW_PROXY_TO_REALM))
		  return 0;
	}

	reply=RLM_ACCT_OK;
	if(!request->proxy) {
		/*
		 *	Keep the radutmp file in sync.
		 */
		radutmp_add(request);

		/*
		 *	Do accounting and if OK, reply.
		 */
		reply = module_accounting(request);
	}
	if (reply == RLM_ACCT_OK || reply == RLM_ACCT_FAIL_SOFT) {
		/*
		 *	Now send back an ACK to the NAS.
		 */
		request->reply = build_reply(PW_ACCOUNTING_RESPONSE, request,
					     NULL, NULL);
		reply = RLM_ACCT_OK;
	}

	return reply;
}

