#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"

static const char rcsid[] = "$Id$";

/*
 *	Do any per-module initialization.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 */
static int radius_init(int argc, char **argv)
{
  /*
   *	Quiet the compiler,  This is ONLY needed if the functions
   *	parameters are not used anywhere in the function.  If there
   *	were code here, we wouldn't need these two "fake" code lines.
   */
  argc = argc;
  argv = argv;

  return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int radius_authorize(REQUEST *request,
			    VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
  /* quiet the compiler */
  request = request;
  check_pairs = check_pairs;
  reply_pairs = reply_pairs;

  return RLM_AUTZ_OK;
}

/*
 *	Authenticate the user with the given password.
 */
static int radius_authenticate(REQUEST *request)
{
  /* quiet the compiler */
  request = request;

  return RLM_AUTH_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static int radius_accounting(REQUEST *request)
{
  /* quiet the compiler */
  request = request;

  return RLM_ACCT_OK;
}

/* globally exported name */
module_t rlm_example = {
  "example",
  0,				/* type: reserved */
  radius_init,			/* initialization */
  radius_authorize,		/* authorization */
  radius_authenticate,		/* authentication */
  radius_accounting,		/* accounting */
  NULL,				/* detach */
};
