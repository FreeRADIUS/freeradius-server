#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"

static int radius_init(int argc, char **argv)
{
  return 0;
}

static int radius_authenticate(REQUEST *request, char *username, char *password)
{
  return RLM_AUTH_OK;
}

static int radius_accounting(REQUEST *request)
{
  return RLM_ACCT_OK;
}

/* globally exported name */
module_t rlm_example = {
  "example",
  0,				/* type: reserved */
  radius_init,			/* initialization */
  NULL,				/* authorization */
  radius_authenticate,		/* authentication */
  radius_accounting,		/* accounting */
  NULL,				/* detach */
};
