#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

static const char rcsid[] = "$Id$";

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct example_config_t {
	int		boolean;
	int		value;
	char		*string;
	uint32_t	ipaddr;
} example_config_t;

/*
 *	A temporary holding area for config values to be extracted
 *	into, before they are copied into the instance data
 */
static example_config_t config;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static CONF_PARSER module_config[] = {
  { "integer", PW_TYPE_INTEGER,    &config.value,   "1" },
  { "boolean", PW_TYPE_BOOLEAN,    &config.boolean, "no" },
  { "string",  PW_TYPE_STRING_PTR, &config.string,  NULL },
  { "ipaddr",  PW_TYPE_IPADDR,     &config.ipaddr,  "*" },

  { NULL, -1, NULL, NULL }		/* end the list */
};

/*
 *	Do any per-module initialization.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	Try to avoid putting too much stuff in here - it's better to
 *	do it in instantiate() where it is not global.
 */
static int radius_init(void)
{
	/*
	 *	Everything's OK, return without an error.
	 */
	return 0;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int radius_instantiate(CONF_SECTION *conf, void **instance)
{
  /*
   *	Set up a storage area for instance data
   */
  *instance = malloc(sizeof(struct example_config_t));
  if(!*instance) {
  	return -1;
  }

  /*
   *	If the configuration parameters can't be parsed, then
   *	fail.
   */
  if (cf_section_parse(conf, module_config) < 0) {
	  free(*instance);
	  return -1;
  }

  /*
   *	Copy the configuration into the instance data
   */
#define inst ((struct example_config_t *)*instance)
  inst->boolean = config.boolean;
  inst->value = config.value;
  inst->string = config.string;
  inst->ipaddr = config.ipaddr;
#undef inst
  config.string = 0; /* So cf_section_parse won't free it next time */

  return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int radius_authorize(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;
	
	return RLM_MODULE_HANDLED;
}

/*
 *	Authenticate the user with the given password.
 */
static int radius_authenticate(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;
	
	return RLM_MODULE_OK;
}

/*
 *	Massage the request before recording it or proxying it
 */
static int radius_preacct(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;
	
	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static int radius_accounting(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;
	
	return RLM_MODULE_OK;
}

/*
 *	See if a user is already logged in. Sets request->simul_count to the
 *	current session count for this user and sets request->simul_mpp to 2
 *	if it looks like a multilink attempt based on the requested IP
 *	address, otherwise leaves request->simul_mpp alone.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. SNMP).
 */
static int radius_checksimul(void *instance, REQUEST *request)
{
  instance = instance;

  request->simul_count=0;

  return RLM_MODULE_OK;
}

static int radius_detach(void *instance)
{
	free(((struct example_config_t *)instance)->string);
	free(instance);
	return 0;
}

/* globally exported name */
module_t rlm_example = {
	"example",
	0,				/* type: reserved */
	radius_init,			/* initialization */
	radius_instantiate,		/* instantiation */
	radius_authorize,		/* authorization */
	radius_authenticate,		/* authentication */
	radius_preacct,			/* preaccounting */
	radius_accounting,		/* accounting */
	radius_checksimul,		/* checksimul */
	radius_detach,			/* detach */
	NULL,				/* destroy */
};
