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
 *	a lot cleaner to do so.
 */
typedef struct example_config_t {
	int		boolean;
	int		value;
	char		*string;
	u_int32_t	ipaddr;
} example_config_t;

/*
 *	Define the local copy of our example configuration,
 *	and initialize it so some values.
 */
static example_config_t config = {
	FALSE,			/* boolean */
	1,			/* integer */
	NULL,			/* string */
	0			/* IP address */
};

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
  { "integer", PW_TYPE_INTEGER,    &config.value },
  { "boolean", PW_TYPE_BOOLEAN,    &config.boolean },
  { "string",  PW_TYPE_STRING_PTR, &config.string },
  { "ipaddr",  PW_TYPE_IPADDR,     &config.ipaddr },

  { NULL, -1, NULL}		/* end the list */
};

/*
 *	Do any per-module initialization.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 */
static int radius_init(int argc, char **argv)
{
	CONF_SECTION *example_cs;

	/*
	 *	Quiet the compiler,  This is ONLY needed if the functions
	 *	parameters are not used anywhere in the function.  If there
	 *	were code here, we wouldn't need these two "fake" code lines.
	 */
	argc = argc;
	argv = argv;
	
	/*
	 *	Look for the module's configuration.  If it doesn't
	 *	exists, exit quietly (and use the defaults).
	 */
	example_cs = cf_module_config_find("example");
	if (!example_cs) {
		return 0;
	}

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(example_cs, module_config) < 0) {
		return -1;
	}

	/*
	 *	Everything's OK, return without an error.
	 */
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
	
	return RLM_MODULE_OK;
}

/*
 *	Authenticate the user with the given password.
 */
static int radius_authenticate(REQUEST *request)
{
	/* quiet the compiler */
	request = request;
	
	return RLM_MODULE_OK;
}

/*
 *	Massage the request before recording it or proxying it
 */
static int radius_preacct(REQUEST *request)
{
	/* quiet the compiler */
	request = request;
	
	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static int radius_accounting(REQUEST *request)
{
	/* quiet the compiler */
	request = request;
	
	return RLM_MODULE_OK;
}

/* globally exported name */
module_t rlm_example = {
	"example",
	0,				/* type: reserved */
	radius_init,			/* initialization */
	radius_authorize,		/* authorization */
	radius_authenticate,		/* authentication */
	radius_preacct,			/* preaccounting */
	radius_accounting,		/* accounting */
	NULL,				/* detach */
};
