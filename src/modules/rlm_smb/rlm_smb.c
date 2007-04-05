/*
 * rlm_smb.c
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2002,2006  The FreeRADIUS server project
 * Copyright 2002  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "valid.h"

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_smb_t {
	char		*server;
	char		*backup;
	char		*domain;
} rlm_smb_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
  { "server",  PW_TYPE_STRING_PTR, offsetof(rlm_smb_t,server), NULL,  NULL},
  { "backup",  PW_TYPE_STRING_PTR, offsetof(rlm_smb_t,backup), NULL,  NULL},
  { "domain",  PW_TYPE_STRING_PTR, offsetof(rlm_smb_t,domain), NULL,  NULL},

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

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
static int smb_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_smb_t *data;

	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));
	if (!data) {
		return -1;
	}
	memset(data, 0, sizeof(*data));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}

	*instance = data;

	return 0;
}

/*
 *	Authenticate the user with the given password.
 */
static int smb_authenticate(void *instance, REQUEST *request)
{
	rlm_smb_t *data = (rlm_smb_t *) instance;
	int rcode;

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!request->username) {
		radlog(L_AUTH, "rlm_smb: Attribute \"User-Name\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Password attribute.
	 */
	if (!request->password) {
		radlog(L_AUTH, "rlm_smb: Attribute \"User-Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *  Ensure that we're being passed a plain-text password,
	 *  and not anything else.
	 */
	if (request->password->attribute != PW_USER_PASSWORD) {
		radlog(L_AUTH, "rlm_smb: Attribute \"User-Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}

	/*
	 *  Call the SMB magic to do the work.
	 */
	rcode = Valid_User(request->username->vp_strvalue,
			   request->password->vp_strvalue,
			   data->server, data->backup, data->domain);

	switch (rcode) {
	case 0:			/* success */
	  return RLM_MODULE_OK;
	  break;

	case 1:			/* network failure */
	case 2:			/* protocol failure */
	  return RLM_MODULE_FAIL;
	  break;

	case 3:			/* invalid user name or password */
	  return RLM_MODULE_REJECT;
	}

	/*
	 *  Something weird happened.  Give up.
	 */
	return RLM_MODULE_INVALID;
}

static int smb_detach(void *instance)
{
	rlm_smb_t *data = (rlm_smb_t *) instance;


	free(instance);
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_smb = {
	RLM_MODULE_INIT,
	"SMB",
	RLM_TYPE_THREAD_UNSAFE,		/* type */
	smb_instantiate,		/* instantiation */
	smb_detach,			/* detach */
	{
		smb_authenticate,	/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
