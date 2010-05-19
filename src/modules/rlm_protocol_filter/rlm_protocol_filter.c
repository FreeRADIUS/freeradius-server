/*
 * rlm_protocol_filter.c
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
 * Copyright 2004  Cladju Consulting, Inc. <aland@cladju.com>
 * Copyright 2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

/*
 *	Define a structure for our module configuration.
 *
 */
typedef struct rlm_protocol_filter_t {
	char		*filename;
	char		*key;
	CONF_SECTION	*cs;
} rlm_protocol_filter_t;

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
	{ "filename",  PW_TYPE_FILENAME,
	  offsetof(rlm_protocol_filter_t,filename), NULL,
	  "${raddbdir}/protocol_filter.conf"},

	{ "key",  PW_TYPE_STRING_PTR,
	  offsetof(rlm_protocol_filter_t,key), NULL, "%{Realm:-DEFAULT}"},

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

static int filter_detach(void *instance)
{
	rlm_protocol_filter_t *inst = instance;

	if (inst->cs) cf_section_free(&(inst->cs));

	free(instance);
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
static int filter_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_protocol_filter_t *inst;

	/*
	 *	Set up a storage area for instance data
	 */
	inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		filter_detach(inst);
		return -1;
	}

	inst->cs = cf_file_read(inst->filename);
	if (!inst->cs) {
		filter_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}


/*
 *	Return permission.
 */
static int str2sense(const char *str)
{
	if (strcasecmp(str, "permit") == 0) return 1;
	if (strcasecmp(str, "deny") == 0) return 0;

	return -1;
}

/*
 *	Apply a subsection to a request.
 *	Returns permit/deny/error.
 */
static int apply_subsection(rlm_protocol_filter_t *inst, REQUEST *request,
			    CONF_SECTION *cs, const char *name)
{
	int sense;
	CONF_PAIR *cp;
	const char *value;
	char keybuf[256];

	DEBUG2("  rlm_protocol_filter: Found subsection %s", name);

	cp = cf_pair_find(cs, "key");
	if (!cp) {
		radlog(L_ERR, "rlm_protocol_filter: %s[%d]: No key defined in subsection %s",
		       inst->filename, cf_section_lineno(cs), name);
		return RLM_MODULE_FAIL;
	}

	radius_xlat(keybuf, sizeof(keybuf),
		    cf_pair_value(cp), request, NULL);
	if (!*keybuf) {
		DEBUG2("  rlm_protocol_filter: %s[%d]: subsection %s, key is empty, doing nothing.",
		       inst->filename, cf_section_lineno(cs), name);
		return RLM_MODULE_NOOP;
	}

	DEBUG2("  rlm_protocol_filter: %s[%d]: subsection %s, using key %s",
	       inst->filename, cf_section_lineno(cs), name, keybuf);

	/*
	 *	And repeat some of the above code.
	 */
	cp = cf_pair_find(cs, keybuf);
	if (!cp) {
		CONF_SECTION *subcs;

		/*
		 *	Maybe it has a subsection, too.
		 */
		subcs = cf_section_sub_find(cs, keybuf);
		if (subcs) {
			return apply_subsection(inst, request, subcs, keybuf);
		} /* it was a subsection */



		DEBUG2("  rlm_protocol_filter: %s[%d]: subsection %s, rule not found, doing nothing.",
		       inst->filename, cf_section_lineno(cs), name);
		return RLM_MODULE_NOOP;
	}

	value = cf_pair_value(cp);
	sense = str2sense(value);
	if (sense < 0) {
		radlog(L_ERR, "rlm_protocol_filter: %s[%d]: Unknwn directive %s",
		       inst->filename, cf_pair_lineno(cp), value);
		return RLM_MODULE_FAIL;
	}

	if (!sense) return RLM_MODULE_REJECT;

	return RLM_MODULE_OK;
}


/*
 *	Authorize the user.
 */
static int filter_authorize(void *instance, REQUEST *request)
{
	int sense;
	VALUE_PAIR *vp;
	CONF_SECTION *cs;
	CONF_PAIR *cp;
	char keybuf[1024];
	rlm_protocol_filter_t *inst = instance;

	radius_xlat(keybuf, sizeof(keybuf), inst->key, request, NULL);
	if (!*keybuf) {
		DEBUG2("  rlm_protocol_filter: key is empty");
		return RLM_MODULE_NOOP;
	}
	DEBUG2("  rlm_protocol_filter: Using key %s", keybuf);

	cs = cf_section_sub_find(inst->cs, keybuf);
	if (!cs) {
		DEBUG2("  rlm_protocol_filter: No such key in %s", inst->filename);
		return RLM_MODULE_NOTFOUND;
	}

	/*
	 *	Walk through the list of attributes, seeing if they're
	 *	permitted/denied.
	 */
	for (vp = request->packet->vps; vp != NULL; vp = vp->next) {
		const char *value;
		CONF_SECTION *subcs;

		cp = cf_pair_find(cs, vp->name);
		if (cp) {
			value = cf_pair_value(cp);

			sense = str2sense(value);
			if (sense < 0) {
				radlog(L_ERR, "rlm_protocol_filter %s[%d]: Unknown directive %s",
				       inst->filename,
				       cf_pair_lineno(cp),
				       value);
				return RLM_MODULE_FAIL;
			}

			if (!sense) return RLM_MODULE_REJECT;
			continue; /* was permitted */
		} /* else no pair was found */

		/*
		 *	Maybe it has a subsection
		 */
		subcs = cf_section_sub_find(cs, vp->name);
		if (subcs) {
			sense = apply_subsection(inst, request, subcs, vp->name);
			if ((sense == RLM_MODULE_OK) ||
			    (sense == RLM_MODULE_NOOP)) {
				continue;
			}

			return sense;
		} /* it was a subsection */

		/*
		 *	Not found, must be "permit"
		 */
	}

	return RLM_MODULE_OK;
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
module_t rlm_protocol_filter = {
	RLM_MODULE_INIT,
	"protocol_filter",
	RLM_TYPE_THREAD_SAFE,		/* type */
	filter_instantiate,		/* instantiation */
	filter_detach,			/* detach */
	{
		NULL,			/* authentication */
		filter_authorize,	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
