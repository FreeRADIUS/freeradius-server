/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file rlm_idn.c
 * @brief Dynamic DNS resolution including draft-ietf-radext-dynamic-discovery.
 *
 * @copyright 2013  Brian S. Julin <bjulin@clarku.edu>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <idna.h>

#include "idn.h"

/* The primary use case for this module is DNS-safe encoding of realms
 * appearing in requests for a DDDS scheme.  Some notes on that usage
 * scenario:
 *
 * RFC2865 5.1 User-Name may be one of:
 *
 * 1) UTF-8 text: in which case this conversion is needed
 *
 * 2) realm part of an NAI: in which case this conversion should do nothing
 *    since only ASCII digits, ASCII alphas, ASCII dots, and ASCII hyphens
 *    are allowed.
 *
 * 3)  "A name in ASN.1 form used in Public Key authentication systems.":
 *     I count four things in that phrase that are rather ... vague.
 *     However, most X.509 docs yell at you to IDNA internationalized
 *     domain names to IA5String, so if it is coming from inside an X.509
 *     certificate IDNA should be idempotent in the encode direction.
 *
 * Except for that last loophole, which we will leave up to higher layers
 * to sort out, we should be safe in processing the realm as UTF-8.
 */


/*
 *      A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER mod_config[] = {
	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

/* Provide IDNA as an xlat.  Might come in handy. */
static size_t xlat_idna(void *instance, UNUSED REQUEST *request,
	                char const *fmt, char *out, size_t freespace)
{
	rlm_idn_t *inst = instance;
	char *idna = NULL;
	int res;
	size_t len;

        if (freespace <= 1) return 0;

        res = idna_to_ascii_8z(fmt, &idna, IDNA_USE_STD3_ASCII_RULES);
	if (res) {
		if (idna) free (idna); /* Docs unclear, be safe. */
		RDEBUG("idn (%s): %s", inst->xlat_name, idna_strerror(res));
		return 0;
	}

        len = strnlen(idna, 254);  /* 253 is max DNS length */
        if (len < freespace - 1 && len <= 253) {
		strlcpy(out, idna, freespace);
		free(idna);
		return len;
	}
        else {
	        /* Never provide a truncated result, as it may be queried. */
		RDEBUG("idn (%s): No partial results allowed, need space.",
			inst->xlat_name);
		free(idna);
	}
	return 0;
}

/*
 *      Do any per-module initialization that is separate to each
 *      configured instance of the module.  e.g. set up connections
 *      to external databases, read configuration files, set up
 *      dictionary entries, etc.
 *
 *      If configuration information is given in the config section
 *      that must be referenced in later calls, store a handle to it
 *      in *instance otherwise put a null pointer there.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_idn_t *inst = instance;
	char const *xlat_name;

	xlat_name = cf_section_name2(conf);
	if (!xlat_name) {
		xlat_name = cf_section_name1(conf);
	}

	inst->xlat_name = xlat_name;

	xlat_register(inst->xlat_name, xlat_idna, NULL, inst);

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
module_t rlm_idn = {
	RLM_MODULE_INIT,
	"idn",
	RLM_TYPE_THREAD_SAFE,		/* type */
	sizeof(rlm_idn_t),
	mod_config,			/* CONF_PARSER */
	mod_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		NULL,		 	/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
#ifdef WITH_COA
		, NULL,
		NULL
#endif
	},
};
