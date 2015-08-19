/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @brief Internationalized Domain Name encoding for DNS aka IDNA aka RFC3490
 *
 * @copyright 2013  Brian S. Julin <bjulin@clarku.edu>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <idna.h>

/*
 *      Structure for module configuration
 */
typedef struct rlm_idn_t {
	char const	*xlat_name;
	bool		use_std3_ascii_rules;
	bool		allow_unassigned;
} rlm_idn_t;

/*
 *	The primary use case for this module is DNS-safe encoding of realms
 *	appearing in requests for a DDDS scheme.  Some notes on that usage
 *	scenario:
 *
 *	RFC2865 5.1 User-Name may be one of:
 *
 *	1) UTF-8 text: in which case this conversion is needed
 *
 *	2) realm part of an NAI: in which case this conversion should do nothing
 *	   since only ASCII digits, ASCII alphas, ASCII dots, and ASCII hyphens
 *	   are allowed.
 *
 *	3) "A name in ASN.1 form used in Public Key authentication systems.":
 *	   I count four things in that phrase that are rather ... vague.
 *	   However, most X.509 docs yell at you to IDNA internationalized
 *	   domain names to IA5String, so if it is coming from inside an X.509
 *	   certificate IDNA should be idempotent in the encode direction.
 *
 *	   Except for that last loophole, which we will leave up to the user
 *	   to sort out, we should be safe in processing the realm as UTF-8.
 */


/*
 *      A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER mod_config[] = {
	/*
	 *	If a STRINGPREP profile other than NAMEPREP is ever desired,
	 *	we can implement an option, and it will default to NAMEPREP settings.
	 *	...and if we want raw punycode or to tweak Bootstring parameters,
	 *	we can do similar things.  All defaults should result in IDNA
	 *	ToASCII with the use_std3_ascii_rules flag set, allow_unassigned unset,
	 *	because that is the forseeable use case.
	 *
	 *	Note that doing anything much different will require choosing the
	 *	appropriate libidn API functions, as we currently call the IDNA
	 *	convenience functions.
	 *
	 *	Also note that right now we do not provide ToUnicode, which may or
	 *	may not be useful as an xlat... depends on how the results need to
	 *	be used.
	 */

	{ "allow_unassigned", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_idn_t, allow_unassigned), "no" },
	{ "use_std3_ascii_rules", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_idn_t, use_std3_ascii_rules), "yes" },
	CONF_PARSER_TERMINATOR
};

static ssize_t xlat_idna(void *instance, REQUEST *request, char const *fmt, char *out, size_t freespace)
{
	rlm_idn_t *inst = instance;
	char *idna = NULL;
	int res;
	size_t len;
	int flags = 0;

	if (inst->use_std3_ascii_rules) {
		flags |= IDNA_USE_STD3_ASCII_RULES;
	}
	if (inst->allow_unassigned) {
		flags |= IDNA_ALLOW_UNASSIGNED;
	}

	res = idna_to_ascii_8z(fmt, &idna, flags);
	if (res) {
		if (idna) {
			free (idna); /* Docs unclear, be safe. */
		}

		REDEBUG("%s", idna_strerror(res));
		return -1;
	}

	len = strlen(idna);

	/* 253 is max DNS length */
	if (!((len < (freespace - 1)) && (len <= 253))) {
		/* Never provide a truncated result, as it may be queried. */
		REDEBUG("Conversion was truncated");

		free(idna);
		return -1;

	}

	strlcpy(out, idna, freespace);
	free(idna);

	return len;
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
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

extern module_t rlm_idn;
module_t rlm_idn = {
	.magic		= RLM_MODULE_INIT,
	.name		= "idn",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_idn_t),
	.config		= mod_config,
	.bootstrap	= mod_bootstrap
};
