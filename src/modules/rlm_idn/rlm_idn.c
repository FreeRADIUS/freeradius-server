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
 * @copyright 2013 Brian S. Julin (bjulin@clarku.edu)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>

#include <idna.h>

/*
 *      Structure for module configuration
 */
typedef struct {
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

	{ FR_CONF_OFFSET("allow_unassigned", FR_TYPE_BOOL, rlm_idn_t, allow_unassigned), .dflt = "no" },
	{ FR_CONF_OFFSET("use_std3_ascii_rules", FR_TYPE_BOOL, rlm_idn_t, use_std3_ascii_rules), .dflt = "yes" },
	CONF_PARSER_TERMINATOR
};

static int mod_xlat_instantiate(void *xlat_inst, UNUSED xlat_exp_t const *exp, void *uctx)
{
	*((void **)xlat_inst) = talloc_get_type_abort(uctx, rlm_idn_t);
	return 0;
}

static xlat_arg_parser_t const xlat_idna_arg = { .required = true, .concat = true, .type = FR_TYPE_STRING };

/** Convert domain name to ASCII punycode
 *
@verbatim
%{idn:<domain>}
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_idna(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
			       void const *xlat_inst, UNUSED void *xlat_thread_inst,
			       fr_value_box_list_t *in)
{
	rlm_idn_t const	*inst;
	void		*instance;
	char		*idna = NULL;
	int		res;
	size_t		len;
	int		flags = 0;
	fr_value_box_t	*arg = fr_dlist_head(in);
	fr_value_box_t	*vb;

	memcpy(&instance, xlat_inst, sizeof(instance));

	inst = talloc_get_type_abort(instance, rlm_idn_t);

	if (inst->use_std3_ascii_rules) {
		flags |= IDNA_USE_STD3_ASCII_RULES;
	}
	if (inst->allow_unassigned) {
		flags |= IDNA_ALLOW_UNASSIGNED;
	}

	res = idna_to_ascii_8z(arg->vb_strvalue, &idna, flags);
	if (res) {
		if (idna) {
			free (idna); /* Docs unclear, be safe. */
		}

		REDEBUG("%s", idna_strerror(res));
		return XLAT_ACTION_FAIL;
	}

	len = strlen(idna);

	/* 253 is max DNS length */
	if (len > 253) {
		/* Never provide a truncated result, as it may be queried. */
		REDEBUG("Conversion was truncated");

		free(idna);
		return XLAT_ACTION_FAIL;
	}

	vb = fr_value_box_alloc_null(ctx);
	fr_value_box_strdup(ctx, vb, NULL, idna, false);
	fr_dcursor_append(out, vb);
	free(idna);

	return XLAT_ACTION_DONE;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_idn_t	*inst = instance;
	char const	*xlat_name;
	xlat_t		*xlat;

	xlat_name = cf_section_name2(conf);
	if (!xlat_name) {
		xlat_name = cf_section_name1(conf);
	}

	inst->xlat_name = xlat_name;

	xlat = xlat_register(inst, inst->xlat_name, xlat_idna, false);
	xlat_func_mono(xlat, &xlat_idna_arg);
	xlat_async_instantiate_set(xlat, mod_xlat_instantiate, rlm_idn_t *, NULL, inst);

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
