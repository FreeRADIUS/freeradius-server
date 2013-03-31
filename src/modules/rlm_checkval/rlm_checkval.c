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
 * @file rlm_checkval.c
 * @brief Enables simple value checking.
 *
 * @copyright 2003,2006  The FreeRADIUS server project
 * @copyright 2003  Kostas Kalevras <kkalev@noc.ntua.gr>
 */
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#ifdef HAVE_REGEX_H
#	include <regex.h>
#endif
#ifndef REG_EXTENDED
#define REG_EXTENDED (0)
#endif

#ifndef REG_NOSUB
#define REG_NOSUB (0)
#endif
/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_checkval_t {
	char		*item_name;	//!< The attribute inside
					//!< Access-Request i.e.
					//!< Calling-Station-Id.
	char		*check_name;	//!< The attribute to check it with ie
					//!< Allowed-Calling-Station-Id.
	char		*data_type;	//!< String, integer, ipaddr, date,
					//!< abinary,octets.
	PW_TYPE		type;		//!< Resolved data type.

	const DICT_ATTR	*item;
	const DICT_ATTR	*check;

	int		notfound_reject;	//!< If we don't find the
						//!< item_name in the request
						//!< send back a reject.
} rlm_checkval_t;

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
	{ "item-name", PW_TYPE_STRING_PTR,
	  offsetof(rlm_checkval_t,item_name), NULL,  NULL},
	{ "check-name", PW_TYPE_STRING_PTR,
	  offsetof(rlm_checkval_t,check_name), NULL,  NULL},
	{ "data-type", PW_TYPE_STRING_PTR,
	  offsetof(rlm_checkval_t,data_type),NULL, "integer"},
	{ "notfound-reject", PW_TYPE_BOOLEAN,
	  offsetof(rlm_checkval_t,notfound_reject),NULL, "no"},
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
static int mod_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_checkval_t *inst;
	const DICT_ATTR *da;
	ATTR_FLAGS flags;

	/*
	 *	Set up a storage area for instance data
	 */
	*instance = inst = talloc_zero(conf, rlm_checkval_t);
	if (!inst) return -1;

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		return -1;
	}

	/*
	 * Check if data_type exists
	 */
	if (!inst->data_type || !*inst->data_type){
		cf_log_err_cs(conf, "Must set 'data-type'");
		return -1;
	}

	if (!inst->item_name || !*inst->item_name){
		cf_log_err_cs(conf, "Must set 'item-name'");
		return -1;
	}

	if (!inst->check_name || !*inst->check_name){
		cf_log_err_cs(conf, "Must set 'check-name'");
		return -1;
	}


	/*
	 *	Convert the string type to an integer type,
	 *	so we don't have to do string comparisons on each
	 *	packet.
	 */
	inst->type = fr_str2int(dict_attr_types, inst->data_type, 0);
	if (!inst->type) {
		cf_log_err_cs(conf, "Invalid data-type '%s'",
			      inst->data_type);
		return -1;
	}

	/*
	 *	Discover the attribute number of the item name
	 */
	da = dict_attrbyname(inst->item_name);
	if (!da) {
		cf_log_err_cs(conf, "No such attribute '%s'",
		       inst->item_name);
		return -1;
	}
	inst->item = da;

	/*
	 *	Add the check attribute name to the dictionary
	 *	if it does not already exists. dict_addattr() handles that
	 */
	memset(&flags, 0, sizeof(flags));

	dict_addattr(inst->check_name, -1, 0, PW_TYPE_STRING, flags);
	da = dict_attrbyname(inst->check_name);
	if (!da){
		radlog(L_ERR, "rlm_checkval: No such attribute %s",
		       inst->check_name);
		return -1;
	}
	inst->check = da;
	DEBUG2("rlm_checkval: Registered name %s for attribute %d",
		da->name,da->attr);

	return 0;
}

static rlm_rcode_t do_checkval(void *instance, REQUEST *request)
{
	rlm_checkval_t *inst = (rlm_checkval_t *) instance;
	rlm_rcode_t rcode = RLM_MODULE_NOOP;
	VALUE_PAIR *check, *item;
	VALUE_PAIR *tmp;
	char found = 0;

	/*
	 *      Look for the check item
	 */
	if (!(item = pairfind(request->packet->vps, inst->item->attr, inst->item->vendor, TAG_ANY))){
		DEBUG2("rlm_checkval: Could not find item named %s in request", inst->item_name);
		if (inst->notfound_reject)
			rcode = RLM_MODULE_REJECT;
		else
			rcode = RLM_MODULE_NOTFOUND;
	}
	if (item)
		DEBUG2("rlm_checkval: Item Name: %s, Value: %s",inst->item_name, item->vp_strvalue);
	tmp = request->config_items;
	do{
		if (!(check = pairfind(tmp, inst->check->attr, inst->check->vendor, TAG_ANY))){
			if (!found){
				DEBUG2("rlm_checkval: Could not find attribute named %s in check pairs",inst->check_name);
				rcode = RLM_MODULE_NOTFOUND;
			}
			break;
		}
		if (!item)
			break;
		DEBUG2("rlm_checkval: Value Name: %s, Value: %s",inst->check_name, check->vp_strvalue);

		/*
	 	* Check if item != check
		*
		*	FIXME:  !!! Call normal API functions!
	 	*/
		found = 1;
		if (inst->type == PW_TYPE_STRING ||
		    inst->type == PW_TYPE_OCTETS) {
			if (item->length != check->length)
				rcode = RLM_MODULE_REJECT;
			else{
				if (!memcmp(item->vp_strvalue,
					    check->vp_strvalue,
					    (size_t) check->length))
					rcode = RLM_MODULE_OK;
				else
					rcode = RLM_MODULE_REJECT;
			}
		} else if (inst->type == PW_TYPE_DATE) {
			if (item->vp_date == check->vp_date)
				rcode = RLM_MODULE_OK;
			else
				rcode = RLM_MODULE_REJECT;
		} else if (inst->type == PW_TYPE_INTEGER) {
			if (item->vp_integer == check->vp_integer)
				rcode = RLM_MODULE_OK;
			else
				rcode = RLM_MODULE_REJECT;
		}
#ifdef HAVE_REGEX_H
		if (rcode == RLM_MODULE_REJECT &&
		    check->op == T_OP_REG_EQ) {
			regex_t reg;
			int err;
			char err_msg[MAX_STRING_LEN];

			DEBUG("rlm_checkval: Doing regex");
			err = regcomp(&reg, (char *)check->vp_strvalue, REG_EXTENDED|REG_NOSUB);
			if (err){
				regerror(err, &reg,err_msg, MAX_STRING_LEN);
				DEBUG("rlm_checkval: regcomp() returned error: %s", err_msg);
				return RLM_MODULE_FAIL;
			}
			if (regexec(&reg, (char *)item->vp_strvalue,0, NULL, 0) == 0)
				rcode = RLM_MODULE_OK;
			else
				rcode = RLM_MODULE_REJECT;
			regfree(&reg);
		}
#endif
		tmp = check->next;
	} while (rcode == RLM_MODULE_REJECT &&
		 tmp != NULL);

	if (rcode == RLM_MODULE_REJECT) {
		if (!item && inst->notfound_reject){
			RDEBUGE("Could not find item named %s in request", inst->item_name);
		} else {
			RDEBUGE("This %s is not allowed for the user", inst->item_name);
		}
	}


	return rcode;
}

/*
 */
static rlm_rcode_t mod_authorize(void *instance, REQUEST *request)
{
	return do_checkval(instance,request);
}

static rlm_rcode_t mod_accounting(void *instance, REQUEST *request)
{
	return do_checkval(instance,request);
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
module_t rlm_checkval = {
	 RLM_MODULE_INIT,
	"checkval",
	0,				/* type */
	mod_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		NULL,			/* authentication */
		mod_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		mod_accounting,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
