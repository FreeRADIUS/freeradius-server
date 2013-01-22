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
	char	*item_name;	/* The attribute inside Access-Request ie Calling-Station-Id */
	char 	*check_name;	/* The attribute to check it with ie Allowed-Calling-Station-Id */
	char	*data_type;	/* string,integer,ipaddr,date,abinary,octets */
	int	dat_type;
	DICT_ATTR *item_attr;
	DICT_ATTR *chk_attr;
	int	notfound_reject;	/* If we don't find the item_name in the request send back a reject */
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
  { "item-name",  PW_TYPE_STRING_PTR, offsetof(rlm_checkval_t,item_name), NULL,  NULL},
  { "check-name",  PW_TYPE_STRING_PTR, offsetof(rlm_checkval_t,check_name), NULL,  NULL},
  { "data-type",    PW_TYPE_STRING_PTR, offsetof(rlm_checkval_t,data_type),NULL, "integer"},
  { "notfound-reject", PW_TYPE_BOOLEAN, offsetof(rlm_checkval_t,notfound_reject),NULL, "no"},
  { NULL, -1, 0, NULL, NULL }		/* end the list */
};


static int checkval_detach(void *instance)
{
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
static int checkval_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_checkval_t *data;
	DICT_ATTR *dattr;
	ATTR_FLAGS flags;

	static const FR_NAME_NUMBER names[] = {
		{ "string", PW_TYPE_STRING },
		{ "integer", PW_TYPE_INTEGER },
		{ "ipaddr", PW_TYPE_IPADDR },
		{ "date", PW_TYPE_DATE },
		{ "abinary", PW_TYPE_OCTETS },
		{ "octets", PW_TYPE_OCTETS },
		{ "binary", PW_TYPE_OCTETS },
		{ NULL, 0 }
	};

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
		checkval_detach(data);
		return -1;
	}

	/*
	 * Check if data_type exists
	 */
	if (!data->data_type || !*data->data_type){
		radlog(L_ERR, "rlm_checkval: Data type not defined");
		checkval_detach(data);
		return -1;
	}
	if (!data->item_name || !*data->item_name){
		radlog(L_ERR, "rlm_checkval: Item name not defined");
		checkval_detach(data);
		return -1;
	}
	if (!data->check_name || !*data->check_name){
		radlog(L_ERR, "rlm_checkval: Check item name not defined");
		checkval_detach(data);
		return -1;
	}

	/*
	 *	Discover the attribute number of the item name
	 */
	dattr = dict_attrbyname(data->item_name);
	if (!dattr) {
		radlog(L_ERR, "rlm_checkval: No such attribute %s",
		       data->item_name);
		checkval_detach(data);
		return -1;
	}
	data->item_attr = dattr;

	/*
	 *	Add the check attribute name to the dictionary
	 *	if it does not already exists. dict_addattr() handles that
	 */

	memset(&flags, 0, sizeof(flags));
	dict_addattr(data->check_name, -1, 0, PW_TYPE_STRING, flags);
	dattr = dict_attrbyname(data->check_name);
	if (!dattr){
		radlog(L_ERR, "rlm_checkval: No such attribute %s",
		       data->check_name);
		checkval_detach(data);
		return -1;
	}
	data->chk_attr = dattr;
	DEBUG2("rlm_checkval: Registered name %s for attribute %d",
		dattr->name,dattr->attr);

	/*
	 *	Convert the string type to an integer type,
	 *	so we don't have to do string comparisons on each
	 *	packet.
	 */
	data->dat_type = fr_str2int(names, data->data_type, -1);
	if (data->dat_type < 0) {
		radlog(L_ERR, "rlm_checkval: Data type %s in not known",data->data_type);
		checkval_detach(data);
		return -1;
	}

	*instance = data;

	return 0;
}

static rlm_rcode_t do_checkval(void *instance, REQUEST *request)
{
	rlm_checkval_t *data = (rlm_checkval_t *) instance;
	rlm_rcode_t rcode = RLM_MODULE_NOOP;
	VALUE_PAIR *chk_vp, *item_vp;
	VALUE_PAIR *tmp;
	char found = 0;

	/* quiet the compiler */
	instance = instance;
	request = request;


	/*
	*      Look for the check item
	*/

	if (!(item_vp = pairfind(request->packet->vps, data->item_attr->attr, data->item_attr->vendor, TAG_ANY))){
		DEBUG2("rlm_checkval: Could not find item named %s in request", data->item_name);
		if (data->notfound_reject)
			rcode = RLM_MODULE_REJECT;
		else
			rcode = RLM_MODULE_NOTFOUND;
	}
	if (item_vp)
		DEBUG2("rlm_checkval: Item Name: %s, Value: %s",data->item_name, item_vp->vp_strvalue);
	tmp = request->config_items;
	do{
		if (!(chk_vp = pairfind(tmp, data->chk_attr->attr, data->chk_attr->vendor, TAG_ANY))){
			if (!found){
				DEBUG2("rlm_checkval: Could not find attribute named %s in check pairs",data->check_name);
				rcode = RLM_MODULE_NOTFOUND;
			}
			break;
		}
		if (!item_vp)
			break;
		DEBUG2("rlm_checkval: Value Name: %s, Value: %s",data->check_name, chk_vp->vp_strvalue);

		/*
	 	* Check if item != check
		*
		*	FIXME:  !!! Call normal API functions!
	 	*/
		found = 1;
		if (data->dat_type == PW_TYPE_STRING ||
		    data->dat_type == PW_TYPE_OCTETS) {
			if (item_vp->length != chk_vp->length)
				rcode = RLM_MODULE_REJECT;
			else{
				if (!memcmp(item_vp->vp_strvalue,
					    chk_vp->vp_strvalue,
					    (size_t) chk_vp->length))
					rcode = RLM_MODULE_OK;
				else
					rcode = RLM_MODULE_REJECT;
			}
		} else if (data->dat_type == PW_TYPE_DATE) {
			if (item_vp->vp_date == chk_vp->vp_date)
				rcode = RLM_MODULE_OK;
			else
				rcode = RLM_MODULE_REJECT;
		} else if (data->dat_type == PW_TYPE_INTEGER) {
			if (item_vp->vp_integer == chk_vp->vp_integer)
				rcode = RLM_MODULE_OK;
			else
				rcode = RLM_MODULE_REJECT;
		}
#ifdef HAVE_REGEX_H
		if (rcode == RLM_MODULE_REJECT &&
		    chk_vp->op == T_OP_REG_EQ) {
			regex_t reg;
			int err;
			char err_msg[MAX_STRING_LEN];

			DEBUG("rlm_checkval: Doing regex");
			err = regcomp(&reg, (char *)chk_vp->vp_strvalue, REG_EXTENDED|REG_NOSUB);
			if (err){
				regerror(err, &reg,err_msg, MAX_STRING_LEN);
				DEBUG("rlm_checkval: regcomp() returned error: %s", err_msg);
				return RLM_MODULE_FAIL;
			}
			if (regexec(&reg, (char *)item_vp->vp_strvalue,0, NULL, 0) == 0)
				rcode = RLM_MODULE_OK;
			else
				rcode = RLM_MODULE_REJECT;
			regfree(&reg);
		}
#endif
		tmp = chk_vp->next;
	} while (rcode == RLM_MODULE_REJECT &&
		 tmp != NULL);

	if (rcode == RLM_MODULE_REJECT) {
		if (!item_vp && data->notfound_reject){
			char module_fmsg[MAX_STRING_LEN];
			VALUE_PAIR *module_fmsg_vp;

			snprintf(module_fmsg,sizeof(module_fmsg),
				"rlm_checkval: Could not find item named %s in request", data->item_name);
			module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
		}
		else{
			char module_fmsg[MAX_STRING_LEN];
			VALUE_PAIR *module_fmsg_vp;

			snprintf(module_fmsg,sizeof(module_fmsg),
				"rlm_checkval: This %s is not allowed for the user", data->item_name);
			module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
		}
	}


	return rcode;
}

/*
 */
static rlm_rcode_t checkval_authorize(void *instance, REQUEST *request)
{
	return do_checkval(instance,request);
}

static rlm_rcode_t checkval_accounting(void *instance, REQUEST *request)
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
	0,		/* type */
	checkval_instantiate,		/* instantiation */
	checkval_detach,		/* detach */
	{
		NULL,			/* authentication */
		checkval_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		checkval_accounting,	/* accounting */
		NULL,			/* checksimul */
		NULL,		        /* pre-proxy */
		NULL,		        /* post-proxy */
		NULL		        /* post-auth */
	},
};
