/*
 * rlm_checkval.c
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2003  The FreeRADIUS server project
 * Copyright 2003  Kostas Kalevras <kkalev@noc.ntua.gr>
 */

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"
#ifdef HAVE_REGEX_H
#	include <regex.h>
#endif
#ifndef REG_EXTENDED 
#define REG_EXTENDED (0)
#endif

#define RLM_CHECKVAL_STR	0
#define RLM_CHECKVAL_INT	1
#define RLM_CHECKVAL_IPADDR	2
#define RLM_CHECKVAL_DATE	3
#define RLM_CHECKVAL_BIN	4

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
	char	dat_type;
	int	item_attr;
	int	chk_attr;
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
static CONF_PARSER module_config[] = {
  { "item-name",  PW_TYPE_STRING_PTR, offsetof(rlm_checkval_t,item_name), NULL,  NULL},
  { "check-name",  PW_TYPE_STRING_PTR, offsetof(rlm_checkval_t,check_name), NULL,  NULL},
  { "data-type",    PW_TYPE_STRING_PTR, offsetof(rlm_checkval_t,data_type),NULL, "integer"},
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
static int checkval_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_checkval_t *data;
	DICT_ATTR *dattr;
	ATTR_FLAGS flags;
	
	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}

	/*
	 * Check if data_type exists
	 */
	if (!data->data_type || !strlen(data->data_type)){
		radlog(L_ERR, "rlm_checkval: Data type not defined");
		free(data->item_name);
		free(data->check_name);
		free(data);
		return -1;
	}
	if (!data->item_name || !strlen(data->item_name)){
		radlog(L_ERR, "rlm_checkval: Item name not defined");
		free(data->data_type);
		free(data->check_name);
		free(data);
		return -1;
	}
	if (!data->check_name || !strlen(data->check_name)){
		radlog(L_ERR, "rlm_checkval: Check item name not defined");
		free(data->data_type);
		free(data->item_name);
		free(data);
		return -1;
	}

	/*
	 *	Discover the attribute number of the item name
	 */
	dattr = dict_attrbyname(data->item_name);
	if (!dattr) {
		radlog(L_ERR, "rlm_checkval: No such attribute %s",
		       data->item_name);
		free(data);
		return -1;
	}
	data->item_attr = dattr->attr;
	
	/*
	 *	Add the check attribute name to the dictionary
	 *	if it does not already exists. dict_addattr() handles that
	 */

	memset(&flags, 0, sizeof(flags));
	dict_addattr(data->check_name, 0, PW_TYPE_STRING, -1,flags);
	dattr = dict_attrbyname(data->check_name);
	if (!dattr){
		radlog(L_ERR, "rlm_checkval: No such attribute %s",
		       data->check_name);
		free(data);
		return -1;
	}
	data->chk_attr = dattr->attr;
	DEBUG2("rlm_checkval: Registered name %s for attribute %d",
		dattr->name,dattr->attr);

	if (!strcmp(data->data_type,"integer") || !strcmp(data->data_type,"int"))
		data->dat_type = RLM_CHECKVAL_INT;
	else if (!strcmp(data->data_type,"string") || !strcmp(data->data_type,"str"))
		data->dat_type = RLM_CHECKVAL_STR;
	else if (!strcmp(data->data_type,"ipaddr") || !strcmp(data->data_type,"ip"))
		data->dat_type = RLM_CHECKVAL_IPADDR;
	else if (!strcmp(data->data_type,"octets") || !strcmp(data->data_type,"abinary") || \
		!strcmp(data->data_type,"bin"))
		data->dat_type = RLM_CHECKVAL_BIN;
	else{
		radlog(L_ERR, "rlm_checkval: Data type %s in not known",data->data_type);
		free(data);
		return -1;
	}


	*instance = data;
	
	return 0;
}

/*
 */
static int checkval_authorize(void *instance, REQUEST *request)
{
	rlm_checkval_t *data = (rlm_checkval_t *) instance;
	int ret=RLM_MODULE_NOOP;
	VALUE_PAIR *chk_vp, *item_vp;
	VALUE_PAIR *tmp;
	char found = 0;

	/* quiet the compiler */
	instance = instance;
	request = request;


	/*
	*      Look for the check item
	*/
	
	if (!(item_vp = pairfind(request->packet->vps, data->item_attr))){
		DEBUG2("rlm_checkval: Could not find item named %s in request", data->item_name);
		return ret;
	}
	DEBUG2("rlm_checkval: Item Name: %s, Value: %s",data->item_name, item_vp->strvalue);
	tmp = request->config_items;
	do{
		if (!(chk_vp = pairfind(tmp, data->chk_attr))){
			if (!found)
				DEBUG2("rlm_checkval: Could not find attribute named %s in check pairs",data->check_name);
			break;
		}
		DEBUG2("rlm_checkval: Value Name: %s, Value: %s",data->check_name, chk_vp->strvalue);

		/*
	 	* Check if item != check
	 	*/
		found = 1;
		if (data->dat_type == RLM_CHECKVAL_STR || data->dat_type == RLM_CHECKVAL_BIN || \
			data->dat_type == RLM_CHECKVAL_IPADDR){
			if (item_vp->length != chk_vp->length)
				ret = RLM_MODULE_REJECT;
			else{
				if (!memcmp(item_vp->strvalue, chk_vp->strvalue, \
					(size_t) chk_vp->length))
					ret = RLM_MODULE_OK;
				else
					ret = RLM_MODULE_REJECT;
			}
		}
		else{	/* Integer or Date */
	
			if (item_vp->lvalue == chk_vp->lvalue)
				ret = RLM_MODULE_OK;
			else
				ret = RLM_MODULE_REJECT;
		}
#ifdef HAVE_REGEX_H
		if (ret == RLM_MODULE_REJECT && chk_vp->operator == T_OP_REG_EQ){
			regex_t reg;
			int err;
			char err_msg[MAX_STRING_LEN];

			DEBUG("rlm_checkval: Doing regex");
			err = regcomp(&reg, (char *)chk_vp->strvalue, REG_EXTENDED);
			if (err){
				regerror(err, &reg,err_msg, MAX_STRING_LEN);
				DEBUG("rlm_checkval: regcomp() returned error: %s", err_msg);
				return RLM_MODULE_FAIL;
			} 
			if (regexec(&reg, (char *)item_vp->strvalue,0, NULL, 0) == 0)
				ret = RLM_MODULE_OK;
			else
				ret = RLM_MODULE_REJECT;
		}
#endif
		tmp = chk_vp->next;
	}while(ret == RLM_MODULE_REJECT && tmp != NULL);

	if (ret == RLM_MODULE_REJECT){
		char module_fmsg[MAX_STRING_LEN];
		VALUE_PAIR *module_fmsg_vp;

		snprintf(module_fmsg,sizeof(module_fmsg), "rlm_checkval: This %s is not allowed for the user", data->item_name);
		module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
		pairadd(&request->packet->vps, module_fmsg_vp);
	}


	return ret;
}

static int checkval_detach(void *instance)
{
	rlm_checkval_t *data = (rlm_checkval_t *) instance;

	if (data->item_name)
		free((char *)data->item_name);
	if (data->check_name)
		free((char *)data->check_name);
	if (data->data_type)
		free((char *)data->data_type);

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
module_t rlm_checkval = {
	"checkval",	
	0,		/* type */
	NULL,				/* initialization */
	checkval_instantiate,		/* instantiation */
	{
		NULL,			/* authentication */
		checkval_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,		        /* pre-proxy */
		NULL,		        /* post-proxy */
		NULL		        /* post-auth */
	},
	checkval_detach,		/* detach */
	NULL,				/* destroy */
};
