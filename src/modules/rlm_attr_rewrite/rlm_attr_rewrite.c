/*
 * rlm_attr_rewrite.c
 *
 * Version:  $Id$
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
 * Copyright 2002  The FreeRADIUS server project
 * Copyright 2002  Kostas Kalevras <kkalev@noc.ntua.gr>
 */

#include "config.h"
#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#ifdef HAVE_REGEX_H
#	include <regex.h>
#endif

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

#define RLM_REGEX_INPACKET 0
#define RLM_REGEX_INCONFIG 1
#define RLM_REGEX_INREPLY  2
#define RLM_REGEX_INPROXY 3
#define RLM_REGEX_INPROXYREPLY 4

static const char rcsid[] = "$Id$";

typedef struct rlm_attr_rewrite_t {
	char *attribute;	/* The attribute to search for */
	int  attr_num;		/* The attribute number */
	char *search;		/* The pattern to search for */
	int search_len;		/* The length of the search pattern */
	char *searchin_str;	/* The VALUE_PAIR list to search in. Can be either packet,reply,proxy,proxy_reply or config */
	char searchin;		/* The same as above just coded as a number for speed */
	char *replace;		/* The replacement */
	int replace_len;	/* The length of the replacement string */
	int  append;		/* Switch to control append mode (1,0) */ 
	int  nocase;		/* Ignore case */
	int  new_attr;		/* Boolean. Do we create a new attribute or not? */
	int  num_matches;	/* Maximum number of matches */
	char *name;		/* The module name */
} rlm_attr_rewrite_t;


static CONF_PARSER module_config[] = {
  { "attribute", PW_TYPE_STRING_PTR, offsetof(rlm_attr_rewrite_t,attribute), NULL, NULL },
  { "searchfor", PW_TYPE_STRING_PTR, offsetof(rlm_attr_rewrite_t,search), NULL, NULL },
  { "searchin",  PW_TYPE_STRING_PTR, offsetof(rlm_attr_rewrite_t,searchin_str), NULL, "packet" },
  { "replacewith", PW_TYPE_STRING_PTR, offsetof(rlm_attr_rewrite_t,replace), NULL, NULL },
  { "append", PW_TYPE_BOOLEAN, offsetof(rlm_attr_rewrite_t,append),NULL, "no" },
  { "ignore_case", PW_TYPE_BOOLEAN, offsetof(rlm_attr_rewrite_t,nocase), NULL, "yes" },
  { "new_attribute", PW_TYPE_BOOLEAN, offsetof(rlm_attr_rewrite_t,new_attr), NULL, "no" },
  { "max_matches", PW_TYPE_INTEGER, offsetof(rlm_attr_rewrite_t,num_matches), NULL, "10" },
  { NULL, -1, 0, NULL, NULL }
};


static int attr_rewrite_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_attr_rewrite_t *data;
	DICT_ATTR *dattr;
	char *instance_name = NULL;
	
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

	/*
	 *	Discover the attribute number of the key. 
	 */
	if (data->attribute == NULL) {
		radlog(L_ERR, "rlm_attr_rewrite: 'attribute' must be set.");
		return -1;
	}
	if (data->search == NULL || data->replace == NULL) {
		radlog(L_ERR, "rlm_attr_rewrite: search/replace strings must be set.");
		return -1;
	}
	data->search_len = strlen(data->search);
	data->replace_len = strlen(data->replace);

	if (data->replace_len == 0 && data->new_attr){
		radlog(L_ERR, "rlm_attr_rewrite: replace string must not be zero length in order to create new attribute.");
		return -1;
	}

	if (data->num_matches < 1 || data->num_matches > MAX_STRING_LEN) {
		radlog(L_ERR, "rlm_attr_rewrite: Illegal range for match number.");
		return -1;
	}
	if (data->searchin_str == NULL) {
		radlog(L_ERR, "rlm_attr_rewrite: Illegal searchin directive given. Assuming packet.");
		data->searchin = RLM_REGEX_INPACKET;
	}
	else{
		if (strcmp(data->searchin_str, "packet") == 0)
			data->searchin = RLM_REGEX_INPACKET;
		else if (strcmp(data->searchin_str, "config") == 0)
			data->searchin = RLM_REGEX_INCONFIG;
		else if (strcmp(data->searchin_str, "reply") == 0)
			data->searchin = RLM_REGEX_INREPLY;
		else if (strcmp(data->searchin_str, "proxy") == 0)
			data->searchin = RLM_REGEX_INPROXY;
		else if (strcmp(data->searchin_str, "proxy_reply") == 0)
			data->searchin = RLM_REGEX_INPROXYREPLY;
		else {
			radlog(L_ERR, "rlm_attr_rewrite: Illegal searchin directive given. Assuming packet.");
			data->searchin = RLM_REGEX_INPACKET;
		}
		free((char *)data->searchin_str);
	}
	dattr = dict_attrbyname(data->attribute);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_attr_rewrite: No such attribute %s",
				data->attribute);
		return -1;
	}
	data->attr_num = dattr->attr;
	/* Add the module instance name */
	data->name = NULL;
	instance_name = cf_section_name2(conf);
	if (instance_name != NULL)
		data->name = strdup(instance_name);
	
	
	*instance = data;
	
	return 0;
}

static int do_attr_rewrite(void *instance, REQUEST *request)
{
	rlm_attr_rewrite_t *data = (rlm_attr_rewrite_t *) instance;
	int ret = RLM_MODULE_NOOP;
	VALUE_PAIR *attr_vp = NULL;
	VALUE_PAIR *tmp = NULL;
	regex_t preg;
	regmatch_t pmatch;
	int cflags = 0;
	int err = 0;
	char done_xlat = 0;
	unsigned int len = 0;
	char err_msg[MAX_STRING_LEN];
	unsigned int i = 0;
	unsigned int counter = 0;
	char new_str[MAX_STRING_LEN];
	char *ptr, *ptr2;
	char search_STR[MAX_STRING_LEN];
	char replace_STR[MAX_STRING_LEN];
	int replace_len = 0;

	if ((attr_vp = pairfind(request->config_items, PW_REWRITE_RULE)) != NULL){
		if (data->name == NULL || strcmp(data->name,attr_vp->strvalue))
			return RLM_MODULE_NOOP;
	}

	if (!data->new_attr){
		switch (data->searchin) {
			case RLM_REGEX_INPACKET:
				if (data->attr_num == PW_USER_NAME)
					attr_vp = request->username;
				else if (data->attr_num == PW_PASSWORD)
					attr_vp = request->password;
				else
					tmp = request->packet->vps;
				break;
			case RLM_REGEX_INCONFIG:
				tmp = request->config_items;
				break;
			case RLM_REGEX_INREPLY:
				tmp = request->reply->vps;
				break;
			case RLM_REGEX_INPROXY:
				tmp = request->proxy_reply->vps;
				break;
			case RLM_REGEX_INPROXYREPLY:
				tmp = request->proxy->vps;
				break;
			default:
				radlog(L_ERR, "rlm_attr_rewrite: Illegal value for searchin. Changing to packet.");
				data->searchin = RLM_REGEX_INPACKET;
				attr_vp = pairfind(request->packet->vps, data->attr_num);
				break;
		}
do_again:
		if (tmp != NULL)
			attr_vp = pairfind(tmp, data->attr_num);
		if (attr_vp == NULL) {
			DEBUG2("rlm_attr_rewrite: Could not find value pair for attribute %s",data->attribute);
			return ret;
		}
		if (attr_vp->strvalue == NULL || attr_vp->length == 0){
			DEBUG2("rlm_attr_rewrite: Attribute %s string value NULL or of zero length",data->attribute);
			return ret;
		}
		cflags |= REG_EXTENDED;
		if (data->nocase)
			cflags |= REG_ICASE;

		if (!radius_xlat(search_STR, sizeof(search_STR), data->search, request, NULL) && data->search_len != 0) {
			DEBUG2("rlm_attr_rewrite: xlat on search string failed.");
			return ret;
		}
	}
	if (data->new_attr){
		if (!radius_xlat(replace_STR, sizeof(replace_STR), data->replace, request, NULL)) {
			DEBUG2("rlm_attr_rewrite: xlat on replace string failed.");
			return ret;
		}
		replace_len = strlen(replace_STR);
	}

	if (!data->new_attr){
		if ((err = regcomp(&preg,search_STR,cflags))) {
			regerror(err, &preg, err_msg, MAX_STRING_LEN);
			DEBUG2("rlm_attr_rewrite: regcomp() returned error: %s",err_msg);
			return ret;
		}
		ptr = new_str;
		ptr2 = attr_vp->strvalue;
		counter = 0;

		for ( i = 0 ;i < (unsigned)data->num_matches; i++) {
			err = regexec(&preg, ptr2, 1, &pmatch, 0);
			if (err == REG_NOMATCH) {
				if (i == 0) {
					DEBUG2("rlm_attr_rewrite: No match found for attribute %s with value '%s'",
							data->attribute, attr_vp->strvalue);
					regfree(&preg);
					goto to_do_again;
				} else
					break;
			}
			if (err != 0) {
				regfree(&preg);
				radlog(L_ERR, "rlm_attr_rewrite: match failure for attribute %s with value '%s'",
						data->attribute, attr_vp->strvalue);
				return ret;
			}
			if (pmatch.rm_so == -1)
				break;
			len = pmatch.rm_so;
			if (data->append) {
				len = len + (pmatch.rm_eo - pmatch.rm_so);
			} 
			counter += len;
			if (counter >= MAX_STRING_LEN) {
				regfree(&preg);
				DEBUG2("rlm_attr_rewrite: Replacement out of limits for attribute %s with value '%s'",
						data->attribute, attr_vp->strvalue);	
				return ret;
			}

			strncpy(ptr, ptr2,len);
			ptr += len;
			ptr2 += pmatch.rm_eo;

			if (!done_xlat){
				if (data->replace_len != 0 &&
				radius_xlat(replace_STR, sizeof(replace_STR), data->replace, request, NULL) == 0) {
					DEBUG2("rlm_attr_rewrite: xlat on replace string failed.");
					return ret;
				}
				replace_len = (data->replace_len != 0) ? strlen(replace_STR) : 0;
				done_xlat = 1;
			}

			counter += replace_len;
			if (counter >= MAX_STRING_LEN) {
				regfree(&preg);
				DEBUG2("rlm_attr_rewrite: Replacement out of limits for attribute %s with value '%s'",
						data->attribute, attr_vp->strvalue);	
				return ret;
			}
			if (replace_len){
				strncpy(ptr, replace_STR, replace_len);
				ptr += replace_len;	
			}
		}
		regfree(&preg);
		len = strlen(ptr2) + 1;		/* We add the ending NULL */
		counter += len;
		if (counter >= MAX_STRING_LEN){
			DEBUG2("rlm_attr_rewrite: Replacement out of limits for attribute %s with value '%s'",
					data->attribute, attr_vp->strvalue);	
			return ret;
		}
		strncpy(ptr, ptr2, len);

		DEBUG2("rlm_attr_rewrite: Changed value for attribute %s from '%s' to '%s'",
				data->attribute, attr_vp->strvalue, new_str);
		attr_vp->length = strlen(new_str);
		strncpy(attr_vp->strvalue, new_str, (attr_vp->length + 1));

to_do_again:
		ret = RLM_MODULE_OK;

		if (tmp != NULL){
			tmp = attr_vp->next;
			if (tmp != NULL)
				goto do_again;
		}
	}
	else{
		attr_vp = pairmake(data->attribute,replace_STR,0);
		if (attr_vp == NULL){
			DEBUG2("rlm_attr_rewrite: Could not add new attribute %s with value '%s'",
				data->attribute,replace_STR);
			return ret;
		}
		switch(data->searchin){
			case RLM_REGEX_INPACKET:
				pairadd(&request->packet->vps,attr_vp);
				break;
			case RLM_REGEX_INCONFIG:
				pairadd(&request->config_items,attr_vp);
				break;
			case RLM_REGEX_INREPLY:
				pairadd(&request->reply->vps,attr_vp);
				break;
			default:
				radlog(L_ERR, "rlm_attr_rewrite: Illegal value for searchin. Changing to packet.");
				data->searchin = RLM_REGEX_INPACKET;
				pairadd(&request->packet->vps,attr_vp);
				break;
		}
		DEBUG2("rlm_attr_rewrite: Added attribute %s with value '%s'",data->attribute,replace_STR);
		ret = RLM_MODULE_OK;
	}
				

	return ret;
}


static int attr_rewrite_accounting(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}

static int attr_rewrite_authorize(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}
static int attr_rewrite_authenticate(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}
static int attr_rewrite_preacct(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}
static int attr_rewrite_ismul(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}

static int attr_rewrite_preproxy(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}

static int attr_rewrite_postproxy(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}

static int attr_rewrite_postauth(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}

static int attr_rewrite_detach(void *instance)
{
	rlm_attr_rewrite_t *data = (rlm_attr_rewrite_t *) instance;

	if (data->attribute)
		free(data->attribute);
	if (data->search)
		free(data->search);
	if (data->replace)	
		free(data->replace);
	if (data->name)
		free(data->name);

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
module_t rlm_attr_rewrite = {
	"attr_rewrite",	
	RLM_TYPE_THREAD_UNSAFE,		/* type */
	NULL,				/* initialization */
	attr_rewrite_instantiate,		/* instantiation */
	{
		attr_rewrite_authenticate,	/* authentication */
		attr_rewrite_authorize, 	/* authorization */
		attr_rewrite_preacct,		/* preaccounting */
		attr_rewrite_accounting,	/* accounting */
		attr_rewrite_ismul,		/* checksimul */
		attr_rewrite_preproxy,		/* pre-proxy */
		attr_rewrite_postproxy,		/* post-proxy */
		attr_rewrite_postauth		/* post-auth */
	},
	attr_rewrite_detach,			/* detach */
	NULL,				/* destroy */
};
