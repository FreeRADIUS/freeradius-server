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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2002,2006  The FreeRADIUS server project
 * Copyright 2002  Kostas Kalevras <kkalev@noc.ntua.gr>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#ifdef HAVE_REGEX_H
#	include <regex.h>
#endif

#define RLM_REGEX_INPACKET 0
#define RLM_REGEX_INCONFIG 1
#define RLM_REGEX_INREPLY  2
#define RLM_REGEX_INPROXY 3
#define RLM_REGEX_INPROXYREPLY 4

typedef struct rlm_attr_rewrite_t {
	char *attribute;	/* The attribute to search for */
	DICT_ATTR *da;		/* The attribute definition */
	char *search;		/* The pattern to search for */
	int search_len;		/* The length of the search pattern */
	char *searchin_str;	/* The VALUE_PAIR list to search in. Can be either packet,reply,proxy,proxy_reply or control (plus it's alias 'config') */
	char searchin;		/* The same as above just coded as a number for speed */
	char *replace;		/* The replacement */
	int replace_len;	/* The length of the replacement string */
	int  append;		/* Switch to control append mode (1,0) */
	int  nocase;		/* Ignore case */
	int  new_attr;		/* Boolean. Do we create a new attribute or not? */
	int  num_matches;	/* Maximum number of matches */
	const char *name;	/* The module name */
} rlm_attr_rewrite_t;

static const CONF_PARSER module_config[] = {
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
		else if (strcmp(data->searchin_str, "control") == 0)
			data->searchin = RLM_REGEX_INCONFIG;
		else if (strcmp(data->searchin_str, "reply") == 0)
			data->searchin = RLM_REGEX_INREPLY;
#ifdef WITH_PROXY
		else if (strcmp(data->searchin_str, "proxy") == 0)
			data->searchin = RLM_REGEX_INPROXY;
		else if (strcmp(data->searchin_str, "proxy_reply") == 0)
			data->searchin = RLM_REGEX_INPROXYREPLY;
#endif
		else {
			radlog(L_ERR, "rlm_attr_rewrite: Illegal searchin directive given. Assuming packet.");
			data->searchin = RLM_REGEX_INPACKET;
		}
	}
	dattr = dict_attrbyname(data->attribute);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_attr_rewrite: No such attribute %s",
				data->attribute);
		return -1;
	}
	data->da = dattr;
	/* Add the module instance name */
	data->name = cf_section_name2(conf); /* may be NULL */

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
	regmatch_t pmatch[9];
	int cflags = 0;
	int err = 0;
	char done_xlat = 0;
	unsigned int len = 0;
	char err_msg[MAX_STRING_LEN];
	unsigned int i = 0;
	unsigned int j = 0;
	unsigned int counter = 0;
	char new_str[MAX_STRING_LEN];
	char *ptr, *ptr2;
	char search_STR[MAX_STRING_LEN];
	char replace_STR[MAX_STRING_LEN];

	if ((attr_vp = pairfind(request->config_items, PW_REWRITE_RULE, 0)) != NULL){
		if (data->name == NULL || strcmp(data->name,attr_vp->vp_strvalue))
			return RLM_MODULE_NOOP;
	}

	if (data->new_attr){
		/* new_attribute = yes */
		if (!radius_xlat(replace_STR, sizeof(replace_STR), data->replace, request, NULL)) {
			DEBUG2("%s: xlat on replace string failed.", data->name);
			return ret;
		}
		attr_vp = pairmake(data->attribute,replace_STR,0);
		if (attr_vp == NULL){
			DEBUG2("%s: Could not add new attribute %s with value '%s'", data->name,
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
#ifdef WITH_PROXY
			case RLM_REGEX_INPROXY:
				if (!request->proxy) {
					pairbasicfree(attr_vp);
					return RLM_MODULE_NOOP;
				}
				pairadd(&request->proxy->vps, attr_vp);
				break;
			case RLM_REGEX_INPROXYREPLY:
				if (!request->proxy_reply) {
					pairbasicfree(attr_vp);
					return RLM_MODULE_NOOP;
				}
				pairadd(&request->proxy_reply->vps, attr_vp);
				break;
#endif
			default:
				radlog(L_ERR, "%s: Illegal value for searchin. Changing to packet.", data->name);
				data->searchin = RLM_REGEX_INPACKET;
				pairadd(&request->packet->vps,attr_vp);
				break;
		}
		DEBUG2("%s: Added attribute %s with value '%s'", data->name,data->attribute,replace_STR);
		ret = RLM_MODULE_OK;
	} else {
		int replace_len = 0;

		/* new_attribute = no */
		switch (data->searchin) {
			case RLM_REGEX_INPACKET:
				if (!data->da->vendor && (data->da->attr == PW_USER_NAME))
					attr_vp = request->username;
				else if (!data->da->vendor && (data->da->attr == PW_USER_PASSWORD))
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
#ifdef WITH_PROXY
			case RLM_REGEX_INPROXYREPLY:
				if (!request->proxy_reply)
					return RLM_MODULE_NOOP;
				tmp = request->proxy_reply->vps;
				break;
			case RLM_REGEX_INPROXY:
				if (!request->proxy)
					return RLM_MODULE_NOOP;
				tmp = request->proxy->vps;
				break;
#endif
			default:
				radlog(L_ERR, "%s: Illegal value for searchin. Changing to packet.", data->name);
				data->searchin = RLM_REGEX_INPACKET;
				attr_vp = pairfind(request->packet->vps, data->da->attr, data->da->vendor);
				break;
		}
do_again:
		if (tmp != NULL)
			attr_vp = pairfind(tmp, data->da->attr, data->da->vendor);
		if (attr_vp == NULL) {
			DEBUG2("%s: Could not find value pair for attribute %s", data->name,data->attribute);
			return ret;
		}
		if (attr_vp->vp_strvalue == NULL || attr_vp->length == 0){
			DEBUG2("%s: Attribute %s string value NULL or of zero length", data->name,data->attribute);
			return ret;
		}
		cflags |= REG_EXTENDED;
		if (data->nocase)
			cflags |= REG_ICASE;

		if (!radius_xlat(search_STR, sizeof(search_STR), data->search, request, NULL) && data->search_len != 0) {
			DEBUG2("%s: xlat on search string failed.", data->name);
			return ret;
		}

		if ((err = regcomp(&preg,search_STR,cflags))) {
			regerror(err, &preg, err_msg, MAX_STRING_LEN);
			DEBUG2("%s: regcomp() returned error: %s", data->name,err_msg);
			return ret;
		}

		if ((attr_vp->type == PW_TYPE_IPADDR) &&
		    (attr_vp->vp_strvalue[0] == '\0')) {
			inet_ntop(AF_INET, &(attr_vp->vp_ipaddr),
				  attr_vp->vp_strvalue,
				  sizeof(attr_vp->vp_strvalue));
		}

		ptr = new_str;
		ptr2 = attr_vp->vp_strvalue;
		counter = 0;

		for ( i = 0 ;i < (unsigned)data->num_matches; i++) {
			err = regexec(&preg, ptr2, REQUEST_MAX_REGEX, pmatch, 0);
			if (err == REG_NOMATCH) {
				if (i == 0) {
					DEBUG2("%s: Does not match: %s = %s", data->name,
							data->attribute, attr_vp->vp_strvalue);
					regfree(&preg);
					goto to_do_again;
				} else
					break;
			}
			if (err != 0) {
				regfree(&preg);
				radlog(L_ERR, "%s: match failure for attribute %s with value '%s'", data->name,
						data->attribute, attr_vp->vp_strvalue);
				return ret;
			}
			if (pmatch[0].rm_so == -1)
				break;
			len = pmatch[0].rm_so;
			if (data->append) {
				len = len + (pmatch[0].rm_eo - pmatch[0].rm_so);
			}
			counter += len;
			if (counter >= MAX_STRING_LEN) {
				regfree(&preg);
				DEBUG2("%s: Replacement out of limits for attribute %s with value '%s'", data->name,
						data->attribute, attr_vp->vp_strvalue);
				return ret;
			}

			memcpy(ptr, ptr2,len);
			ptr += len;
			*ptr = '\0';
			ptr2 += pmatch[0].rm_eo;

			if (i == 0){
				/*
				 * We only run on the first match, sorry
				 */
				for(j = 0; j <= REQUEST_MAX_REGEX; j++){
					char *p;
					char buffer[sizeof(attr_vp->vp_strvalue)];

					/*
				   	 * Stolen from src/main/valuepair.c, paircompare()
				 	 */

					/*
					 * Delete old matches if the corresponding match does not
					 * exist in the current regex
					 */
					if (pmatch[j].rm_so == -1){
						p = request_data_get(request,request,REQUEST_DATA_REGEX | j);
						if (p){
							free(p);
							continue;
						}
						break;
					}
					memcpy(buffer,
					       attr_vp->vp_strvalue + pmatch[j].rm_so,
					       pmatch[j].rm_eo - pmatch[j].rm_so);
					buffer[pmatch[j].rm_eo - pmatch[j].rm_so] = '\0';
					p = strdup(buffer);
					request_data_add(request,request,REQUEST_DATA_REGEX | j,p,free);
				}
			}

			if (!done_xlat){
				if (data->replace_len != 0 &&
				radius_xlat(replace_STR, sizeof(replace_STR), data->replace, request, NULL) == 0) {
					DEBUG2("%s: xlat on replace string failed.", data->name);
					return ret;
				}
				replace_len = (data->replace_len != 0) ? strlen(replace_STR) : 0;
				done_xlat = 1;
			}

			counter += replace_len;
			if (counter >= MAX_STRING_LEN) {
				regfree(&preg);
				DEBUG2("%s: Replacement out of limits for attribute %s with value '%s'", data->name,
						data->attribute, attr_vp->vp_strvalue);
				return ret;
			}
			if (replace_len){
				memcpy(ptr, replace_STR, replace_len);
				ptr += replace_len;
				*ptr = '\0';
			}
		}
		regfree(&preg);
		len = strlen(ptr2) + 1;		/* We add the ending NULL */
		counter += len;
		if (counter >= MAX_STRING_LEN){
			DEBUG2("%s: Replacement out of limits for attribute %s with value '%s'", data->name,
					data->attribute, attr_vp->vp_strvalue);
			return ret;
		}
		memcpy(ptr, ptr2, len);
		ptr[len] = '\0';

		DEBUG2("%s: Changed value for attribute %s from '%s' to '%s'", data->name,
				data->attribute, attr_vp->vp_strvalue, new_str);
		if (pairparsevalue(attr_vp, new_str) == NULL) {
			DEBUG2("%s: Could not write value '%s' into attribute %s: %s", data->name, new_str, data->attribute, fr_strerror());
			return ret;
		}

to_do_again:
		ret = RLM_MODULE_OK;

		if (tmp != NULL){
			tmp = attr_vp->next;
			if (tmp != NULL)
				goto do_again;
		}
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

static int attr_rewrite_checksimul(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}

#ifdef WITH_PROXY
static int attr_rewrite_preproxy(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}

static int attr_rewrite_postproxy(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}
#endif

static int attr_rewrite_postauth(void *instance, REQUEST *request)
{
	return do_attr_rewrite(instance, request);
}

static int attr_rewrite_detach(void *instance)
{
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
	RLM_MODULE_INIT,
	"attr_rewrite",
	RLM_TYPE_THREAD_UNSAFE,		/* type */
	attr_rewrite_instantiate,		/* instantiation */
	attr_rewrite_detach,			/* detach */
	{
		attr_rewrite_authenticate,	/* authentication */
		attr_rewrite_authorize, 	/* authorization */
		attr_rewrite_preacct,		/* preaccounting */
		attr_rewrite_accounting,	/* accounting */
		attr_rewrite_checksimul,	/* checksimul */
#ifdef WITH_PROXY
		attr_rewrite_preproxy,		/* pre-proxy */
		attr_rewrite_postproxy,		/* post-proxy */
#else
		NULL, NULL,
#endif
		attr_rewrite_postauth		/* post-auth */
	},
};
