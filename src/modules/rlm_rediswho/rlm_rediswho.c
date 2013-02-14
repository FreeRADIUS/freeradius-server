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
 * @file rlm_rediswho.c
 * @brief Session tracking using redis.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2011  TekSavvy Solutions <gabe@teksavvy.com>
 */
#include <freeradius-devel/ident.h>

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <ctype.h>

#include <rlm_redis.h>

typedef struct rlm_rediswho_t {
	const char *xlat_name;
	CONF_SECTION *cs;

	char *redis_instance_name;
	REDIS_INST *redis_inst;

	/*
	 * 	expiry time in seconds if no updates are received for a user
	 */
	int expiry_time; 

	/*
	 *	How many session updates to keep track of per user
	 */
	int trim_count;             
} rlm_rediswho_t;

static CONF_PARSER module_config[] = {
	{ "redis-instance-name", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rediswho_t, redis_instance_name), NULL, "redis"},
	{ "trim-count", PW_TYPE_INTEGER,
	  offsetof(rlm_rediswho_t, trim_count), NULL, "-1"},
	{ NULL, -1, 0, NULL, NULL}
};

/*
 *	Query the database executing a command with no result rows
 */
static int rediswho_command(const char *fmt, REDISSOCK **dissocket_p,
			    rlm_rediswho_t *inst, REQUEST *request)
{
	REDISSOCK *dissocket;
	char query[MAX_STRING_LEN * 4];
	int result = 0;

	/*
	 *	Do an xlat on the provided string
	 */
	if (request) {
		if (!radius_xlat(query, sizeof (query), fmt, request,
				 inst->redis_inst->redis_escape_func,
				 inst->redis_inst)) {
			radlog(L_ERR, "rediswho_command: xlat failed on: '%s'", query);
			return 0;
		}

	} else {
		strcpy(query, fmt);
	}

	if (inst->redis_inst->redis_query(dissocket_p, inst->redis_inst, query) < 0) {

		radlog(L_ERR, "rediswho_command: database query error in: '%s'", query);
		return -1;

	}
	dissocket = *dissocket_p;

	switch (dissocket->reply->type) {
	case REDIS_REPLY_INTEGER:
		DEBUG("rediswho_command: query response %lld\n",
		      dissocket->reply->integer);
		if (dissocket->reply->integer > 0)
			result = dissocket->reply->integer;
		break;
	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_STRING:
		DEBUG("rediswho_command: query response %s\n",
		      dissocket->reply->str);
		break;
	default:
		break;
	}

	(inst->redis_inst->redis_finish_query)(dissocket);

	return result;
}

static int rediswho_detach(void *instance)
{
	rlm_rediswho_t *inst;

	inst = instance;
	free(inst);

	return 0;
}

static int rediswho_instantiate(CONF_SECTION * conf, void ** instance)
{
	module_instance_t *modinst;
	rlm_rediswho_t *inst;

	/*
	 *	Set up a storage area for instance data
	 */
	inst = *instance = rad_malloc(sizeof (*inst));
	memset(inst, 0, sizeof (*inst));
    
	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	inst->xlat_name = cf_section_name2(conf);

	if (!inst->xlat_name) 
		inst->xlat_name = cf_section_name1(conf);

	inst->xlat_name = strdup(inst->xlat_name);
	inst->cs = conf;

	modinst = find_module_instance(cf_section_find("modules"),
				       inst->redis_instance_name, 1);
	if (!modinst) {
		radlog(L_ERR,
		       "rediswho: failed to find module instance \"%s\"",
		       inst->redis_instance_name);

		rediswho_detach(inst);
		return -1;
	}

	if (strcmp(modinst->entry->name, "rlm_redis") != 0) {
		radlog(L_ERR, "rediswho: Module \"%s\""
		       " is not an instance of the redis module",
		       inst->redis_instance_name);

		rediswho_detach(inst);
		return -1;
	}

	inst->redis_inst = (REDIS_INST *) modinst->insthandle;

	return 0;
}

static int rediswho_accounting_all(REDISSOCK **dissocket_p,
				   rlm_rediswho_t *inst, REQUEST *request,
				   const char *insert,
				   const char *trim,
				   const char *expire)
{
	REDISSOCK *dissocket;
	int result;

	if (!insert || !trim || !expire) return 0;

	result = rediswho_command(insert, dissocket_p, inst, request);
	if (result < 0) {
		return -1;
	}

	/* Only trim if necessary */
	if (inst->trim_count >= 0 && result > inst->trim_count) {
		if (rediswho_command(trim, dissocket_p,
				     inst, request) < 0) {
			return -1;
		}
	}

	rediswho_command(expire, dissocket_p, inst, request);

	return RLM_MODULE_OK;
}

static rlm_rcode_t rediswho_accounting(void * instance, REQUEST * request)
{
	rlm_rcode_t rcode;
	VALUE_PAIR * vp;
	DICT_VALUE *dv;
	CONF_SECTION *cs;
	const char *insert, *trim, *expire;
	rlm_rediswho_t *inst = (rlm_rediswho_t *) instance;
	REDISSOCK *dissocket;

	vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY);
	if (!vp) {
		RDEBUG("Could not find account status type in packet.");
		return RLM_MODULE_NOOP;
	}

	dv = dict_valbyattr(vp->attribute, vp->vendor, vp->vp_integer);
	if (!dv) {
		RDEBUG("Unknown Acct-Status-Type %u", vp->vp_integer);
		return RLM_MODULE_NOOP;
	}

	cs = cf_section_sub_find(inst->cs, dv->name);
	if (!cs) {
		RDEBUG("No subsection %s", dv->name);
		return RLM_MODULE_NOOP;
	}

	dissocket = fr_connection_get(inst->redis_inst->pool);
	if (!dissocket) {
		RDEBUG("cannot allocate redis connection");
		return RLM_MODULE_FAIL;
	}

	insert = cf_pair_value(cf_pair_find(cs, "insert"));
	trim = cf_pair_value(cf_pair_find(cs, "trim"));
	expire = cf_pair_value(cf_pair_find(cs, "expire"));

	rcode = rediswho_accounting_all(&dissocket, inst, request,
					insert,
					trim,
					expire);

	if (dissocket) fr_connection_release(inst->redis_inst->pool, dissocket);

	return rcode;
}


module_t rlm_rediswho = {
	RLM_MODULE_INIT,
	"rediswho",
	RLM_TYPE_THREAD_SAFE, /* type */
	rediswho_instantiate, /* instantiation */
	rediswho_detach, /* detach */
	{
		NULL, /* authentication */
		NULL, /* authorization */
		NULL, /* preaccounting */
		rediswho_accounting, /* accounting */
		NULL, /* checksimul */
		NULL, /* pre-proxy */
		NULL, /* post-proxy */
		NULL /* post-auth */
	},
};
