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
 * @file rlm_rediswho.c
 * @brief Session tracking using redis.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2011  TekSavvy Solutions <gabe@teksavvy.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <ctype.h>

#include <rlm_redis.h>

typedef struct rlm_rediswho_t {
	char const *xlat_name;
	CONF_SECTION *cs;

	char const *redis_instance_name;
	REDIS_INST *redis_inst;

	/*
	 * 	expiry time in seconds if no updates are received for a user
	 */
	int expiry_time;

	/*
	 *	How many session updates to keep track of per user
	 */
	int trim_count;
	char const *insert;
	char const *trim;
	char const *expire;
} rlm_rediswho_t;

static CONF_PARSER module_config[] = {
	{ "redis_module_instance", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_rediswho_t, redis_instance_name), "redis" },

	{ "trim_count", FR_CONF_OFFSET(PW_TYPE_SIGNED, rlm_rediswho_t, trim_count), "-1" },

	{ "insert", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED | PW_TYPE_XLAT, rlm_rediswho_t, insert), NULL },
	{ "trim", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_rediswho_t, trim), NULL }, /* required only if trim_count > 0 */
	{ "expire", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED | PW_TYPE_XLAT, rlm_rediswho_t, expire), NULL },

	{ NULL, -1, 0, NULL, NULL}
};

/*
 *	Query the database executing a command with no result rows
 */
static int rediswho_command(char const *fmt, REDISSOCK **dissocket_p,
			    rlm_rediswho_t *inst, REQUEST *request)
{
	REDISSOCK *dissocket;
	int result = 0;

	if (!fmt) {
		return 0;
	}

	if (inst->redis_inst->redis_query(dissocket_p, inst->redis_inst,
					  fmt, request) < 0) {

		ERROR("rediswho_command: database query error in: '%s'", fmt);
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

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	module_instance_t *modinst;
	rlm_rediswho_t *inst = instance;

	inst->xlat_name = cf_section_name2(conf);

	if (!inst->xlat_name)
		inst->xlat_name = cf_section_name1(conf);

	inst->cs = conf;

	modinst = module_instantiate(cf_section_find("modules"),
				       inst->redis_instance_name);
	if (!modinst) {
		ERROR("rediswho: failed to find module instance \"%s\"",
		       inst->redis_instance_name);
		return -1;
	}

	if (strcmp(modinst->entry->name, "rlm_redis") != 0) {
		ERROR("rediswho: Module \"%s\""
		       " is not an instance of the redis module",
		       inst->redis_instance_name);
		return -1;
	}

	inst->redis_inst = (REDIS_INST *) modinst->insthandle;

	return 0;
}

static int mod_accounting_all(REDISSOCK **dissocket_p,
			      rlm_rediswho_t *inst, REQUEST *request)
{
	int result;

	result = rediswho_command(inst->insert, dissocket_p, inst, request);
	if (result < 0) {
		return RLM_MODULE_FAIL;
	}

	/* Only trim if necessary */
	if (inst->trim_count >= 0 && result > inst->trim_count) {
		if (rediswho_command(inst->trim, dissocket_p,
				     inst, request) < 0) {
			return RLM_MODULE_FAIL;
		}
	}

	if (rediswho_command(inst->expire, dissocket_p, inst, request) < 0) {
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void * instance, REQUEST * request)
{
	rlm_rcode_t rcode;
	VALUE_PAIR * vp;
	DICT_VALUE *dv;
	CONF_SECTION *cs;
	rlm_rediswho_t *inst = (rlm_rediswho_t *) instance;
	REDISSOCK *dissocket;

	vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY);
	if (!vp) {
		RDEBUG("Could not find account status type in packet");
		return RLM_MODULE_NOOP;
	}

	dv = dict_valbyattr(vp->da->attr, vp->da->vendor, vp->vp_integer);
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
	if (!dissocket) return RLM_MODULE_FAIL;

	rcode = mod_accounting_all(&dissocket, inst, request);

	if (dissocket) fr_connection_release(inst->redis_inst->pool, dissocket);

	return rcode;
}

extern module_t rlm_rediswho;
module_t rlm_rediswho = {
	.magic		= RLM_MODULE_INIT,
	.name		= "rediswho",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_rediswho_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_ACCOUNTING]	= mod_accounting
	},
};
