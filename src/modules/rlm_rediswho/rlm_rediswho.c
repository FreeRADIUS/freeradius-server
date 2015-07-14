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
 * @author Gabriel Blanchard
 *
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2011  TekSavvy Solutions <gabe@teksavvy.com>
 * @copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/rad_assert.h>

#include "../rlm_redis/redis.h"

typedef struct rlm_rediswho {
	redis_conn_conf_t	*server;	//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	char const		*name;		//!< Instance name.
	CONF_SECTION		*cs;
	fr_connection_pool_t	*pool;		//!< Connection pool.

	int			expiry_time;	//!< Expiry time in seconds if no updates are received for a user

	int			trim_count;	//!< How many session updates to keep track of per user.

	char const		*insert;	//!< Command for inserting session data
	char const		*trim;		//!< Command for trimming the session list.
	char const		*expire;	//!< Command for expiring entries.
} rlm_rediswho_t;

static CONF_PARSER module_config[] = {
	{ "server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, redis_conn_conf_t, hostname), NULL },
	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, redis_conn_conf_t, port), "6379" },
	{ "database", FR_CONF_OFFSET(PW_TYPE_INTEGER, redis_conn_conf_t, database), "0" },
	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, redis_conn_conf_t, password), NULL },

	{ "trim_count", FR_CONF_OFFSET(PW_TYPE_SIGNED, rlm_rediswho_t, trim_count), "-1" },

	{ "insert", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED | PW_TYPE_XLAT, rlm_rediswho_t, insert), NULL },
	{ "trim", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_rediswho_t, trim), NULL }, /* required only if trim_count > 0 */
	{ "expire", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED | PW_TYPE_XLAT, rlm_rediswho_t, expire), NULL },

	{ NULL, -1, 0, NULL, NULL}
};

/*
 *	Query the database executing a command with no result rows
 */
static int rediswho_command(UNUSED rlm_rediswho_t *inst, REQUEST *request, char const *fmt, redis_conn_t **conn_p)
{
	redisReply	*reply;
	int		ret = -1;

	int		argc;
	char const	*argv[MAX_REDIS_ARGS];
	char		argv_buf[MAX_REDIS_COMMAND_LEN];

	if (!fmt || !*fmt) return 0;

	argc = rad_expand_xlat(request, fmt, MAX_REDIS_ARGS, argv, false, sizeof(argv_buf), argv_buf);
 	if (argc < 0) return -1;

	reply = redisCommandArgv((*conn_p)->handle, argc, argv, NULL);
	switch (fr_redis_command_status(*conn_p, reply)) {
	case 0:
		break;

	default:
		rad_assert(0);
		/* FALL-THROUGH */

	case -1:
		RERROR("Command failed: %s", fr_strerror());
		freeReplyObject(reply);
		return -1;

	case -2:
		RERROR("Connection error: %s.  Reconnecting", fr_strerror());
		return -1;
	}

	switch (reply->type) {
	case REDIS_REPLY_INTEGER:
		RDEBUG2("Query response %lld", reply->integer);
		if (reply->integer > 0) ret = reply->integer;
		break;

	case REDIS_REPLY_STRING:
		REDEBUG2("Query response %s", reply->str);
		break;

	default:
		break;
	}
	freeReplyObject(reply);

	return ret;
}

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_rediswho_t *inst = instance;

	inst->pool = fr_connection_pool_module_init(conf, inst->server, fr_redis_conn_create, NULL, NULL);
	if (!inst->pool) return -1;

	return 0;
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_rediswho_t *inst = instance;

	fr_redis_version_print();

	inst->cs = conf;
	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);
	inst->server->prefix = talloc_asprintf(inst, "rlm_rediswho (%s)", inst->name);

	return 0;
}

static rlm_rcode_t mod_accounting_all(rlm_rediswho_t *inst, REQUEST *request, redis_conn_t **conn_p)
{
	int ret;

	ret = rediswho_command(inst, request, inst->insert, conn_p);
	if (ret < 0) return RLM_MODULE_FAIL;

	/* Only trim if necessary */
	if ((inst->trim_count >= 0) && (ret > inst->trim_count)) {
		if (rediswho_command(inst, request, inst->trim, conn_p) < 0) return RLM_MODULE_FAIL;
	}

	if (rediswho_command(inst, request, inst->expire, conn_p) < 0) return RLM_MODULE_FAIL;
	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
	rlm_rediswho_t 	*inst = instance;
	rlm_rcode_t	rcode;
	VALUE_PAIR	*vp;
	DICT_VALUE	*dv;
	CONF_SECTION	*cs;

	redis_conn_t	*conn;

	vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY);
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

	conn = fr_connection_get(inst->pool);
	if (!conn) return RLM_MODULE_FAIL;

	rcode = mod_accounting_all(inst, request, &conn);

	fr_connection_release(inst->pool, conn);

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
	.bootstrap	= mod_bootstrap,
	.methods = {
		[MOD_ACCOUNTING]	= mod_accounting
	},
};
