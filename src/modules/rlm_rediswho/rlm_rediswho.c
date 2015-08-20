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
#include "../rlm_redis/cluster.h"

typedef struct rlm_rediswho {
	fr_redis_conf_t		*conf;		//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	char const		*name;		//!< Instance name.
	CONF_SECTION		*cs;
	fr_redis_cluster_t	*cluster;	//!< Pool O pools

	int			expiry_time;	//!< Expiry time in seconds if no updates are received for a user

	int			trim_count;	//!< How many session updates to keep track of per user.

	char const		*insert;	//!< Command for inserting session data
	char const		*trim;		//!< Command for trimming the session list.
	char const		*expire;	//!< Command for expiring entries.
} rlm_rediswho_t;

static CONF_PARSER module_config[] = {
	REDIS_COMMON_CONFIG,

	{ FR_CONF_OFFSET("trim_count", PW_TYPE_SIGNED, rlm_rediswho_t, trim_count), .dflt = "-1" },
	{ FR_CONF_OFFSET("insert", PW_TYPE_STRING | PW_TYPE_REQUIRED | PW_TYPE_XLAT, rlm_rediswho_t, insert) },
	{ FR_CONF_OFFSET("trim", PW_TYPE_STRING | PW_TYPE_XLAT, rlm_rediswho_t, trim) }, /* required only if trim_count > 0 */
	{ FR_CONF_OFFSET("expire", PW_TYPE_STRING | PW_TYPE_REQUIRED | PW_TYPE_XLAT, rlm_rediswho_t, expire) },
	CONF_PARSER_TERMINATOR
};

/*
 *	Query the database executing a command with no result rows
 */
static int rediswho_command(rlm_rediswho_t *inst, REQUEST *request, char const *fmt)
{
	fr_redis_conn_t		*conn;

	int 			ret = -1;

	fr_redis_cluster_state_t	state;
	fr_redis_rcode_t		status;
	redisReply		*reply = NULL;
	int			s_ret;

	uint8_t	const		*key = NULL;
	size_t			key_len = 0;

	int			argc;
	char const		*argv[MAX_REDIS_ARGS];
	char			argv_buf[MAX_REDIS_COMMAND_LEN];

	if (!fmt || !*fmt) return 0;

	argc = rad_expand_xlat(request, fmt, MAX_REDIS_ARGS, argv, false, sizeof(argv_buf), argv_buf);
 	if (argc < 0) return -1;

	/*
	 *	If we've got multiple arguments, the second one is usually the key.
	 *	The Redis docs say commands should be analysed first to get key
	 *	positions, but this involves sending them to the server, which is
	 *	just as expensive as sending them to the wrong server and receiving
	 *	a redirect.
	 */
	if (argc > 1) {
		key = (uint8_t const *)argv[1];
	 	key_len = strlen((char const *)key);
	}

	for (s_ret = fr_redis_cluster_state_init(&state, &conn, inst->cluster, request, key, key_len, false);
	     s_ret == REDIS_RCODE_TRY_AGAIN;	/* Continue */
	     s_ret = fr_redis_cluster_state_next(&state, &conn, inst->cluster, request, status, &reply)) {
		reply = redisCommandArgv(conn->handle, argc, argv, NULL);
		status = fr_redis_command_status(conn, reply);
	}
	if (s_ret != REDIS_RCODE_SUCCESS) {
		RERROR("Failed inserting accounting data");
		fr_redis_reply_free(reply);
		return -1;
	}

	rad_assert(reply);	/* clang scan */
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
	fr_redis_reply_free(reply);

	return ret;
}

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_rediswho_t *inst = instance;

	inst->cluster = fr_redis_cluster_alloc(inst, conf, inst->conf);
	if (!inst->cluster) return -1;

	return 0;
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_rediswho_t *inst = instance;

	fr_redis_version_print();

	inst->cs = conf;
	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	return 0;
}

static rlm_rcode_t mod_accounting_all(rlm_rediswho_t *inst, REQUEST *request)
{
	int ret;

	ret = rediswho_command(inst, request, inst->insert);
	if (ret < 0) return RLM_MODULE_FAIL;

	/* Only trim if necessary */
	if ((inst->trim_count >= 0) && (ret > inst->trim_count)) {
		if (rediswho_command(inst, request, inst->trim) < 0) return RLM_MODULE_FAIL;
	}

	if (rediswho_command(inst, request, inst->expire) < 0) return RLM_MODULE_FAIL;
	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
	rlm_rediswho_t 	*inst = instance;
	rlm_rcode_t	rcode;
	VALUE_PAIR	*vp;
	DICT_VALUE	*dv;
	CONF_SECTION	*cs;

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

	rcode = mod_accounting_all(inst, request);

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
