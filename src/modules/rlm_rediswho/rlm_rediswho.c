/*
 *  rlm_rediswho.c     rlm_rediswho - FreeRADIUS redis/bashtable "radwho" Module
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
 * Copyright 2006  The FreeRADIUS server project
 * Copyright 2011  TekSavvy Solutions Inc <gabe@teksavvy.com>
 */

#include <freeradius-devel/ident.h>

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <ctype.h>

#include <rlm_redis.h>

typedef struct rlm_rediswho_t {
	const char *xlat_name;

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

	char *start_insert;
	char *start_trim;
	char *start_expire;

	char *alive_insert;
	char *alive_trim;
	char *alive_expire;

	char *stop_insert;
	char *stop_trim;
	char *stop_expire;
} rlm_rediswho_t;

static CONF_PARSER module_config[] = {
	{ "redis-instance-name", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rediswho_t, redis_instance_name), NULL, "redis"},

	{ "expiry-time", PW_TYPE_INTEGER,
	  offsetof(rlm_rediswho_t, expiry_time), NULL, "86400"},
	{ "trim-count", PW_TYPE_INTEGER,
	  offsetof(rlm_rediswho_t, trim_count), NULL, "100"},

	{ "start-insert", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rediswho_t, start_insert), NULL, ""},
	{ "start-trim", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rediswho_t, start_trim), NULL, ""},
	{ "start-expire", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rediswho_t, start_expire), NULL, ""},

	{ "alive-insert", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rediswho_t, alive_insert), NULL, ""},
	{ "alive-trim", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rediswho_t, alive_trim), NULL, ""},
	{ "alive-expire", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rediswho_t, alive_expire), NULL, ""},

	{ "stop-insert", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rediswho_t, stop_insert), NULL, ""},
	{ "stop-trim", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rediswho_t, stop_trim), NULL, ""},
	{ "stop-expire", PW_TYPE_STRING_PTR,
	  offsetof(rlm_rediswho_t, stop_expire), NULL, ""},

	{ NULL, -1, 0, NULL, NULL}
};

/*
 *	Query the database executing a command with no result rows
 */
static int rediswho_command(const char *fmt, REDISSOCK *dissocket,
			    rlm_rediswho_t *data, REQUEST *request)
{
	if (data->redis_inst->redis_query(dissocket, data->redis_inst,
	                                  fmt, request) < 0) {

		radlog(L_ERR, "rediswho_command: database query error in: '%s'", fmt);
		return -1;
	}

	switch (dissocket->reply->type) {
	case REDIS_REPLY_INTEGER:
		DEBUG("rediswho_command: query response %lld\n",
		      dissocket->reply->integer);
		break;
	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_STRING:
		DEBUG("rediswho_command: query response %s\n",
		      dissocket->reply->str);
		break;
	default:
		break;
	}

	(data->redis_inst->redis_finish_query)(dissocket);

	return 0;
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

	DEBUG("xlat name %s\n", inst->xlat_name);

	/*
	 *	Check that all the queries are in place
	 */
	if ((inst->start_insert == NULL) || !*inst->start_insert) {
		radlog(L_ERR, "rlm_rediswho: the 'start_insert' statement must be set.");
		rediswho_detach(inst);
		return -1;
	}
	if ((inst->start_trim == NULL) || !*inst->start_trim) {
		radlog(L_ERR, "rlm_rediswho: the 'start_trim' statement must be set.");
		rediswho_detach(inst);
		return -1;
	}
	if ((inst->start_expire == NULL) || !*inst->start_expire) {
		radlog(L_ERR, "rlm_rediswho: the 'start_expire' statement must be set.");
		rediswho_detach(inst);
		return -1;
	}

	if ((inst->alive_insert == NULL) || !*inst->alive_insert) {
		radlog(L_ERR, "rlm_rediswho: the 'alive_insert' statement must be set.");
		rediswho_detach(inst);
		return -1;
	}
	if ((inst->alive_trim == NULL) || !*inst->alive_trim) {
		radlog(L_ERR, "rlm_rediswho: the 'alive_trim' statement must be set.");
		rediswho_detach(inst);
		return -1;
	}
	if ((inst->alive_expire == NULL) || !*inst->alive_expire) {
		radlog(L_ERR, "rlm_rediswho: the 'alive_expire' statement must be set.");
		rediswho_detach(inst);
		return -1;
	}

	if ((inst->stop_insert == NULL) || !*inst->stop_insert) {
		radlog(L_ERR, "rlm_rediswho: the 'stop_insert' statement must be set.");
		rediswho_detach(inst);
		return -1;
	}
	if ((inst->stop_trim == NULL) || !*inst->stop_trim) {
		radlog(L_ERR, "rlm_rediswho: the 'stop_trim' statement must be set.");
		rediswho_detach(inst);
		return -1;
	}
	if ((inst->stop_expire == NULL) || !*inst->stop_expire) {
		radlog(L_ERR, "rlm_rediswho: the 'stop_expire' statement must be set.");
		rediswho_detach(inst);
		return -1;
	}

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

#define REDISWHO_COMMAND(_a, _b, _c, _d) if (rediswho_command(_a, _b, _c, _d) < 0) return RLM_MODULE_FAIL

static int rediswho_accounting_start(REDISSOCK *dissocket,
				     rlm_rediswho_t *data, REQUEST *request)
{
	REDISWHO_COMMAND(data->start_insert, dissocket, data, request);
    
	/* Only trim if necessary */
	if (dissocket->reply->type == REDIS_REPLY_INTEGER) {
		if (dissocket->reply->integer > data->trim_count) {
			rediswho_command(data->start_trim, dissocket, data, request);
		}
	}

	REDISWHO_COMMAND(data->start_expire, dissocket, data, request);

	return RLM_MODULE_OK;
}

static int rediswho_accounting_alive(REDISSOCK *dissocket,
				     rlm_rediswho_t *data, REQUEST *request)
{
	REDISWHO_COMMAND(data->alive_insert, dissocket, data, request);

	/* Only trim if necessary */
	if (dissocket->reply->type == REDIS_REPLY_INTEGER) {
		if (dissocket->reply->integer > data->trim_count) {
			rediswho_command(data->alive_trim, dissocket, data, request);
		}
	}

	REDISWHO_COMMAND(data->alive_expire, dissocket, data, request);

	return RLM_MODULE_OK;
}

static int rediswho_accounting_stop(REDISSOCK *dissocket,
				    rlm_rediswho_t *data, REQUEST *request)
{

	REDISWHO_COMMAND(data->stop_insert, dissocket, data, request);

	/* Only trim if necessary */
	if (dissocket->reply->type == REDIS_REPLY_INTEGER) {
		if (dissocket->reply->integer > data->trim_count) {
			rediswho_command(data->stop_trim, dissocket, data, request);
		}
	}

	REDISWHO_COMMAND(data->stop_expire, dissocket, data, request);

	return RLM_MODULE_OK;
}

static int rediswho_accounting(void * instance, REQUEST * request)
{
	int rcode = RLM_MODULE_NOOP;
	VALUE_PAIR * vp;
	int acct_status_type;
	rlm_rediswho_t * data = (rlm_rediswho_t *) instance;
	REDISSOCK *dissocket;

	vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE);
	if (!vp) {
		RDEBUG("Could not find account status type in packet.");
		return RLM_MODULE_NOOP;
	}
	acct_status_type = vp->vp_integer;

	switch (acct_status_type) {
        case PW_STATUS_START:
        case PW_STATUS_ALIVE:
        case PW_STATUS_STOP:
        case PW_STATUS_ACCOUNTING_ON:
        case PW_STATUS_ACCOUNTING_OFF:
		break;

        default:
		/* We don't care about any other accounting packet */
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Some nonsensical security checks.
	 */
	if (!request->username) {
		RDEBUG("User-Name is required");
		return RLM_MODULE_NOOP;
	}

	dissocket = data->redis_inst->redis_get_socket(data->redis_inst);
	if (dissocket == NULL) {
		RDEBUG("cannot allocate redis connection");
		return RLM_MODULE_FAIL;
	}

	switch (acct_status_type) {
        case PW_STATUS_START:
		rcode = rediswho_accounting_start(dissocket, data, request);
		break;

        case PW_STATUS_ALIVE:
		rcode = rediswho_accounting_alive(dissocket, data, request);
		break;

        case PW_STATUS_STOP:
		rcode = rediswho_accounting_stop(dissocket, data, request);
		break;

        case PW_STATUS_ACCOUNTING_ON:
        case PW_STATUS_ACCOUNTING_OFF:
		/* TODO */
		break;

	}

	data->redis_inst->redis_release_socket(data->redis_inst, dissocket);

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
