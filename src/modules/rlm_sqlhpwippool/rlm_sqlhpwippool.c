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
 * @file rlm_sqlhpwippool.c
 * @brief Allocates an IPv4 address from pools defined in ASN Netvim.
 *
 * Current bugs/limits:
 * - probably works only with newer versions of MySQL (subqueries)
 * - requires FreeRADIUS' SQL user to have proper permissions on proper tables
 *   from Netvim database
 * - of course uses dirty hacks to get access to the database
 * - queries and table names are not configurable
 * - IPv4 only (I don't even care about IPv6 by now)
 * - pool names (fetched from database) are not "escaped"
 * - you have to set encoding of radius.acctuniqueid to same as
 *   netvim.ips.rsv_by
 *
 * @copyright 2005-2006 Pawel Foremski <pjf@asn.pl>,
 * @copyright 2000-2006 The FreeRADIUS server project
 */
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/modpriv.h>

#include <ctype.h>

#include "rlm_sql.h"

#define RLM_NETVIM_MAX_ROWS 1000000
#define RLM_NETVIM_TMP_PREFIX "auth-tmp-"

#define MAX_QUERY_LEN 4096

RCSID("$Id$")

typedef struct rlm_sqlhpwippool_t {
	char const		*myname;	 		//!< Name of this instance
	rlm_sql_t		*sql_inst;
	rlm_sql_driver_t const	*db;
#ifdef HAVE_PTHREAD_D
	pthread_mutex_t		mutex;			//!< Used "with" sync_after
#endif
	uint32_t		sincesync;		//!< req. done so far since last free IP sync.

	/* from config */
	char const		*sql_instance_name;	//!< rlm_sql instance to use.
	char const		*db_name;		//!< Netvim database.
	bool			no_free_fail;		//!< Fail if no free IP addresses found.
	uint32_t		free_after;	      	//!< How many seconds an IP should not be used after freeing.
	uint32_t		sync_after;		//!< How often to sync with radacct.
} rlm_sqlhpwippool_t;

/* char *name, int type,
 * size_t offset, void *data, char *dflt */
static CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("sql_module_instance", FR_TYPE_STRING, rlm_sqlhpwippool_t, sql_instance_name), .dflt = "sql" },
	{ FR_CONF_OFFSET("db_name", FR_TYPE_STRING, rlm_sqlhpwippool_t, db_name), .dflt = "netvim" },
	{ FR_CONF_OFFSET("no_free_fail", FR_TYPE_BOOL, rlm_sqlhpwippool_t, no_free_fail), .dflt = "yes" },
	{ FR_CONF_OFFSET("free_after", FR_TYPE_UINT32, rlm_sqlhpwippool_t, free_after), .dflt = "300" },
	{ FR_CONF_OFFSET("sync_after", FR_TYPE_UINT32, rlm_sqlhpwippool_t, sync_after), .dflt = "25" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_sqlhpwippool_dict[];
fr_dict_autoload_t rlm_sqlhpwippool_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_acct_unique_session_id;
static fr_dict_attr_t const *attr_framed_ip_address;
static fr_dict_attr_t const *attr_nas_ip_address;
static fr_dict_attr_t const *attr_acct_status_type;
static fr_dict_attr_t const *attr_asn_ip_pool_name;

extern fr_dict_attr_autoload_t rlm_sqlhpwippool_dict_attr[];
fr_dict_attr_autoload_t rlm_sqlhpwippool_dict_attr[] = {
	{ .out = &attr_acct_unique_session_id, .name = "Acct-Unique-Session-Id", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_framed_ip_address, .name = "Framed-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_nas_ip_address, .name = "NAS-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_asn_ip_pool_name, .name = "ASN-IP-Pool-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

DIAG_OFF(format-nonliteral)
/* handy SQL query tool */
static int nvp_vquery(rlm_sqlhpwippool_t *data,
		      rlm_sql_handle_t *sqlsock, char const *fmt, va_list ap)
{
	char query[MAX_QUERY_LEN];
	vsnprintf(query, MAX_QUERY_LEN, fmt, ap);

	if (!sqlsock) return 0;

	if (rlm_sql_query(data->sql_inst, NULL, &sqlsock, query)) {
		return 0;
	}

	return 1;
}
DIAG_ON(format-nonliteral)

/* wrapper around nvp_vquery */
static int nvp_query(rlm_sqlhpwippool_t *data,
		    rlm_sql_handle_t *sqlsock, char const *fmt, ...)
{
	int r;
	va_list ap;

	va_start(ap, fmt);
	r = nvp_vquery(data, sqlsock, fmt, ap);
	va_end(ap);

	return r;
}

/* handy wrapper around data->db->sql_finish_query() */
static int nvp_finish(rlm_sqlhpwippool_t *data, rlm_sql_handle_t *sqlsock)
{
	return (data->db->sql_finish_query)(sqlsock, data->sql_inst->config);
}

/* executes query and fetches first row
 * -1 on no results
 *  0 on db error
 *  1 on success */
static int nvp_select(rlm_sql_row_t *row, rlm_sqlhpwippool_t *data,
		      rlm_sql_handle_t *sqlsock, char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!nvp_vquery(data, sqlsock, fmt, ap)) {
		va_end(ap);
		return 0;
	}
	va_end(ap);

	if (data->db->sql_store_result && (data->db->sql_store_result)(sqlsock, data->sql_inst->config)) {
		ERROR("nvp_select(): error while saving results of query");
		return 0;
	}

	if (data->db->sql_num_rows && ((data->db->sql_num_rows)(sqlsock, data->sql_inst->config) < 1)) {
		DEBUG("nvp_select(): no results in query");
		return -1;
	}

	if ((data->db->sql_fetch_row)(row, sqlsock, data->sql_inst->config)) {
		ERROR("nvp_select(): couldn't fetch row from results of query");
		return 0;
	}

	return 1;
}

static int nvp_select_finish(rlm_sqlhpwippool_t *data, rlm_sql_handle_t *sqlsock)
{
	return ((data->db->sql_free_result)(sqlsock, data->sql_inst->config) ||
		nvp_finish(data, sqlsock));
}

/* frees IPs of closed sessions (eg. by external modifications to db) */
static int nvp_freeclosed(rlm_sqlhpwippool_t *data, rlm_sql_handle_t *sqlsock)
{
	if (!nvp_query(data, sqlsock,
	    "UPDATE `%s`.`ips`, `radacct` "
		"SET "
			"`ips`.`rsv_until` = `radacct`.`acctstoptime` + INTERVAL %u SECOND "
		"WHERE "
			"`radacct`.`acctstoptime` IS NOT NULL AND "   /* session is closed */
			"("				    /* address is being used */
				"`ips`.`pid` IS NOT NULL AND "
				"(`rsv_until` = 0 OR `rsv_until` > NOW())"
			") AND "
			"`radacct`.`acctuniqueid` = `ips`.`rsv_by`",
	    data->db_name, data->free_after)) {
		return 0;
	}

	nvp_finish(data, sqlsock);
	return 1;
}

/* updates number of free IP addresses in pools */
static int nvp_syncfree(rlm_sqlhpwippool_t *data, rlm_sql_handle_t *sqlsock)
{
	if (!nvp_query(data, sqlsock,
	    "UPDATE `%s`.`ip_pools` "
		"SET `ip_pools`.`free` = "
			"(SELECT COUNT(*) "
				"FROM `%1$s`.`ips` "
				"WHERE "
					"`ips`.`ip` BETWEEN "
						"`ip_pools`.`ip_start` AND `ip_pools`.`ip_stop` AND "
					"("
						"`ips`.`pid` IS NULL OR "
						"(`ips`.`rsv_until` > 0 AND `ips`.`rsv_until` < NOW())"
					"))",
	    data->db_name)) {
		return 0;
	}

	nvp_finish(data, sqlsock);
	return 1;
}

/* cleanup IP pools and sync them with radacct */
static int nvp_cleanup(rlm_sqlhpwippool_t *data)
{
	rlm_sql_handle_t *sqlsock;

	/* initialize the SQL socket */
	sqlsock = fr_pool_connection_get(data->sql_inst->pool, NULL);
	if (!sqlsock) {
		ERROR("nvp_cleanup(): error while requesting new SQL connection");
		return 0;
	}

	/* free IPs of closed sessions */
	if (!nvp_freeclosed(data, sqlsock)) {
		fr_pool_connection_release(data->sql_inst->pool, NULL, sqlsock);
		return 0;
	}

	/* add sessions opened in the meantime */
	if (!nvp_query(data, sqlsock,
	    "UPDATE `%s`.`ips`, `radacct` "
		"SET "
			"`ips`.`pid` = 0, "
			"`ips`.`rsv_by` = `radacct`.`acctuniqueid`, "
			"`ips`.`rsv_since` = `radacct`.`acctstarttime`, "
			"`ips`.`rsv_until` = 0 "
		"WHERE "
			"`radacct`.`acctstoptime` IS NULL AND "     /* session is opened */
			"`ips`.`ip` = INET_ATON(`radacct`.`framedipaddress`) AND "
			"("
				"`ips`.`pid` IS NULL OR "
/*	    			"(`ips`.`rsv_until` > 0 AND `ips.`rsv_until` < NOW()) " */
				"`ips`.`rsv_until` != 0"   /* no acct pkt received yet */
			")",
	    data->db_name)) {
		fr_pool_connection_release(data->sql_inst->pool, NULL, sqlsock);
		return 0;
	}
	else {
		nvp_finish(data, sqlsock);
	}

	/* count number of free IP addresses in IP pools */
	if (!nvp_syncfree(data, sqlsock)) {
		fr_pool_connection_release(data->sql_inst->pool, NULL, sqlsock);
		return 0;
	}

	fr_pool_connection_release(data->sql_inst->pool, NULL, sqlsock);
	return 1;
}

/* standard foobar code */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_sqlhpwippool_t	*inst = instance;
	module_instance_t	*sql_inst;

	/* save my name */
	inst->myname = cf_section_name2(conf);
	if (!inst->myname) {
		inst->myname = "(no name)";
	}

	inst->sincesync = 0;

	sql_inst = module_find(cf_section_find(main_config->root_cs, "modules", NULL), inst->sql_instance_name);
	if (!sql_inst) {
		cf_log_err(conf, "Cannot find SQL module instance named \"%s\"",
			      inst->sql_instance_name);
		return -1;
	}

	/* save pointers to useful "objects" */
	inst->sql_inst = (rlm_sql_t *) sql_inst->dl_inst->data;
	inst->db = (rlm_sql_driver_t const *) inst->sql_inst->driver;

	/* check if the given instance is really a rlm_sql instance */
	if (strcmp(inst->sql_inst->driver->name, "sql") != 0) {
		cf_log_err(conf, "Module \"%s\" is not an instance of the rlm_sql module",
			      inst->sql_instance_name);
		return -1;
	}

	return ((nvp_cleanup(inst)) ? 0 : -1);
}

/* assign new IP address, if required */
static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, UNUSED void *thread, REQUEST *request)
{
	VALUE_PAIR *vp;
	char const *pname;       /* name of requested IP pool */
	uint32_t nasip;	     /* NAS IP in host byte order */
	struct in_addr ip = {0};    /* reserved IP for client (net. byte order) */
	rlm_sql_handle_t *sqlsock;
	unsigned long s_gid,	/* _s_elected in sql result set */
		      s_prio,      /* as above */
		      s_pid,	/* as above */
		      gid,	  /* real integer value */
		      pid,	  /* as above */
		      weights_sum, used_sum, ip_start, ip_stop, connid;
	long prio;
	rlm_sql_row_t row;

	rlm_sqlhpwippool_t	*inst = (rlm_sqlhpwippool_t *) instance;


	/* if IP is already there, then nothing to do */
	vp = fr_pair_find_by_da(request->reply->vps, attr_framed_ip_address, TAG_ANY);
	if (vp) {
		RDEBUG2("IP address already in the reply packet - exiting");
		return RLM_MODULE_NOOP;
	}

	/* if no pool name, we don't need to do anything */
	vp = fr_pair_find_by_da(request->reply->vps, attr_asn_ip_pool_name, TAG_ANY);
	if (vp) {
		pname = vp->vp_strvalue;
		RDEBUG2("pool name = '%s'", pname);
	}
	else {
		RDEBUG2("No IP pool name - exiting");
		return RLM_MODULE_NOOP;
	}

	/* if no NAS IP address, assign 0 */
	vp = fr_pair_find_by_da(request->packet->vps, attr_nas_ip_address, TAG_ANY);
	if (vp) {
		nasip = ntohl(vp->vp_ipv4addr);
	}
	else {
		nasip = 0;
		RDEBUG2("No NAS IP address in the request packet - using \"0.0.0.0/0\" (any)");
	}

	/* get our database connection */
	sqlsock = fr_pool_connection_get(inst->sql_inst->pool, request);
	if (!sqlsock) {
		RERROR("Error while requesting an SQL socket");
		return RLM_MODULE_FAIL;
	}

	/* get connection id as temporary unique integer */
	if (nvp_select(&row, inst, sqlsock, "SELECT CONNECTION_ID()") < 1) {
		REDEBUG("Failed getting connection ID");
		nvp_select_finish(inst, sqlsock);
		fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
		return RLM_MODULE_FAIL;
	}

	connid = strtoul(row[0], (char **) NULL, 10);
	nvp_select_finish(inst, sqlsock);

	/* synchronize with radacct db, if needed */
	if (++inst->sincesync >= inst->sync_after
#ifdef HAVE_PTHREAD_D
	    && (pthread_mutex_trylock(&inst->mutex)) == 0
#endif
	   ) {
		int r;

		inst->sincesync = 0;

		RDEBUG2("Syncing with radacct table");

		r = (nvp_freeclosed(inst, sqlsock) && nvp_syncfree(inst, sqlsock));

#ifdef HAVE_PTHREAD_D
		pthread_mutex_unlock(&inst->mutex);
#endif

		if (!r) {
			RERROR("Synchronization failed");
			fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
			return RLM_MODULE_FAIL;
		}
	}

	for (s_gid = 0; s_gid < RLM_NETVIM_MAX_ROWS && !(ip.s_addr); s_gid++) {
		RDEBUG2("Selecting gid on position %lu", s_gid);

		/* find the most specific group which NAS belongs to */
		switch (nvp_select(&row, inst, sqlsock,
		       "SELECT `host_groups`.`gid` "
			"FROM "
				"`%s`.`host_groups`, "
				"`%1$s`.`gid_ip`, "
				"`%1$s`.`ids` "
			"WHERE "
				"`host_groups`.`gid` = `ids`.`id` AND "
				"`ids`.`enabled` = 1 AND "
				"`host_groups`.`gid` = `gid_ip`.`gid` AND "
				"%lu BETWEEN `gid_ip`.`ip_start` AND `gid_ip`.`ip_stop` "
			"ORDER BY (`gid_ip`.`ip_stop` - `gid_ip`.`ip_start`) ASC "
			"LIMIT %lu, 1",
		       inst->db_name, nasip, s_gid)) {
		case -1:
			RERROR("Couldn't find any more matching host groups");
			goto end_gid;		  /* exit the main loop */

		case 0:
			fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
			return RLM_MODULE_FAIL;
		}

		/* store the group ID and free memory occupied by results */
		gid = strtoul(row[0], (char **) NULL, 10);
		nvp_select_finish(inst, sqlsock);

		for (s_prio = 0; s_prio < RLM_NETVIM_MAX_ROWS && !(ip.s_addr); s_prio++) {
			REDEBUG2("Selecting prio on position %lu", s_prio);

			/* prepare to search for best fit pool */
			switch (nvp_select(&row, inst, sqlsock,
				"SELECT "
					"`ip_pools`.`prio`, "
					"SUM(`ip_pools`.`weight`) AS `weights_sum`, "
					"(SUM(`ip_pools`.`total`) - "
						"SUM(`ip_pools`.`free`)) AS `used_sum` "
					"FROM "
						"`%s`.`ip_pools`, "
						"`%1$s`.`ids`, "
						"`%1$s`.`pool_names` "
					"WHERE "
						"`ip_pools`.`gid` = %lu AND "
						"`ids`.`id` = `ip_pools`.`pid` AND "
						"`ids`.`enabled` = 1 AND "
						"`pool_names`.`pnid` = `ip_pools`.`pnid` AND "
						"`pool_names`.`name` = '%s' AND "
						"`ip_pools`.`free` > 0 "
					"GROUP BY `prio` "
					"ORDER BY `prio` ASC "
					"LIMIT %lu, 1",
				inst->db_name, gid, pname, s_prio)) {
			case -1:
				RDEBUG2("Couldn't find any more matching pools for gid = %lu", gid);
				goto end_prio;	       /* select next gid */

			case 0:
				fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
				return RLM_MODULE_FAIL;
			}

			/* store the prio and weights sum */
			prio = strtol(row[0], (char **) NULL, 10);
			weights_sum = strtoul(row[1], (char **) NULL, 10);
			used_sum = strtoul(row[2], (char **) NULL, 10);

			/* free memory */
			nvp_select_finish(inst, sqlsock);

			for (s_pid = 0; s_pid < RLM_NETVIM_MAX_ROWS && !(ip.s_addr); s_pid++) {
				RDEBUG2("Selecting PID on position %lu", s_pid);

				/* search for best fit pool */
				switch (nvp_select(&row, inst, sqlsock,
					"SELECT "
						"`ip_pools`.`pid`, "
						"`ip_pools`.`ip_start`, "
						"`ip_pools`.`ip_stop` "
						"FROM "
							"`%s`.`ip_pools`, "
							"`%1$s`.`ids`, "
							"`%1$s`.`pool_names` "
						"WHERE "
							"`ip_pools`.`gid` = %lu AND "
							"`ids`.`id` = `ip_pools`.`pid` AND "
							"`ids`.`enabled` = 1 AND "
							"`pool_names`.`pnid` = `ip_pools`.`pnid` AND "
							"`pool_names`.`name` = '%s' AND "
							"`ip_pools`.`free` > 0 AND "
							"`prio` = %ld "
						"ORDER BY (`weight`/%lu.0000 - (`total` - `free`)/%lu) DESC "
						"LIMIT %lu, 1",
					inst->db_name, gid, pname, prio,
					weights_sum, used_sum, s_pid)) {
				case -1:
					RDEBUG2("Couldn't find any more matching pools of prio = %ld for gid = %lu",
						prio, gid);
					goto end_pid;	      /* select next prio */

				case 0:
					fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
					return RLM_MODULE_FAIL;
				}

				/* store the inst and free memory occupied by results */
				pid = strtoul(row[0], (char **) NULL, 10);
				ip_start = strtoul(row[1], (char **) NULL, 10);
				ip_stop = strtoul(row[2], (char **) NULL, 10);
				nvp_select_finish(inst, sqlsock);

				/* reserve an IP address */
				if (!nvp_query(inst, sqlsock,
				    "UPDATE `%s`.`ips` "
					"SET "
						"`pid` = %lu, "
						"`rsv_since` = NOW(), "
						"`rsv_by` = '" RLM_NETVIM_TMP_PREFIX "%lu', "
						"`rsv_until` = NOW() + INTERVAL %d SECOND "
					"WHERE "
						"`ip` BETWEEN %lu AND %lu AND "
						"("
							"`pid` IS NULL OR "
							"(`rsv_until` > 0 AND `rsv_until` < NOW())"
						") "
					"ORDER BY RAND() "
					"LIMIT 1",
				    inst->db_name, pid, connid, inst->free_after, ip_start, ip_stop)) {
					fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
					return RLM_MODULE_FAIL;
				}
				else {
					nvp_finish(inst, sqlsock);
				}

				/* select assigned IP address */
				switch (nvp_select(&row, inst, sqlsock,
					"SELECT `ip` "
						"FROM `%s`.`ips` "
						"WHERE `rsv_by` = '" RLM_NETVIM_TMP_PREFIX "%lu' "
						"ORDER BY `rsv_since` DESC "
						"LIMIT 1",
					inst->db_name, connid)) {
				case -1:
					RERROR("Couldn't reserve an IP address from pool of pid = %lu "
					       "(prio = %ld, gid = %lu)", pid, prio, gid);
					continue;			    /* select next pid */

				case 0:
					fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
					return RLM_MODULE_FAIL;
				}

				/* update free IPs count */
				if (!nvp_query(inst, sqlsock,
				    "UPDATE `%s`.`ip_pools` "
					"SET "
						"`free` = `free` - 1 "
					"WHERE "
						"`pid` = %lu "
				"LIMIT 1",
				    inst->db_name, pid)) {
					fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
					return RLM_MODULE_FAIL;
				}
				else {
					nvp_finish(inst, sqlsock);
				}

				/* get assigned IP and free memory */
				ip.s_addr = htonl(strtoul(row[0], (char **) NULL, 10));
				nvp_select_finish(inst, sqlsock);
			} /* pid */
end_pid: continue;	   /* stupid */
		} /* prio */
end_prio: continue;	  /* stupid */
	} /* gid */
end_gid:

	/* release SQL socket */
fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);

	/* no free IP address found */
	if (!ip.s_addr) {
		RINFO("No free IP address found!");

		if (inst->no_free_fail) {
			RDEBUG2("Rejecting user");
			return RLM_MODULE_REJECT;
		}
		else {
			RDEBUG2("Exiting");
			return RLM_MODULE_NOOP;
		}
	}

	/* add IP address to reply packet */
	MEM(pair_add_reply(&vp, attr_framed_ip_address) >= 0);
	vp->vp_ipv4addr = ip.s_addr;

	RDEBUG2("Returning %s", inet_ntoa(ip));
	return RLM_MODULE_OK;
}

static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, UNUSED void *thread, REQUEST *request)
{
	VALUE_PAIR *vp;
	rlm_sql_handle_t *sqlsock;
	struct in_addr nasip;      /* NAS IP */
	char const *sessid;     /* unique session id */
	char nasipstr[16];	 /* NAS IP in string format */
	uint32_t framedip = 0;     /* client's IP, host byte order */
	uint32_t acct_type;

	rlm_sqlhpwippool_t *inst = (rlm_sqlhpwippool_t *) instance;

	/* if no unique session ID, don't even try */
	vp = fr_pair_find_by_da(request->packet->vps, attr_acct_unique_session_id, TAG_ANY);
	if (vp) {
		sessid = vp->vp_strvalue;
	}
	else {
		REDEBUG("Acct-Unique-Session-Id not found");
		return RLM_MODULE_FAIL;
	}

	vp = fr_pair_find_by_da(request->packet->vps, attr_acct_status_type, TAG_ANY);
	if (vp) {
		acct_type = vp->vp_uint32;
	}
	else {
		REDEBUG("Couldn't find type of accounting packet");
		return RLM_MODULE_FAIL;
	}

	if (!(acct_type == FR_STATUS_START ||
	      acct_type == FR_STATUS_ALIVE ||
	      acct_type == FR_STATUS_STOP  ||
	      acct_type == FR_STATUS_ACCOUNTING_OFF ||
	      acct_type == FR_STATUS_ACCOUNTING_ON)) {
		return RLM_MODULE_NOOP;
	}

	/* connect to database */
	sqlsock = fr_pool_connection_get(inst->sql_inst->pool, request);
	if (!sqlsock) {
		REDEBUG("Couldn't connect to database");
		return RLM_MODULE_FAIL;
	}


	switch (acct_type) {
	case FR_STATUS_START:
	case FR_STATUS_ALIVE:
		vp = fr_pair_find_by_da(request->packet->vps, attr_framed_ip_address, TAG_ANY);
		if (!vp) {
			REDEBUG("No framed IP");
			fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
			return RLM_MODULE_FAIL;
		}

		framedip = ntohl(vp->vp_ipv4addr);

		if (!nvp_query(inst, sqlsock,
		    "UPDATE `%s`.`ips` "
			"SET "
				"`rsv_until` = 0, "
				"`rsv_by` = '%s' "
			"WHERE `ip` = %lu",
		    inst->db_name, sessid, framedip)) {
			fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
			return RLM_MODULE_FAIL;
		}
		nvp_finish(inst, sqlsock);
		break;

	case FR_STATUS_STOP:
		if (!nvp_query(inst, sqlsock,
		    "UPDATE `%s`.`ips`, `%1$s`.`ip_pools` "
			"SET "
				"`ips`.`rsv_until` = NOW() + INTERVAL %u SECOND, "
				"`ip_pools`.`free` = `ip_pools`.`free` + 1 "
			"WHERE "
				"`ips`.`rsv_by` = '%s' AND "
				"`ips`.`ip` BETWEEN `ip_pools`.`ip_start` AND `ip_pools`.`ip_stop`",
		    inst->db_name, inst->free_after, sessid)) {
			fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
			return RLM_MODULE_FAIL;
		}
		nvp_finish(inst, sqlsock);
		break;

	case FR_STATUS_ACCOUNTING_OFF:
	case FR_STATUS_ACCOUNTING_ON:
		vp = fr_pair_find_by_da(request->packet->vps, attr_nas_ip_address, TAG_ANY);
		if (!vp) {
			REDEBUG("No NAS IP");
			fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
			return RLM_MODULE_FAIL;
		}

		nasip.s_addr = vp->vp_ipv4addr;
		strlcpy(nasipstr, inet_ntoa(nasip), sizeof(nasipstr));

		if (!nvp_query(inst, sqlsock,
		    "UPDATE `%s`.`ips`, `radacct` "
			"SET `ips`.`rsv_until` = NOW() + INTERVAL %u SECOND "
			"WHERE "
				"`radacct`.`nasipaddress` = '%s' AND "
				"`ips`.`rsv_by` = `radacct`.`acctuniqueid`",
		    inst->db_name, inst->free_after, nasipstr)) {
			fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
			return RLM_MODULE_FAIL;
		}
		nvp_finish(inst, sqlsock);

		break;
	}

	fr_pool_connection_release(inst->sql_inst->pool, request, sqlsock);
	return RLM_MODULE_OK;
}

extern rad_module_t rlm_sqlhpwippool;
rad_module_t rlm_sqlhpwippool = {
	.magic		= RLM_MODULE_INIT,
	.name		= "sqlhpwippool",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_sqlhpwippool_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
