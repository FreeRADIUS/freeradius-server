/*
 * sql_oracle.c	Oracle (OCI) routines for rlm_sql
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
 * @copyright 2019 Robert Biktimirov (pobept@gmail.com)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 David Kerry (davidk@snti.com)
 */

RCSID("$Id$")

#define LOG_PREFIX "sql - oracle"

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <sys/stat.h>

/*
 *	There are typos in the Oracle Instaclient where the definition controlling prototype
 *	format is _STDC_ (not __STDC__).
 *
 *	There are still cases where the oracle headers do not declare ANSI C function types
 *	but this at least cuts down the errors.
 *
 *	-Wno-strict-prototypes does the rest.
 */
DIAG_OFF(unused-macros)
#if defined(__STDC__) && __STDC__
#  define _STDC_
#endif

#include <oci.h>
DIAG_ON(unused-macros)

#include "rlm_sql.h"

typedef struct {
	OCIEnv		*env;	//!< Number of columns associated with the result set
	OCIError	*error;	//!< Oracle error handle
	OCISPool	*pool;	//!< Oracle session pool handle
	char		*pool_name;	//!< The name of the session pool returned by OCISessionPoolCreate
	ub4		pool_name_len;	//!< Length of pool_name in bytes.

	uint32_t	stmt_cache_size;	//!< Statement cache size for each of the sessions in a session pool
	uint32_t	spool_timeout;	//!< The sessions idle time (in seconds) (0 disable).
	uint32_t	spool_min;	//!< Specifies the minimum number of sessions in the session pool.
	uint32_t	spool_max;	//!< Specifies the maximum number of sessions that can be opened in the session pool
	uint32_t	spool_inc;	//!< Specifies the increment for sessions to be started if the current number of sessions are less than sessMax
} rlm_sql_oracle_t;

typedef struct {
	OCIStmt		*query;
	OCIError	*error;
	OCISvcCtx	*ctx;
	sb2		*ind;
	char		**row;
	int		id;
	int		col_count;	//!< Number of columns associated with the result set
} rlm_sql_oracle_conn_t;

static const CONF_PARSER spool_config[] = {
	{ FR_CONF_OFFSET("stmt_cache_size", FR_TYPE_UINT32, rlm_sql_oracle_t, stmt_cache_size), .dflt = "32" },
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, rlm_sql_oracle_t, spool_timeout), .dflt = "0" },
	{ FR_CONF_OFFSET("min", FR_TYPE_UINT32, rlm_sql_oracle_t, spool_min), .dflt = "1" },
	{ FR_CONF_OFFSET("max", FR_TYPE_UINT32, rlm_sql_oracle_t, spool_max), .dflt = "2" },
	{ FR_CONF_OFFSET("inc", FR_TYPE_UINT32, rlm_sql_oracle_t, spool_inc), .dflt = "1" },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER driver_config[] = {
	{ FR_CONF_POINTER("spool", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) spool_config },
	CONF_PARSER_TERMINATOR
};

#define	MAX_DATASTR_LEN	64

/** Write the last Oracle error out to a buffer
 *
 * @param out Where to write the error (should be at least 512 bytes).
 * @param outlen The length of the error buffer.
 * @param handle sql handle.
 * @param config Instance config.
 * @return
 *	- 0 on success.
 *	- -1 if there was no error.
 */
static int sql_snprint_error(char *out, size_t outlen, rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	sb4			errcode = 0;
	rlm_sql_oracle_conn_t	*conn = handle->conn;

	fr_assert(conn);

	out[0] = '\0';

	OCIErrorGet((dvoid *) conn->error, 1, (OraText *) NULL, &errcode, (OraText *) out,
		    outlen, OCI_HTYPE_ERROR);
	if (!errcode) return -1;

	return 0;
}

/** Retrieves any errors associated with the connection handle
 *
 * @note Caller will free any memory allocated in ctx.
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of sql_log_entrys to fill.
 * @param outlen Length of out array.
 * @param handle rlm_sql connection handle.
 * @param config rlm_sql config.
 * @return number of errors written to the #sql_log_entry_t array.
 */
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], NDEBUG_UNUSED size_t outlen,
		        rlm_sql_handle_t *handle, rlm_sql_config_t const *config)
{
	char errbuff[512];
	int ret;

	fr_assert(outlen > 0);

	ret = sql_snprint_error(errbuff, sizeof(errbuff), handle, config);
	if (ret < 0) return 0;

	out[0].type = L_ERR;
	out[0].msg = talloc_strdup(ctx, errbuff);

	return 1;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_sql_oracle_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_sql_oracle_t);

	if (inst->pool) OCISessionPoolDestroy((dvoid *)inst->pool, (dvoid *)inst->error, OCI_DEFAULT );
	if (inst->error) OCIHandleFree((dvoid *)inst->error, OCI_HTYPE_ERROR);
	if (inst->env) OCIHandleFree((dvoid *)inst->env, OCI_HTYPE_ENV);

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_sql_t const		*parent = talloc_get_type_abort(mctx->inst->parent->data, rlm_sql_t);
	rlm_sql_config_t const	*config = &parent->config;
	rlm_sql_oracle_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_sql_oracle_t);
	char  			errbuff[512];
	sb4 			errcode = 0;
	OraText 		*sql_password = NULL;
	OraText 		*sql_login = NULL;

	if (!cf_section_find(mctx->inst->conf, "spool", NULL)) {
		ERROR("Couldn't load mctx->configuration of session pool(\"spool\" section in driver mctx->config)");
		return RLM_SQL_ERROR;
	}

	/*
	 *	Initialises the oracle environment
	 */
	if (OCIEnvCreate(&inst->env, OCI_DEFAULT | OCI_THREADED, NULL, NULL, NULL, NULL, 0, NULL)) {
		ERROR("Couldn't init Oracle OCI environment (OCIEnvCreate())");

		return RLM_SQL_ERROR;
	}

	/*
	 *	Allocates an error handle
	 */
	if (OCIHandleAlloc((dvoid *)inst->env, (dvoid **)&inst->error, OCI_HTYPE_ERROR, 0, NULL)) {
		ERROR("Couldn't init Oracle ERROR handle (OCIHandleAlloc())");

		return RLM_SQL_ERROR;
	}

	/*
	 *	Allocates an session pool handle
	 */
	if (OCIHandleAlloc((dvoid *)inst->env, (dvoid **)&inst->pool, OCI_HTYPE_SPOOL, 0, NULL)) {
		ERROR("Couldn't init Oracle session pool (OCIHandleAlloc())");
		return RLM_SQL_ERROR;
	}

	/*
	 *	Create session pool
	 */
	DEBUG("OCISessionPoolCreate min=%d max=%d inc=%d", inst->spool_min, inst->spool_max, inst->spool_inc);

	/* We need it to fix const issues between 'const char *' vs 'unsigned char *' */
	memcpy(&sql_login, config->sql_login, sizeof(sql_login));
	memcpy(&sql_password, config->sql_password, sizeof(sql_password));

	if (OCISessionPoolCreate((dvoid *)inst->env, (dvoid *)inst->error, (dvoid *)inst->pool,
				 (OraText**)&inst->pool_name, (ub4*)&inst->pool_name_len,
				 (CONST OraText *)config->sql_db, strlen(config->sql_db),
				 inst->spool_min, inst->spool_max, inst->spool_inc,
				 sql_login, strlen(config->sql_login),
				 sql_password, strlen(config->sql_password),
				 OCI_SPC_STMTCACHE | OCI_SPC_HOMOGENEOUS)) {

		errbuff[0] = '\0';
		OCIErrorGet((dvoid *) inst->error, 1, (OraText *) NULL, &errcode, (OraText *) errbuff,
		    sizeof(errbuff), OCI_HTYPE_ERROR);
		if (!errcode) return RLM_SQL_ERROR;

		ERROR("Oracle create session pool failed: '%s'", errbuff);
		return RLM_SQL_ERROR;
	}

	if (inst->spool_timeout > 0) {
		if (OCIAttrSet(inst->pool, OCI_HTYPE_SPOOL, &inst->spool_timeout, 0,
		      OCI_ATTR_SPOOL_TIMEOUT, inst->error) != OCI_SUCCESS) {
			ERROR("Couldn't set Oracle session idle time");
			return RLM_SQL_ERROR;
		}
	}

	if (OCIAttrSet(inst->pool, OCI_HTYPE_SPOOL, &inst->stmt_cache_size, 0,
	      OCI_ATTR_SPOOL_STMTCACHESIZE, inst->error) != OCI_SUCCESS) {
		ERROR("Couldn't set Oracle default statement cache size");
		return RLM_SQL_ERROR;
	}

	return 0;
}

static int sql_check_reconnect(rlm_sql_handle_t *handle, rlm_sql_config_t const *config)
{
	char errbuff[512];

	if (sql_snprint_error(errbuff, sizeof(errbuff), handle, config) < 0) return -1;

	if (strstr(errbuff, "ORA-03113") || strstr(errbuff, "ORA-03114")) {
		ERROR("OCI_SERVER_NOT_CONNECTED");
		return RLM_SQL_RECONNECT;
	}

	return -1;
}

static int _sql_socket_destructor(rlm_sql_oracle_conn_t *conn)
{
	if (conn->ctx) OCISessionRelease(conn->ctx, conn->error, NULL, 0, OCI_DEFAULT);
	if (conn->error) OCIHandleFree((dvoid *)conn->error, OCI_HTYPE_ERROR);
	return 0;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t const *config,
				   UNUSED fr_time_delta_t timeout)
{
	char errbuff[512];

	rlm_sql_oracle_t	*inst = talloc_get_type_abort(handle->inst->driver_submodule->dl_inst->data, rlm_sql_oracle_t);
	rlm_sql_oracle_conn_t	*conn;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_oracle_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	/*
	 *	Allocates an error handle
	 */
	if (OCIHandleAlloc((dvoid *)inst->env, (dvoid **)&conn->error, OCI_HTYPE_ERROR, 0, NULL)) {
		ERROR("Couldn't init Oracle ERROR handle (OCIHandleAlloc())");

		return RLM_SQL_ERROR;
	}

	/*
	 *	Get session from pool
	 */
	if (OCISessionGet((dvoid *)inst->env, conn->error, &conn->ctx, NULL,
		     (OraText *)inst->pool_name, inst->pool_name_len,
		     NULL, 0, NULL, NULL, NULL,
		     OCI_SESSGET_SPOOL | OCI_SESSGET_STMTCACHE) != OCI_SUCCESS) {
		ERROR("Oracle get sessin from pool[%s] failed: '%s'",
		      inst->pool_name,
		      (sql_snprint_error(errbuff, sizeof(errbuff), handle, config) == 0) ? errbuff : "unknown");

		return RLM_SQL_ERROR;
	}

	return RLM_SQL_OK;
}

static int sql_num_fields(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	int count;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	/* get the number of columns in the select list */
	if (OCIAttrGet((dvoid *)conn->query, OCI_HTYPE_STMT, (dvoid *)&count, NULL, OCI_ATTR_PARAM_COUNT,
		       conn->error)) return -1;

	return count;
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, rlm_sql_config_t const *config)
{
	rlm_sql_oracle_conn_t *conn = handle->conn;
	int		fields, i, status;
	char const	**names;
	OCIParam	*param;

	fields = sql_num_fields(handle, config);
	if (fields <= 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(handle, char const *, fields));

	for (i = 0; i < fields; i++) {
		OraText *pcol_name = NULL;
		ub4 pcol_size = 0;

		status = OCIParamGet(conn->query, OCI_HTYPE_STMT, conn->error, (dvoid **)&param, i + 1);
		if (status != OCI_SUCCESS) {
			ERROR("OCIParamGet(OCI_HTYPE_STMT) failed in sql_fields()");
		error:
			talloc_free(names);

			return RLM_SQL_ERROR;
		}

		status = OCIAttrGet((dvoid **)param, OCI_DTYPE_PARAM, &pcol_name, &pcol_size,
				    OCI_ATTR_NAME, conn->error);
		if (status != OCI_SUCCESS) {
			ERROR("OCIParamGet(OCI_ATTR_NAME) failed in sql_fields()");

			goto error;
		}

		names[i] = (char const *)pcol_name;
	}

	*out = names;

	return RLM_SQL_OK;
}

static sql_rcode_t sql_query(rlm_sql_handle_t *handle, rlm_sql_config_t const *config, char const *query)
{
	int			status;
	rlm_sql_oracle_conn_t	*conn = handle->conn;

	if (!conn->ctx) {
		ERROR("Socket not connected");

		return RLM_SQL_RECONNECT;
	}

	if (OCIStmtPrepare2(conn->ctx, &conn->query, conn->error, (const OraText *)query, strlen(query),
	           NULL, 0, OCI_NTV_SYNTAX, OCI_DEFAULT)) {
		ERROR("prepare failed in sql_query");

		return RLM_SQL_ERROR;
	}

	status = OCIStmtExecute(conn->ctx, conn->query, conn->error, 1, 0,
				NULL, NULL, OCI_COMMIT_ON_SUCCESS);

	if (status == OCI_SUCCESS) return RLM_SQL_OK;
	if (status == OCI_ERROR) {
		ERROR("execute query failed in sql_query");

		return sql_check_reconnect(handle, config);
	}

	return RLM_SQL_ERROR;
}

static sql_rcode_t sql_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t const *config, char const *query)
{
	int		status;
	char		**row;

	int		i;
	OCIParam	*param;
	OCIDefine	*define;

	ub2		dtype;
	ub2		dsize;

	sb2		*ind;

	rlm_sql_oracle_conn_t *conn = handle->conn;

	if (OCIStmtPrepare2(conn->ctx, &conn->query, conn->error, (const OraText *)query, strlen(query),
	           NULL, 0, OCI_NTV_SYNTAX, OCI_DEFAULT)) {
		ERROR("prepare failed in sql_select_query");

		return RLM_SQL_ERROR;
	}

	/*
	 *	Retrieve a single row
	 */
	status = OCIStmtExecute(conn->ctx, conn->query, conn->error, 0, 0, NULL, NULL, OCI_DEFAULT);
	if (status == OCI_NO_DATA) return RLM_SQL_OK;
	if (status != OCI_SUCCESS) {
		ERROR("query failed in sql_select_query");

		return sql_check_reconnect(handle, config);
	}

	/*
	 *	We only need to do this once per result set, because
	 *	the number of columns won't change.
	 */
	if (conn->col_count == 0) {
		conn->col_count = sql_num_fields(handle, config);

		if (conn->col_count == 0) return RLM_SQL_ERROR;
	}

	MEM(row = talloc_zero_array(conn, char*, conn->col_count + 1));
	MEM(ind = talloc_zero_array(row, sb2, conn->col_count + 1));

	for (i = 0; i < conn->col_count; i++) {
		status = OCIParamGet(conn->query, OCI_HTYPE_STMT, conn->error, (dvoid **)&param, i + 1);
		if (status != OCI_SUCCESS) {
			ERROR("OCIParamGet() failed in sql_select_query");

			goto error;
		}

		status = OCIAttrGet((dvoid*)param, OCI_DTYPE_PARAM, (dvoid*)&dtype, NULL, OCI_ATTR_DATA_TYPE,
				    conn->error);
		if (status != OCI_SUCCESS) {
			ERROR("OCIAttrGet() failed in sql_select_query");

			goto error;
		}

		dsize = MAX_DATASTR_LEN;

		/*
		 *	Use the retrieved length of dname to allocate an output buffer, and then define the output
		 *	variable (but only for char/string type columns).
		 */
		switch (dtype) {
#ifdef SQLT_AFC
		case SQLT_AFC:	/* ansii fixed char */
#endif
#ifdef SQLT_AFV
		case SQLT_AFV:	/* ansii var char */
#endif
		case SQLT_VCS:	/* var char */
		case SQLT_CHR:	/* char */
		case SQLT_STR:	/* string */
			status = OCIAttrGet((dvoid *)param, OCI_DTYPE_PARAM, (dvoid *)&dsize, NULL,
					    OCI_ATTR_DATA_SIZE, conn->error);
			if (status != OCI_SUCCESS) {
				ERROR("OCIAttrGet() failed in sql_select_query");

				goto error;
			}

			MEM(row[i] = talloc_zero_array(row, char, dsize + 1));

			break;
		case SQLT_DAT:
		case SQLT_INT:
		case SQLT_UIN:
		case SQLT_FLT:
		case SQLT_PDN:
		case SQLT_BIN:
		case SQLT_NUM:
			MEM(row[i] = talloc_zero_array(row, char, dsize + 1));

			break;
		default:
			dsize = 0;
			row[i] = NULL;
			break;
		}

		ind[i] = 0;

		/*
		 *	Grab the actual row value and write it to the buffer we allocated.
		 */
		status = OCIDefineByPos(conn->query, &define, conn->error, i + 1, (ub1 *)row[i], dsize + 1, SQLT_STR,
					(dvoid *)&ind[i], NULL, NULL, OCI_DEFAULT);

		if (status != OCI_SUCCESS) {
			ERROR("OCIDefineByPos() failed in sql_select_query");
			goto error;
		}
	}

	conn->row = row;
	conn->ind = ind;

	return RLM_SQL_OK;

 error:
	talloc_free(row);

	return RLM_SQL_ERROR;
}

static int sql_num_rows(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_oracle_conn_t *conn = handle->conn;
	ub4 rows = 0;
	ub4 size = sizeof(ub4);

	OCIAttrGet((CONST dvoid *)conn->query, OCI_HTYPE_STMT, (dvoid *)&rows, &size, OCI_ATTR_ROW_COUNT, conn->error);

	return rows;
}

static sql_rcode_t sql_fetch_row(rlm_sql_row_t *out, rlm_sql_handle_t *handle, rlm_sql_config_t const *config)
{
	int status;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	*out = NULL;

	if (!conn->ctx) {
		ERROR("Socket not connected");

		return RLM_SQL_RECONNECT;
	}

	handle->row = NULL;

	status = OCIStmtFetch(conn->query, conn->error, 1, OCI_FETCH_NEXT, OCI_DEFAULT);
	if (status == OCI_SUCCESS) {
		*out = handle->row = conn->row;

		return RLM_SQL_OK;
	}

	if (status == OCI_NO_DATA) {
		handle->row = 0;

		return RLM_SQL_NO_MORE_ROWS;
	}

	if (status == OCI_ERROR) {
		ERROR("fetch failed in sql_fetch_row");
		return sql_check_reconnect(handle, config);
	}

	return RLM_SQL_ERROR;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_oracle_conn_t *conn = handle->conn;

	/* Cancel the cursor first */
	(void) OCIStmtFetch(conn->query, conn->error, 0, OCI_FETCH_NEXT, OCI_DEFAULT);

	TALLOC_FREE(conn->row);
	conn->ind = NULL;	/* ind is a child of row */
	conn->col_count = 0;

	if (OCIStmtRelease (conn->query, conn->error, NULL, 0, OCI_DEFAULT) != OCI_SUCCESS ) {
		ERROR("OCI release failed in sql_finish_query");
		return RLM_SQL_ERROR;
	}

	return RLM_SQL_OK;
}

static sql_rcode_t sql_finish_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_oracle_conn_t *conn = handle->conn;

	if (OCIStmtRelease(conn->query, conn->error, NULL, 0, OCI_DEFAULT) != OCI_SUCCESS ) {
		ERROR("OCI release failed in sql_finish_query");
		return RLM_SQL_ERROR;
	}

	return 0;
}

static sql_rcode_t sql_finish_select_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_oracle_conn_t *conn = handle->conn;

	TALLOC_FREE(conn->row);
	conn->ind = NULL;	/* ind is a child of row */
	conn->col_count = 0;

	if (OCIStmtRelease (conn->query, conn->error, NULL, 0, OCI_DEFAULT) != OCI_SUCCESS ) {
		ERROR("OCI release failed in sql_finish_query");
		return RLM_SQL_ERROR;
	}

	return 0;
}

static int sql_affected_rows(rlm_sql_handle_t *handle, rlm_sql_config_t const *config)
{
	return sql_num_rows(handle, config);
}

/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_oracle;
rlm_sql_driver_t rlm_sql_oracle = {
	.common = {
		.name				= "sql_oracle",
		.magic				= MODULE_MAGIC_INIT,
		.inst_size			= sizeof(rlm_sql_oracle_t),
		.config				= driver_config,
		.instantiate			= mod_instantiate,
		.detach				= mod_detach
	},
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_num_fields			= sql_num_fields,
	.sql_num_rows			= sql_num_rows,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fetch_row			= sql_fetch_row,
	.sql_fields			= sql_fields,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_select_query
};
