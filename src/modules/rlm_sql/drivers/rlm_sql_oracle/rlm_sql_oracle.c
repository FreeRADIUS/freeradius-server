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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  David Kerry <davidk@snti.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

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

typedef struct rlm_sql_oracle_conn_t {
	OCIEnv		*env;
	OCIStmt		*query;
	OCIError	*error;
	OCISvcCtx	*ctx;
	sb2		*ind;
	char		**row;
	int		id;
	int		col_count;	//!< Number of columns associated with the result set
	struct timeval	tv;
} rlm_sql_oracle_conn_t;

#define	MAX_DATASTR_LEN	64

/** Write the last Oracle error out to a buffer
 *
 * @param out Where to write the error (should be at least 512 bytes).
 * @param outlen The length of the error buffer.
 * @param handle sql handle.
 * @param config Instance config.
 * @return 0 on success, -1 if there was no error.
 */
static int sql_prints_error(char *out, size_t outlen, rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	sb4			errcode = 0;
	rlm_sql_oracle_conn_t	*conn = handle->conn;

	rad_assert(conn);

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
 * @return number of errors written to the sql_log_entry array.
 */
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
		        rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	char errbuff[512];
	int ret;

	rad_assert(outlen > 0);

	ret = sql_prints_error(errbuff, sizeof(errbuff), handle, config);
	if (ret < 0) return 0;

	out[0].type = L_ERR;
	out[0].msg = talloc_strdup(ctx, errbuff);

	return 1;
}

static int sql_check_error(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	char errbuff[512];

	if (sql_prints_error(errbuff, sizeof(errbuff), handle, config) < 0) goto unknown;

	if (strstr(errbuff, "ORA-03113") || strstr(errbuff, "ORA-03114")) {
		ERROR("rlm_sql_oracle: OCI_SERVER_NOT_CONNECTED");
		return RLM_SQL_RECONNECT;
	}

unknown:
	ERROR("rlm_sql_oracle: OCI_SERVER_NORMAL");
	return -1;
}

static int _sql_socket_destructor(rlm_sql_oracle_conn_t *conn)
{
	if (conn->ctx) OCILogoff(conn->ctx, conn->error);
	if (conn->query) OCIHandleFree((dvoid *)conn->query, OCI_HTYPE_STMT);
	if (conn->error) OCIHandleFree((dvoid *)conn->error, OCI_HTYPE_ERROR);
	if (conn->env) OCIHandleFree((dvoid *)conn->env, OCI_HTYPE_ENV);

	return 0;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	char errbuff[512];

	rlm_sql_oracle_conn_t *conn;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_oracle_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	/*
	 *	Initialises the oracle environment
	 */
	if (OCIEnvCreate(&conn->env, OCI_DEFAULT | OCI_THREADED, NULL, NULL, NULL, NULL, 0, NULL)) {
		ERROR("rlm_sql_oracle: Couldn't init Oracle OCI environment (OCIEnvCreate())");

		return RLM_SQL_ERROR;
	}

	/*
	 *	Allocates an error handle
	 */
	if (OCIHandleAlloc((dvoid *)conn->env, (dvoid **)&conn->error, OCI_HTYPE_ERROR, 0, NULL)) {
		ERROR("rlm_sql_oracle: Couldn't init Oracle ERROR handle (OCIHandleAlloc())");

		return RLM_SQL_ERROR;
	}

	/*
	 *	Allocate handles for select and update queries
	 */
	if (OCIHandleAlloc((dvoid *)conn->env, (dvoid **)&conn->query, OCI_HTYPE_STMT, 0, NULL)) {
		ERROR("rlm_sql_oracle: Couldn't init Oracle query handles: %s",
		      (sql_prints_error(errbuff, sizeof(errbuff), handle, config) == 0) ? errbuff : "unknown");

		return RLM_SQL_ERROR;
	}

	/*
	 *	Login to the oracle server
	 */
	if (OCILogon(conn->env, conn->error, &conn->ctx,
		     (OraText const *)config->sql_login, strlen(config->sql_login),
		     (OraText const *)config->sql_password, strlen(config->sql_password),
		     (OraText const *)config->sql_db, strlen(config->sql_db))) {
		ERROR("rlm_sql_oracle: Oracle logon failed: '%s'",
		      (sql_prints_error(errbuff, sizeof(errbuff), handle, config) == 0) ? errbuff : "unknown");

		return RLM_SQL_ERROR;
	}

	return RLM_SQL_OK;
}

static int sql_num_fields(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	int count;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	/* get the number of columns in the select list */
	if (OCIAttrGet((dvoid *)conn->query, OCI_HTYPE_STMT, (dvoid *)&count, NULL, OCI_ATTR_PARAM_COUNT,
		       conn->error)) return -1;

	return count;
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, rlm_sql_config_t *config)
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
			ERROR("rlm_sql_oracle: OCIParamGet(OCI_HTYPE_STMT) failed in sql_fields()");
		error:
			talloc_free(names);

			return RLM_SQL_ERROR;
		}

		status = OCIAttrGet((dvoid **)param, OCI_DTYPE_PARAM, &pcol_name, &pcol_size,
				    OCI_ATTR_NAME, conn->error);
		if (status != OCI_SUCCESS) {
			ERROR("rlm_sql_oracle: OCIParamGet(OCI_ATTR_NAME) failed in sql_fields()");

			goto error;
		}

		names[i] = (char const *)pcol_name;
	}

	*out = names;

	return RLM_SQL_OK;
}

static sql_rcode_t sql_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query)
{
	int status;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	OraText *oracle_query;

	memcpy(&oracle_query, &query, sizeof(oracle_query));

	if (!conn->ctx) {
		ERROR("rlm_sql_oracle: Socket not connected");

		return RLM_SQL_RECONNECT;
	}

	if (OCIStmtPrepare(conn->query, conn->error, oracle_query, strlen(query),
			   OCI_NTV_SYNTAX, OCI_DEFAULT)) {
		ERROR("rlm_sql_oracle: prepare failed in sql_query");

		return RLM_SQL_ERROR;
	}

	status = OCIStmtExecute(conn->ctx, conn->query, conn->error, 1, 0,
				NULL, NULL, OCI_COMMIT_ON_SUCCESS);

	if (status == OCI_SUCCESS) return RLM_SQL_OK;
	if (status == OCI_ERROR) {
		ERROR("rlm_sql_oracle: execute query failed in sql_query");

		return sql_check_error(handle, config);
	}

	return RLM_SQL_ERROR;
}

static sql_rcode_t sql_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query)
{
	int		status;
	char		**row;

	int		i;
	OCIParam	*param;
	OCIDefine	*define;

	ub2		dtype;
	ub2		dsize;

	sb2		*ind;

	OraText 	*oracle_query;

	rlm_sql_oracle_conn_t *conn = handle->conn;

	memcpy(&oracle_query, &query, sizeof(oracle_query));

	if (OCIStmtPrepare(conn->query, conn->error, oracle_query, strlen(query), OCI_NTV_SYNTAX,
			   OCI_DEFAULT)) {
		ERROR("rlm_sql_oracle: prepare failed in sql_select_query");

		return RLM_SQL_ERROR;
	}

	/*
	 *	Retrieve a single row
	 */
	status = OCIStmtExecute(conn->ctx, conn->query, conn->error, 0, 0, NULL, NULL, OCI_DEFAULT);
	if (status == OCI_NO_DATA) return RLM_SQL_OK;
	if (status != OCI_SUCCESS) {
		ERROR("rlm_sql_oracle: query failed in sql_select_query");

		return sql_check_error(handle, config);
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
			ERROR("rlm_sql_oracle: OCIParamGet() failed in sql_select_query");

			goto error;
		}

		status = OCIAttrGet((dvoid*)param, OCI_DTYPE_PARAM, (dvoid*)&dtype, NULL, OCI_ATTR_DATA_TYPE,
				    conn->error);
		if (status != OCI_SUCCESS) {
			ERROR("rlm_sql_oracle: OCIAttrGet() failed in sql_select_query");

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
				ERROR("rlm_sql_oracle: OCIAttrGet() failed in sql_select_query");

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
			ERROR("rlm_sql_oracle: OCIDefineByPos() failed in sql_select_query");
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

static int sql_num_rows(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_oracle_conn_t *conn = handle->conn;
	ub4 rows = 0;
	ub4 size = sizeof(ub4);

	OCIAttrGet((CONST dvoid *)conn->query, OCI_HTYPE_STMT, (dvoid *)&rows, &size, OCI_ATTR_ROW_COUNT, conn->error);

	return rows;
}

static sql_rcode_t sql_fetch_row(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	int status;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	if (!conn->ctx) {
		ERROR("rlm_sql_oracle: Socket not connected");

		return RLM_SQL_RECONNECT;
	}

	handle->row = NULL;

	status = OCIStmtFetch(conn->query, conn->error, 1, OCI_FETCH_NEXT, OCI_DEFAULT);
	if (status == OCI_SUCCESS) {
		handle->row = conn->row;

		return RLM_SQL_OK;
	}

	if (status == OCI_NO_DATA) {
		handle->row = 0;

		return RLM_SQL_NO_MORE_ROWS;
	}

	if (status == OCI_ERROR) {
		ERROR("rlm_sql_oracle: fetch failed in sql_fetch_row");
		return sql_check_error(handle, config);
	}

	return RLM_SQL_ERROR;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_oracle_conn_t *conn = handle->conn;

	/* Cancel the cursor first */
	(void) OCIStmtFetch(conn->query, conn->error, 0, OCI_FETCH_NEXT, OCI_DEFAULT);

	TALLOC_FREE(conn->row);
	conn->ind = NULL;	/* ind is a child of row */
	conn->col_count = 0;

	return RLM_SQL_OK;
}

static sql_rcode_t sql_finish_query(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	return 0;
}

static sql_rcode_t sql_finish_select_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_oracle_conn_t *conn = handle->conn;

	TALLOC_FREE(conn->row);
	conn->ind = NULL;	/* ind is a child of row */
	conn->col_count = 0;

	return 0;
}

static int sql_affected_rows(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	return sql_num_rows(handle, config);
}

/* Exported to rlm_sql */
extern rlm_sql_module_t rlm_sql_oracle;
rlm_sql_module_t rlm_sql_oracle = {
	.name				= "rlm_sql_oracle",
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
