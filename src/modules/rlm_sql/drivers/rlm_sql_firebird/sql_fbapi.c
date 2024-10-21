/*
 * sql_fbapi.c Part of Firebird rlm_sql driver
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
 * @copyright 2006 The FreeRADIUS server project
 * @copyright 2006 Vitaly Bodzhgua (vitaly@eastera.net)
 */

RCSID("$Id$")

#include "sql_fbapi.h"

#include <stdarg.h>

static void fb_dpb_add_str(char **dpb, char name, char const *value)
{
	int l;

	if (!value) return;

	l = strlen(value);

	*(*dpb)++= name;
	*(*dpb)++= (char) l;

	memmove(*dpb, value, l);

	*dpb += l;
}

static void fb_set_sqlda(XSQLDA *sqlda) {
	int i;

	for (i = 0; i < sqlda->sqld; i++) {
		if ((sqlda->sqlvar[i].sqltype & ~1) == SQL_VARYING) {
			MEM(sqlda->sqlvar[i].sqldata = talloc_array(sqlda, char, sqlda->sqlvar[i].sqllen + sizeof(short)));
		} else {
			MEM(sqlda->sqlvar[i].sqldata = talloc_array(sqlda, char, sqlda->sqlvar[i].sqllen));
		}

		if (sqlda->sqlvar[i].sqltype & 1) {
			MEM(sqlda->sqlvar[i].sqlind = talloc(sqlda, short));
		} else {
			sqlda->sqlvar[i].sqlind = 0;
		}
	}
}

DIAG_OFF(deprecated-declarations)
int fb_error(rlm_sql_firebird_conn_t *conn)
{
	ISC_SCHAR error[2048];	/* Only 1024 bytes should be written to this, but were playing it extra safe */
	ISC_STATUS *pstatus;

	conn->sql_code = 0;

	/*
	 *	Free any previous errors.
	 */
	TALLOC_FREE(conn->error);

	/*
	 *	Check if the status array contains an error
	 */
	if (IS_ISC_ERROR(conn->status)) {
		conn->sql_code = isc_sqlcode(conn->status);

		if (conn->sql_code == DUPLICATE_KEY_SQL_CODE) return conn->sql_code;

		/*
		 *	pstatus is a pointer into the status array which is
		 *	advanced by isc_interprete. It's initialised to the
		 *	first element of the status array.
		 */
		pstatus = &conn->status[0];

		/*
		 *	It's deprecated because the size of the buffer isn't
		 *	passed and this isn't safe. But as were passing a very
		 *	large buffer it's unlikely this will be an issue, and
		 *	allows us to maintain compatibility with the interbase
		 *	API.
		 */
		isc_interprete(&error[0], &pstatus);
		conn->error = talloc_typed_asprintf(conn, "%s. ", &error[0]);

		while (isc_interprete(&error[0], &pstatus)) {
			conn->error = talloc_asprintf_append(conn->error, "%s. ", &error[0]);
		}

		memset(&conn->status, 0, sizeof(conn->status));
	}

	return conn->sql_code;
}
DIAG_ON(deprecated-declarations)

void fb_free_sqlda(XSQLDA *sqlda)
{
	int i;
	for (i = 0; i < sqlda->sqld; i++) {
		free(sqlda->sqlvar[i].sqldata);
		free(sqlda->sqlvar[i].sqlind);
	}
	sqlda->sqld = 0;
}



//Macro for NULLs check
#define IS_NULL(x) (x->sqltype & 1) && (*x->sqlind < 0)

//Structure to manage a SQL_VARYING Firebird's data types
typedef struct {
	 short vary_length;
	 char vary_string[1];
} VARY;

//function fb_store_row based on fiebird's apifull example
sql_rcode_t fb_store_row(rlm_sql_firebird_conn_t *conn)
{
	int		dtype, i, nulls = 0;
	struct		tm times;
	ISC_QUAD	bid;
	XSQLVAR		*var;
	VARY		*vary;

	conn->row = talloc_zero_array(conn, char *, conn->sqlda_out->sqld + 1);

	for (i = 0, var = conn->sqlda_out->sqlvar; i < conn->sqlda_out->sqld; var++, i++) {
		if (IS_NULL(var)) {
			nulls++;
			continue;
		}

		dtype = var->sqltype & ~1;

		switch (dtype) {
		case SQL_TEXT:
			conn->row[i] = talloc_bstrndup(conn->row, var->sqldata, var->sqllen);
			break;

		case SQL_VARYING:
			vary = (VARY *)var->sqldata;
			conn->row[i] = talloc_bstrndup(conn->row, vary->vary_string, vary->vary_length);
			break;

		case SQL_FLOAT:
			conn->row[i] = talloc_typed_asprintf(conn->row, "%g", *(double ISC_FAR *) (var->sqldata));
			break;

		case SQL_SHORT:
		case SQL_LONG:
		case SQL_INT64:
		{
			ISC_INT64 value = 0;
			short dscale = 0;

			switch (dtype) {
			case SQL_SHORT:
				value = (ISC_INT64) *(short *)var->sqldata;
				break;

			case SQL_LONG:
				value = (ISC_INT64) *(int *)var->sqldata;
				break;

			case SQL_INT64:
				value = (ISC_INT64) *(ISC_INT64 *)var->sqldata;
				break;
			}
			dscale = var->sqlscale;

			if (dscale < 0) {
				ISC_INT64 tens;
				short j;

				tens = 1;
				for (j = 0; j > dscale; j--) {
					tens *= 10;
				}

				if (value >= 0) {
					conn->row[i] = talloc_typed_asprintf(conn->row, "%lld.%0*lld",
						 (ISC_INT64) value / tens,
						 -dscale,
						 (ISC_INT64) value % tens);
				} else if ((value / tens) != 0) {
					conn->row[i] = talloc_typed_asprintf(conn->row, "%lld.%0*lld",
						 (ISC_INT64) (value / tens),
						 -dscale,
						 (ISC_INT64) -(value % tens));
				} else {
					conn->row[i] = talloc_typed_asprintf(conn->row, "%s.%0*lld",
						 "-0", -dscale, (ISC_INT64) - (value % tens));
				}
			} else if (dscale) {
				conn->row[i] = talloc_typed_asprintf(conn->row, "%lld%0*d", (ISC_INT64) value, dscale, 0);
			} else {
				conn->row[i] = talloc_typed_asprintf(conn->row, "%lld", (ISC_INT64) value);
			}
		}
			break;

		case SQL_D_FLOAT:
		case SQL_DOUBLE:
			conn->row[i] = talloc_typed_asprintf(conn->row, "%f", *(double ISC_FAR *) (var->sqldata));
			break;

		case SQL_TIMESTAMP:
			isc_decode_timestamp((ISC_TIMESTAMP ISC_FAR *)var->sqldata, &times);
			conn->row[i] = talloc_typed_asprintf(conn->row, "%04d-%02d-%02d %02d:%02d:%02d.%04d",
				 times.tm_year + 1900,
				 times.tm_mon + 1,
				 times.tm_mday,
				 times.tm_hour,
				 times.tm_min,
				 times.tm_sec,
				 ((ISC_TIMESTAMP *)var->sqldata)->timestamp_time % 10000);
			break;

		case SQL_TYPE_DATE:
			isc_decode_sql_date((ISC_DATE ISC_FAR *)var->sqldata, &times);
			conn->row[i] = talloc_typed_asprintf(conn->row, "%04d-%02d-%02d",
				 times.tm_year + 1900,
				 times.tm_mon + 1,
				 times.tm_mday);
			break;

		case SQL_TYPE_TIME:
			isc_decode_sql_time((ISC_TIME ISC_FAR *)var->sqldata, &times);
			conn->row[i] = talloc_typed_asprintf(conn->row, "%02d:%02d:%02d.%04d",
				 times.tm_hour,
				 times.tm_min,
				 times.tm_sec,
				 (*((ISC_TIME *)var->sqldata)) % 10000);
			break;

		case SQL_BLOB:
		case SQL_ARRAY:
			/* Print the blob id on blobs or arrays */
			bid = *(ISC_QUAD ISC_FAR *) var->sqldata;
			conn->row[i] = talloc_typed_asprintf(conn->row, "%08" ISC_LONG_FMT "x:%08" ISC_LONG_FMT "x",
				 bid.gds_quad_high, bid.gds_quad_low);
			break;
		}
	}

	/*
	 *	An "UPDATE ... RETURNING" which updated nothing actually returns a row
	 *	with all fields set to NULL.  This is effectively no rows.
	 */
	if (nulls == i) return RLM_SQL_NO_MORE_ROWS;

	return RLM_SQL_OK;
}

int fb_connect(rlm_sql_firebird_conn_t *conn, rlm_sql_config_t const *config)
{
	char		*p, *buff = NULL;
	char const	*database;
	uint8_t		timeout;

	conn->dpb_len = 7;
	if (config->sql_login) conn->dpb_len+= strlen(config->sql_login) + 2;

	if (config->sql_password) conn->dpb_len += strlen(config->sql_password) + 2;

	MEM(conn->dpb = talloc_array(conn, char, conn->dpb_len));
	p = conn->dpb;

	*conn->dpb++= isc_dpb_version1;

	/*
	 *	Except for the version above, all Database Parameter Buffer options
	 *	are LTV format, built from:
	 *	 - 1 byte option code
	 *	 - 1 byte length of value
	 *	 - 1 or more bytes of value.  Integers are lsb first.
	 */
	*conn->dpb++= isc_dpb_num_buffers;
	*conn->dpb++= 1;
	*conn->dpb++= 90;

	timeout = fr_time_delta_to_sec(config->trunk_conf.conn_conf->connection_timeout);
	*conn->dpb++= isc_dpb_connect_timeout;
	*conn->dpb++= 1;
	*conn->dpb++= timeout;

	fb_dpb_add_str(&conn->dpb, isc_dpb_user_name, config->sql_login);
	fb_dpb_add_str(&conn->dpb, isc_dpb_password, config->sql_password);

	conn->dpb = p;

	/*
	 *	Check if database and server in the form of server:database.
	 *	If config->sql_server contains ':', then config->sql_db
	 *	parameter ignored.
	 */
	if (strchr(config->sql_server, ':')) {
		database = config->sql_server;
	} else {
		/*
		 *	Make database and server to be in the form
		 *	of server:database
		 */
		database = buff = talloc_asprintf(NULL, "%s:%s", config->sql_server, config->sql_db);
	}
	DEBUG2("rlm_sql_firebird: Connecting to %s", database);
	isc_attach_database(conn->status, 0, database, &conn->dbh,
			    conn->dpb_len, conn->dpb);
	talloc_free(buff);

	return fb_error(conn);
}


int fb_fetch(rlm_sql_firebird_conn_t *conn)
{
	long fetch_stat;
	if (conn->statement_type!= isc_info_sql_stmt_select) return 100;

	fetch_stat = isc_dsql_fetch(conn->status, &conn->stmt,
				    SQL_DIALECT_V6, conn->sqlda_out);
	if (fetch_stat) {
		if (fetch_stat!= 100L) {
			fb_error(conn);
		} else {
			conn->sql_code = 0;
		}
	}

	return fetch_stat;
}

static int fb_prepare(rlm_sql_firebird_conn_t *conn, char const *query)
{
	static char stmt_info[] = { isc_info_sql_stmt_type };
	char info_buffer[128];
	short l;

	if (!conn->trh) {
		isc_start_transaction(conn->status, &conn->trh, 1, &conn->dbh,
				      conn->tpb_len, conn->tpb);
		if (!conn->trh) return -4;
	}

	if (!conn->stmt) {
		isc_dsql_allocate_statement(conn->status, &conn->dbh,
					    &conn->stmt);
		if (!conn->stmt) return -1;
	}

	isc_dsql_prepare(conn->status, &conn->trh, &conn->stmt, 0, query,
			 conn->sql_dialect, conn->sqlda_out);
	if (IS_ISC_ERROR(conn->status)) return -2;

	if (conn->sqlda_out->sqln < conn->sqlda_out->sqld) {
		conn->sqlda_out = (XSQLDA ISC_FAR *) _talloc_realloc_array(conn, conn->sqlda_out, 1,
							     XSQLDA_LENGTH(conn->sqlda_out->sqld), "XSQLDA");
		conn->sqlda_out->sqln = conn->sqlda_out->sqld;
		isc_dsql_describe(conn->status, &conn->stmt, SQL_DIALECT_V6,
				  conn->sqlda_out);

		if (IS_ISC_ERROR(conn->status)) return -3;
	}
	/*
	 *	Get statement type
	 */
	isc_dsql_sql_info(conn->status, &conn->stmt, sizeof(stmt_info),
			  stmt_info, sizeof(info_buffer), info_buffer);
	if (IS_ISC_ERROR(conn->status)) return -4;

	l = (short) isc_vax_integer((char ISC_FAR *) info_buffer + 1, 2);
	conn->statement_type = isc_vax_integer((char ISC_FAR *) info_buffer + 3, l);

	if (conn->sqlda_out->sqld) fb_set_sqlda(conn->sqlda_out); //set out sqlda

	return 0;
}


int fb_sql_query(rlm_sql_firebird_conn_t *conn, char const *query) {
	if (fb_prepare(conn, query)) return fb_error(conn);

	switch (conn->statement_type) {
		case isc_info_sql_stmt_exec_procedure:
			isc_dsql_execute2(conn->status, &conn->trh, &conn->stmt,
					  SQL_DIALECT_V6, 0, conn->sqlda_out);
			break;

		default:
			isc_dsql_execute(conn->status, &conn->trh, &conn->stmt,
					 SQL_DIALECT_V6, 0);
			break;
	}
	return fb_error(conn);
}

int fb_affected_rows(rlm_sql_firebird_conn_t *conn) {
	static char count_info[] = {isc_info_sql_records};
	char info_buffer[128];
	char *p ;
	int affected_rows = -1;

	if (!conn->stmt) return -1;

	isc_dsql_sql_info(conn->status, &conn->stmt,
			  sizeof (count_info), count_info,
			  sizeof (info_buffer), info_buffer);

	if (IS_ISC_ERROR(conn->status)) return fb_error(conn);

	p = info_buffer + 3;
	while (*p != isc_info_end) {
		short len;
		len = (short)isc_vax_integer(++p, 2);
		p += 2;

		affected_rows = isc_vax_integer(p, len);
		if (affected_rows > 0) break;
		p += len;
	}
	return affected_rows;
}

void fb_free_statement(rlm_sql_firebird_conn_t *conn) {
	if (conn->stmt) {
		isc_dsql_free_statement(conn->status, &conn->stmt, DSQL_drop);
		conn->stmt = 0;
	}
}

int fb_rollback(rlm_sql_firebird_conn_t *conn) {
	conn->sql_code = 0;
	if (conn->trh)  {
		isc_rollback_transaction(conn->status, &conn->trh);
		if (IS_ISC_ERROR(conn->status)) return fb_error(conn);
	}
	return conn->sql_code;
}

int fb_commit(rlm_sql_firebird_conn_t *conn) {
	conn->sql_code = 0;
	if (conn->trh)  {
		isc_commit_transaction(conn->status, &conn->trh);
		if (IS_ISC_ERROR(conn->status)) {
			fb_error(conn);
			ERROR("Fail to commit. Error: %s. Try to rollback.", conn->error);
			return fb_rollback(conn);
		}
	}
	return conn->sql_code;
}
