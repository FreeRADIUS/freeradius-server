/*
 * sql_fbapi.h	Part of Firebird rlm_sql driver
 *
 * Copyright 2006  Vitaly Bodzhgua <vitaly@easteara.net>
 */

#ifndef _SQL_FBAPI_H_
#define _SQL_FBAPI_H_

#include <stdlib.h>
#include <string.h>
#include <ibase.h>

#include "radiusd.h"
#include "rlm_sql.h"

#define IS_ISC_ERROR(status)  (status[0] == 1 && status[1])

#define DEADLOCK_TRYS 2
#define DEADLOCK_SQL_CODE -913

typedef struct rlm_sql_firebird_sock {
	isc_db_handle dbh;
	isc_stmt_handle stmt;
	isc_tr_handle trh;
	ISC_STATUS status[20];
	ISC_LONG sql_code;
	XSQLDA *sqlda_out;
	int sql_dialect;
	int statement_type;
	char *tpb;
	int tpb_len;
	char *dpb;
	int dpb_len;
	char *lasterror;
	
	SQL_ROW row;
	int *row_sizes;
	int row_fcount;
	
} rlm_sql_firebird_sock;


int fb_free_result(rlm_sql_firebird_sock *sock);
int fb_lasterror(rlm_sql_firebird_sock *);
int fb_init_socket(rlm_sql_firebird_sock *sock);
int fb_connect(rlm_sql_firebird_sock * sock,SQL_CONFIG *config);
int fb_sql_query(rlm_sql_firebird_sock * sock,char *sqlstr);
int fb_fetch(rlm_sql_firebird_sock * sock);
void fb_destroy_socket(rlm_sql_firebird_sock *);
void fb_store_row(rlm_sql_firebird_sock *sock);

#endif
