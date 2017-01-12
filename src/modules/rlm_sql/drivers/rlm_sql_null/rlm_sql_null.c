/*
 * sql_null.c		SQL Module
 *
 * Version:	$Id$
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
 * Copyright 2012  Alan DeKok <aland@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include	"rlm_sql.h"


/* Prototypes */
static sql_rcode_t sql_free_result(rlm_sql_handle_t*, rlm_sql_config_t*);

static const void *fake = "fake";

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	memcpy(&handle->conn, &fake, sizeof(handle->conn));
	return 0;
}

static sql_rcode_t sql_query(UNUSED rlm_sql_handle_t * handle,
			     UNUSED rlm_sql_config_t *config, UNUSED char const *query)
{
	return 0;
}

static int sql_num_fields(UNUSED rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	return 0;
}

static sql_rcode_t sql_select_query(UNUSED rlm_sql_handle_t *handle,
				    UNUSED rlm_sql_config_t *config, UNUSED char const *query)
{
	return 0;
}

static int sql_num_rows(UNUSED rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	return 0;
}

static sql_rcode_t sql_fetch_row(rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	handle->row = NULL;

	return RLM_SQL_NO_MORE_ROWS;
}

static sql_rcode_t sql_free_result(UNUSED rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	return 0;
}

/** Stub function for retrieving errors, should not be called
 *
 */
static size_t sql_error(UNUSED TALLOC_CTX *ctx, UNUSED sql_log_entry_t out[], UNUSED size_t outlen,
			UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	return 0;
}

static sql_rcode_t sql_finish_query(UNUSED rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	return 0;
}

static sql_rcode_t sql_finish_select_query(UNUSED rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	return 0;
}

static int sql_affected_rows(UNUSED rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	return 1;
}

/* Exported to rlm_sql */
extern rlm_sql_module_t rlm_sql_null;
rlm_sql_module_t rlm_sql_null = {
	.name				= "rlm_sql_null",
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_num_fields			= sql_num_fields,
	.sql_num_rows			= sql_num_rows,
	.sql_fetch_row			= sql_fetch_row,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_select_query,
	.sql_affected_rows		= sql_affected_rows
};
