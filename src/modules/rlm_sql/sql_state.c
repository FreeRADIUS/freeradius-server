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
 * @file sql_state.c
 * @brief Implements sql_state matching and categorisation
 *
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "rlm_sql.h"

/** These are standard, universal, error classes which all SQL servers should produce
 *
 * @note Only vague descriptions of these errors were available when deciding return codes.
 *	If anyone wishes to change the classification of any of these errors, please send
 *	a pull request.
 */
static sql_state_entry_t sql_2011_classes[] = {
	{ "00", "Successful completion",					RLM_SQL_OK },
	{ "01", "Warning",							RLM_SQL_OK },
	{ "02", "No data",							RLM_SQL_NO_MORE_ROWS },
	{ "07", "Dynamic SQL error",						RLM_SQL_ERROR },
	{ "08", "Connection exception",						RLM_SQL_RECONNECT },
	{ "09", "Triggered action exception",					RLM_SQL_ERROR },
	{ "0A", "Feature not supported",					RLM_SQL_ERROR },
	{ "0D", "Invalid target type specification",				RLM_SQL_ERROR },
	{ "0E", "Invalid schema name list specification",			RLM_SQL_ERROR },
	{ "0F", "Locator exception",						RLM_SQL_ERROR },
	{ "0K", "Resignal when handler not active",				RLM_SQL_ERROR },
	{ "0L", "Invalid grantor",						RLM_SQL_ERROR },
	{ "0M", "Invalid sql-invoked procedure reference",			RLM_SQL_ERROR },
	{ "0N", "SQL/XML mapping error",					RLM_SQL_ERROR },
	{ "0P", "Invalid role specification",					RLM_SQL_ERROR },
	{ "0S", "Invalid transform group name specification",			RLM_SQL_ERROR },
	{ "0T", "Target table disagrees with cursor specification",		RLM_SQL_ERROR },
	{ "0V", "Attempt to assign to ordering column",				RLM_SQL_ERROR },
	{ "0W", "Prohibited statement encountered during trigger execution",	RLM_SQL_ERROR },
	{ "0X", "Invalid foreign server specification",				RLM_SQL_ERROR },
	{ "0Y", "Pass-through specific condition",				RLM_SQL_ERROR },
	{ "0Z", "Diagnostics exception",					RLM_SQL_ERROR },
	{ "20", "Case not found",						RLM_SQL_ERROR },
	{ "21", "Cardinality violation",					RLM_SQL_ERROR },
	{ "22", "Data exception",						RLM_SQL_QUERY_INVALID },
	{ "23", "Integrity constraint violation",				RLM_SQL_ALT_QUERY },
	{ "24", "Invalid cursor state",						RLM_SQL_ERROR },
	{ "25", "Invalid transaction state",					RLM_SQL_ERROR },
	{ "26", "Invalid sql statement name",					RLM_SQL_QUERY_INVALID },
	{ "27", "Triggered data changed violation",				RLM_SQL_ERROR },
	{ "28", "Invalid authorization specification",				RLM_SQL_ERROR },
	{ "2B", "Dependent privilege descriptions still exist",			RLM_SQL_ERROR },
	{ "2C", "Invalid character set name",					RLM_SQL_ERROR },
	{ "2D", "Invalid transaction termination",				RLM_SQL_ERROR },
	{ "2E", "Invalid connection name",					RLM_SQL_ERROR },
	{ "2F", "SQL routine exception",					RLM_SQL_ERROR },
	{ "2H", "Invalid collation name",					RLM_SQL_ERROR },
	{ "30", "Invalid sql statement name",					RLM_SQL_ERROR },
	{ "33", "Invalid sql descriptor name",					RLM_SQL_ERROR },
	{ "34", "Invalid cursor name",						RLM_SQL_QUERY_INVALID },
	{ "35", "Invalid condition number",					RLM_SQL_ERROR },
	{ "36", "Cursor sensitivity exception",					RLM_SQL_ERROR },
	{ "38", "External routine exception",					RLM_SQL_ERROR },
	{ "39", "External routine invocation exception",			RLM_SQL_ERROR },
	{ "3B", "Savepoint exception",						RLM_SQL_ERROR },
	{ "3C", "Ambiguous cursor name",					RLM_SQL_ERROR },
	{ "3D", "Invalid catalog name",						RLM_SQL_ERROR },
	{ "3F", "Invalid schema name",						RLM_SQL_ERROR },
	{ "40", "Transaction rollback",						RLM_SQL_ERROR },
	{ "42", "Syntax error",							RLM_SQL_QUERY_INVALID },
	{ "44", "With check option violation",					RLM_SQL_ERROR },
	{ "45", "Unhandled user-defined exception",				RLM_SQL_ERROR },
	{ "46", "Java DDL",							RLM_SQL_ERROR },
	{ "HV", "FDW Error",							RLM_SQL_ERROR },
	{ "HY", "CLI-Specific Condition",					RLM_SQL_ERROR },
	{ "HZ", "RDA",								RLM_SQL_ERROR },
	{ NULL, NULL,								RLM_SQL_OK }
};

/** Allocate a sql_state trie, and insert the initial set of entries
 *
 * @param[in] ctx	to allocate states in.
 * @return
 *	- SQL state trie on success.
 *	- NULL on failure.
 */
fr_trie_t *sql_state_trie_alloc(TALLOC_CTX *ctx)
{
	fr_trie_t *states;

	MEM(states = fr_trie_alloc(ctx));

	if (sql_state_entries_from_table(states, sql_2011_classes) < 0) {
		talloc_free(states);
		return NULL;
	}

	return states;
}

/** Insert the contents of a state table into the state trie
 *
 * @param[in] states	Trie of states.
 * @param[in] table	to insert.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int sql_state_entries_from_table(fr_trie_t *states, sql_state_entry_t const table[])
{
	sql_state_entry_t const	*entry;

	for (entry = table; entry->sql_state; entry++) {
		size_t	len = strlen(entry->sql_state) * 8;
		int	ret;

		fr_trie_remove(states, entry->sql_state, len);	/* Remove any old entries */
		ret = fr_trie_insert(states, entry->sql_state, len, entry);
		if (ret < 0) {
			DEBUG("Failed inserting state: %s", fr_strerror());
		}
		if (!fr_cond_assert(ret == 0)) return -1;
	}

	return 0;
}

/** Insert the contents of a CONF_SECTION into the state trie
 *
 * The attribute side of the CONF_PAIR specifies the sqlclass and the value specifies the error code.
 *
 * @param[in] states	Trie of states.
 * @param[in] cs	Containing overrides to define new sql state entries or change existing ones.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int sql_state_entries_from_cs(fr_trie_t *states, CONF_SECTION *cs)
{
	CONF_PAIR *cp = NULL;

	while ((cp = cf_pair_find_next(cs, cp, NULL))) {
		char const		*state;
		size_t			len;
		sql_rcode_t		rcode;
		sql_state_entry_t	*entry;

		state = cf_pair_attr(cp);
		len = strlen(state) * 8;
		if (len < 2) {
			cf_log_err(cp, "Expected state to have a length between 2-5 chars, got %zu", len);
			return -1;
		}

		/*
		 *	Resolve value to sql_rcode_t
		 */
		if (cf_pair_in_table((int32_t *)&rcode, sql_rcode_table, sql_rcode_table_len, cp) < 0) return -1;/* Logs own error */

		/*
		 *	No existing match, create a new entry
		 */
		entry = fr_trie_match(states, state, len );
		if (!entry) {
			MEM(entry = talloc(states, sql_state_entry_t));
			entry->sql_state = talloc_strdup(entry, state);
			entry->meaning = "USER DEFINED";
			entry->rcode = rcode;
			(void) fr_trie_insert(states, state, len, entry);
		} else {
			entry->rcode = rcode;	/* Override previous sql rcode */
		}

		cf_pair_mark_parsed(cp);		/* Make sure it doesn't emit a warning later */
	}

	return 0;
}

/** Lookup an SQL state based on an error code returned from the SQL server or client library
 *
 * @param[in] states	Trie of states.
 * @param[in] sql_state	to lookup.
 * @return
 *	- An #sql_state_entry_t with the #sql_rcode_t associated with the sql state.
 *	- NULL if no entry exists.
 */
sql_state_entry_t const *sql_state_entry_find(fr_trie_t const *states, char const *sql_state)
{
	return fr_trie_lookup(states, sql_state, strlen(sql_state) * 8);
}
