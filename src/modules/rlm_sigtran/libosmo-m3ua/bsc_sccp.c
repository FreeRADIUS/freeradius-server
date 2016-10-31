/* routines to track connections */
/*
 * (C) 2010-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2011 by On-Waves
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "bsc_sccp.h"
#include "bsc_data.h"

#include <cellmgr_debug.h>
#include <ss7_application.h>
#include <ss7_application.h>

#include <osmocom/core/talloc.h>

#include <string.h>

struct active_sccp_con *find_con_by_dest_ref(struct ss7_application *fw, struct sccp_source_reference *ref)
{
	struct active_sccp_con *con;

	if (!ref) {
		LOGP(DINP, LOGL_ERROR, "Dest Reference is NULL. No connection found.\n");
		return NULL;
	}

	llist_for_each_entry(con, &fw->sccp_connections, entry) {
		if (memcmp(&con->dst_ref, ref, sizeof(*ref)) == 0)
			return con;
	}

	LOGP(DINP, LOGL_ERROR, "No connection fond with: 0x%x as dest\n", sccp_src_ref_to_int(ref));
	return NULL;
}


struct active_sccp_con *find_con_by_src_ref(struct ss7_application *fw, struct sccp_source_reference *src_ref)
{
	struct active_sccp_con *con;

	/* it is quite normal to not find this one */
	if (!src_ref)
		return NULL;

	llist_for_each_entry(con, &fw->sccp_connections, entry) {
		if (memcmp(&con->src_ref, src_ref, sizeof(*src_ref)) == 0)
			return con;
	}

	return NULL;
}

struct active_sccp_con *find_con_by_src_dest_ref(struct ss7_application *fw,
						 struct sccp_source_reference *src_ref,
						 struct sccp_source_reference *dst_ref)
{
	struct active_sccp_con *con;

	llist_for_each_entry(con, &fw->sccp_connections, entry) {
		if (memcmp(src_ref, &con->src_ref, sizeof(*src_ref)) == 0 &&
		    memcmp(dst_ref, &con->dst_ref, sizeof(*dst_ref)) == 0) {
			return con;
		}
	}

	return NULL;
}

unsigned int sls_for_src_ref(struct ss7_application *fw, struct sccp_source_reference *ref)
{
	struct active_sccp_con *con;

	con = find_con_by_src_ref(fw, ref);
	if (!con)
		return -1;
	return con->sls;
}

/*
 * remove data
 */
void free_con(struct active_sccp_con *con)
{
	llist_del(&con->entry);
	osmo_timer_del(&con->rlc_timeout);
	talloc_free(con);
}

