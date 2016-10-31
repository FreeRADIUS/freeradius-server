/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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
#ifndef bssap_sccp_h
#define bssap_sccp_h

#include <stdint.h>
#include <osmocom/sccp/sccp_types.h>

struct msgb *create_clear_command(struct sccp_source_reference *dest_ref);
struct msgb *create_sccp_rlsd(struct sccp_source_reference *src_ref, struct sccp_source_reference *dst);
struct msgb *create_sccp_rlc(struct sccp_source_reference *src_ref, struct sccp_source_reference *dst);
struct msgb *create_sccp_refuse(struct sccp_source_reference *dest_ref);
struct msgb *create_reset();

#endif
