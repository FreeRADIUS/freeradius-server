/* Patch Messages to and from the MSC */
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
#ifndef bss_patch_h
#define bss_patch_h

#include <osmocom/core/msgb.h>

#include <osmocom/sccp/sccp.h>

#define BSS_FILTER_RESET	1
#define BSS_FILTER_RESET_ACK	2
#define BSS_FILTER_RLSD		3
#define BSS_FILTER_RLC		4
#define BSS_FILTER_CLEAR_COMPL	5
#define BSS_FILTER_DTAP		6

#define BSS_DIR_BSC		1
#define BSS_DIR_MSC		2
#define BSS_DIR_ANY		(BSS_DIR_MSC | BSS_DIR_BSC)

struct ss7_application;

/**
 * Error is < 0
 * Success is == 0
 * Filter is > 0
 *
 * Direction...
 */
int bss_patch_filter_msg(struct ss7_application *app, struct msgb *msg, struct sccp_parse_result *result, int dir);

/*
 * Copy inpt->l2h to target->l2h but rewrite the SCCP header on the way
 */
void bss_rewrite_header_for_msc(int, struct msgb *target, struct msgb *inpt, struct sccp_parse_result *result);
int bss_rewrite_header_to_bsc(struct msgb *target, int opc, int dpc);

#endif
