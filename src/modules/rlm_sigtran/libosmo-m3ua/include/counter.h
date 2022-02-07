/* Counter for the Link and Link-Set */
/*
 * (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#ifndef counter_h
#define counter_h

#include <osmocom/core/rate_ctr.h>

enum {
	MTP_LSET_TOTA_IN_MSG,
	MTP_LSET_SCCP_IN_MSG,
	MTP_LSET_IUSP_IN_MSG,
	MTP_LSET_TOTA_OUT_MSG,
	MTP_LSET_TOTA_DRP_MSG,
	MTP_LSET_SCCP_OUT_MSG,
	MTP_LSET_ISUP_OUT_MSG,
};

enum {
	MTP_LNK_IN,
	MTP_LNK_OUT,
	MTP_LNK_ERROR,
	MTP_LNK_DRP,
	MTP_LNK_SLTM_TOUT,
};

const struct rate_ctr_group_desc *mtp_link_set_rate_ctr_desc(void);
const struct rate_ctr_group_desc *mtp_link_rate_ctr_desc(void);

#endif
