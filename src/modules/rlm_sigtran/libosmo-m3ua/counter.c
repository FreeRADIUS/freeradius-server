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

#include <counter.h>

#include <osmocom/core/utils.h>

static const struct rate_ctr_desc mtp_lset_cfg_description[] = {
	[MTP_LSET_TOTA_IN_MSG]	= { "total.in",       "Total messages in  "},
	[MTP_LSET_SCCP_IN_MSG]	= { "sccp.in",        "SCCP messages in   "},
	[MTP_LSET_IUSP_IN_MSG]	= { "isup.in",        "ISUP messages in   "},
	[MTP_LSET_TOTA_OUT_MSG]	= { "total.out",      "Total messages out "},
	[MTP_LSET_SCCP_OUT_MSG]	= { "sccp.out",       "SCCP messages out  "},
	[MTP_LSET_ISUP_OUT_MSG]	= { "isup.out",       "ISUP messages out  "},
	[MTP_LSET_TOTA_DRP_MSG] = { "total.dropped",  "Total dropped msgs "},
};

static const struct rate_ctr_desc mtp_link_cfg_description[] = {
	[MTP_LNK_IN]		= { "total.in",       "Messages in        "},
	[MTP_LNK_OUT]		= { "total.out",      "Messages out       "},
	[MTP_LNK_ERROR]		= { "total.error",    "Errors occured     "},
	[MTP_LNK_DRP]		= { "total.dropped",  "Messages dropped   "},
	[MTP_LNK_SLTM_TOUT]	= { "sltm.timeouts",  "SLTM timeouts      "},
};

static const struct rate_ctr_group_desc mtp_lset_ctrg_desc = {
	.group_name_prefix	= "mtp_lset",
	.group_description	= "MTP LinkSet",
	.num_ctr		= ARRAY_SIZE(mtp_lset_cfg_description),
	.ctr_desc		= mtp_lset_cfg_description,
};

static const struct rate_ctr_group_desc mtp_link_ctrg_desc = {
	.group_name_prefix	= "mtp_link",
	.group_description	= "MTP Link",
	.num_ctr		= ARRAY_SIZE(mtp_link_cfg_description),
	.ctr_desc		= mtp_link_cfg_description,
};

const struct rate_ctr_group_desc *mtp_link_set_rate_ctr_desc()
{
	return &mtp_lset_ctrg_desc;
}

const struct rate_ctr_group_desc *mtp_link_rate_ctr_desc()
{
	return &mtp_link_ctrg_desc;
}
