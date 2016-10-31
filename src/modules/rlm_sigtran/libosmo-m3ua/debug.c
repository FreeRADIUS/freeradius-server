/* cellmgr logging support code */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <cellmgr_debug.h>

#include <osmocom/core/utils.h>

/* default categories */
static const struct log_info_cat default_categories[] = {
	[DINP] = {
		.name = "DINP",
		.description = "A-bis Intput Subsystem",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSCCP] = {
		.name = "DSCCP",
		.description = "SCCP Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMSC] = {
		.name = "DMSC",
		.description = "Mobile Switching Center",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMGCP] = {
		.name = "DMGCP",
		.description = "Media Gateway Control Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DISUP] = {
		.name = "DISUP",
		.description = "ISUP",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DM2UA] = {
		.name = "DM2UA",
		.description = "M2UA handling",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DPCAP] = {
		.name = "DPCAP",
		.description = "Dump traffic",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
};

static int filter_fn(const struct log_context *ctx,
		     struct log_target *tar)
{
	return 0;
}

const struct log_info log_info = {
	.filter_fn = filter_fn,
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

