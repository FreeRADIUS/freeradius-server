/*
 * (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011 by On-Waves
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

#ifndef SS7_VTY_H
#define SS7_VTY_H

#include <osmocom/vty/vty.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/command.h>

enum ss7_vty_node {
	MGCP_NODE = _LAST_OSMOVTY_NODE + 1,
	TRUNK_NODE,
	VTRUNK_NODE,
	CELLMGR_NODE,
	SS7_NODE,
	LINKSETS_NODE,
	LINK_NODE,
	MSC_NODE,
	APP_NODE,
};

extern struct cmd_element cfg_description_cmd;
extern struct cmd_element cfg_no_description_cmd;


#endif
