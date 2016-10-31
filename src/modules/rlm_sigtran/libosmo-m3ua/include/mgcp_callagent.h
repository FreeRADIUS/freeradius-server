/*
 * (C) 2012 by Holger Hans Peter Freyther
 * (C) 2012 by On-Waves
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

#ifndef mgcp_callagent_h
#define mgcp_callagent_h

#include <osmocom/core/write_queue.h>

struct mgcp_callagent {
	struct osmo_wqueue queue;
	void (*read_cb)(struct mgcp_callagent *, struct msgb *msg);
};

int mgcp_create_port(struct mgcp_callagent *agent);
void mgcp_forward(struct mgcp_callagent *agent, const uint8_t *data,
		unsigned int length);

#endif
