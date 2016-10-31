/* (C) 2015 by Holger Hans Peter Freyther
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "sctp_m3ua.h"

/*
 * Conversion
 */
const char *m3ua_traffic_mode_name(uint32_t mode)
{
	switch (mode) {
	case 1:
		return "override";
	case 2:
		return "loadshare";
	case 3:
		return "broadcast";
	}
	abort();
}

uint32_t m3ua_traffic_mode_num(const char *name)
{
	if (name[0] == 'o')
		return 1;
	if (name[0] == 'l')
		return 2;
	if (name[0] == 'b')
		return 3;
	abort();
}

