/*
 * stats.c	Internal statistics handling.
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * @copyright 2008 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok (aland@deployingradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/client.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/stats.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/radius/defs.h>


#define EMA_SCALE (100)
#define F_EMA_SCALE (1000000)

#define FR_STATS_INIT { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 	\
				 { 0, 0, 0, 0, 0, 0, 0, 0 }}

fr_stats_t radius_auth_stats = FR_STATS_INIT;
fr_stats_t radius_acct_stats = FR_STATS_INIT;

void request_stats_final(request_t *request)
{
	if (request->counted) return;

#if 0
	if (!request->listener) return;
	if (!request->client) return;
	if (!request->packet) return;
#endif

#if 0
	if ((request->listener->type != RAD_LISTEN_NONE) &&
	    (request->listener->type != RAD_LISTEN_ACCT) &&
	    (request->listener->type != RAD_LISTEN_AUTH)) return;
#endif
	/* don't count statistic requests */
	if (request->packet->code == FR_RADIUS_CODE_STATUS_SERVER)
		return;

#undef INC_AUTH
#define INC_AUTH(_x) do { radius_auth_stats._x++;request->client->auth._x++; } while (0)

#undef INC_ACCT
#define INC_ACCT(_x) do { radius_acct_stats._x++;request->client->acct._x++; } while (0)

	/*
	 *	Update the statistics.
	 *
	 *	Note that we do NOT do this in a child thread.
	 *	Instead, we update the stats when a request is
	 *	deleted, because only the main server thread calls
	 *	this function, which makes it thread-safe.
	 */
	if (request->reply && (request->packet->code != FR_RADIUS_CODE_STATUS_SERVER)) switch (request->reply->code) {
	case FR_RADIUS_CODE_ACCESS_ACCEPT:
		INC_AUTH(total_access_accepts);

		auth_stats:
		INC_AUTH(total_responses);

		/*
		 *	FIXME: Do the time calculations once...
		 */
		fr_stats_bins(&radius_auth_stats,
			      request->packet->timestamp,
			      request->reply->timestamp);
		fr_stats_bins(&request->client->auth,
			      request->packet->timestamp,
			      request->reply->timestamp);
		break;

	case FR_RADIUS_CODE_ACCESS_REJECT:
		INC_AUTH(total_access_rejects);
		goto auth_stats;

	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
		INC_AUTH(total_access_challenges);
		goto auth_stats;

	case FR_RADIUS_CODE_ACCOUNTING_RESPONSE:
		INC_ACCT(total_responses);
		fr_stats_bins(&radius_acct_stats,
			      request->packet->timestamp,
			      request->reply->timestamp);
		break;

		/*
		 *	No response, it must have been a bad
		 *	authenticator.
		 */
	case 0:
		switch (request->packet->code) {
		case FR_RADIUS_CODE_ACCESS_REQUEST:
			if (request->reply->id == -1) {
				INC_AUTH(total_bad_authenticators);
			} else {
				INC_AUTH(total_packets_dropped);
			}
			break;


		case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
			if (request->reply->id == -1) {
				INC_ACCT(total_bad_authenticators);
			} else {
				INC_ACCT(total_packets_dropped);
			}
			break;

			default:
				break;
		}
		break;

	default:
		break;
	}

	request->counted = true;
}

/** Sort latency times into bins
 *
 * This solves the problem of attempting to keep min/max/avg latencies, whilst
 * not knowing what the polling frequency will be.
 *
 * @param[out] stats Holding monotonically increasing stats bins.
 * @param[in] start of the request.
 * @param[in] end of the request.
 */
void fr_stats_bins(fr_stats_t *stats, fr_time_t start, fr_time_t end)
{
	fr_time_delta_t	diff;
	uint32_t	delay;

	if (fr_time_lt(end, start)) return;	/* bad data */
	diff = fr_time_sub(end, start);

	if (fr_time_delta_gteq(diff, fr_time_delta_from_sec(10))) {
		stats->elapsed[7]++;
	} else {
		int i;
		uint32_t cmp;

		delay = fr_time_delta_to_usec(diff);

		cmp = 10;
		for (i = 0; i < 7; i++) {
			if (delay < cmp) {
				stats->elapsed[i]++;
				break;
			}
			cmp *= 10;
		}
	}
}
