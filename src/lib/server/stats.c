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

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/radius/defs.h>


#ifdef WITH_STATS

#define EMA_SCALE (100)
#define F_EMA_SCALE (1000000)

static fr_time_t start_time;
static fr_time_t hup_time;

#define FR_STATS_INIT { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 	\
				 { 0, 0, 0, 0, 0, 0, 0, 0 }}

fr_stats_t radius_auth_stats = FR_STATS_INIT;
fr_stats_t radius_acct_stats = FR_STATS_INIT;

void request_stats_final(request_t *request)
{
	if (request->master_state == REQUEST_COUNTED) return;

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
#define INC_AUTH(_x) radius_auth_stats._x++;request->client->auth._x++;

#undef INC_ACCT
#define INC_ACCT(_x) radius_acct_stats._x++;request->client->acct._x++

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

	request->master_state = REQUEST_COUNTED;
}

void radius_stats_init(int flag)
{
	if (!flag) {
		start_time = fr_time();
		hup_time = start_time; /* it's just nicer this way */
	} else {
		hup_time = fr_time();
	}
}

void radius_stats_ema(fr_stats_ema_t *ema, fr_time_t start, fr_time_t end)
{
	int64_t	tdiff;
#ifdef WITH_STATS_DEBUG
	static int	n = 0;
#endif
	if (ema->window == 0) return;

	fr_assert(fr_time_lteq(start, end));

	/*
	 *	Initialize it.
	 */
	if (ema->f1 == 0) {
		if (ema->window > 10000) ema->window = 10000;

		ema->f1 =  (2 * F_EMA_SCALE) / (ema->window + 1);
		ema->f10 = (2 * F_EMA_SCALE) / ((10 * ema->window) + 1);
	}

	tdiff = fr_time_delta_to_usec(fr_time_sub(start, end));
	tdiff *= EMA_SCALE;

	if (ema->ema1 == 0) {
		ema->ema1 = tdiff;
		ema->ema10 = tdiff;
	} else {
		int diff;

		diff = ema->f1 * (tdiff - ema->ema1);
		ema->ema1 += (diff / 1000000);

		diff = ema->f10 * (tdiff - ema->ema10);
		ema->ema10 += (diff / 1000000);
	}


#ifdef WITH_STATS_DEBUG
	DEBUG("time %d %d.%06d\t%d.%06d\t%d.%06d\n",
	      n, tdiff / PREC, (tdiff / EMA_SCALE) % USEC,
	      ema->ema1 / PREC, (ema->ema1 / EMA_SCALE) % USEC,
	      ema->ema10 / PREC, (ema->ema10 / EMA_SCALE) % USEC);
	n++;
#endif
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

#endif /* WITH_STATS */
