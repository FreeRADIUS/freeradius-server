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
 * Copyright 2008  The FreeRADIUS server project
 * Copyright 2008  Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#ifdef WITH_STATS

#define USEC (1000000)
#define PREC (USEC * EMA_SCALE)

#define F_EMA_SCALE (1000000)

struct timeval	radius_start_time;
struct timeval	radius_hup_time;

fr_stats_t radius_auth_stats = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#ifdef WITH_ACCOUNTING
fr_stats_t radius_acct_stats = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#endif

#ifdef WITH_PROXY
fr_stats_t proxy_auth_stats = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#ifdef WITH_ACCOUNTING
fr_stats_t proxy_acct_stats = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#endif
#endif

void request_stats_final(REQUEST *request)
{
	if (request->master_state == REQUEST_COUNTED) return;

	if ((request->listener->type != RAD_LISTEN_NONE) &&
	    (request->listener->type != RAD_LISTEN_AUTH) &&
	    (request->listener->type != RAD_LISTEN_ACCT)) return;

	/*
	 *	Update the statistics.
	 *
	 *	Note that we do NOT do this in a child thread.
	 *	Instead, we update the stats when a request is
	 *	deleted, because only the main server thread calls
	 *	this function, which makes it thread-safe.
	 */
	switch (request->reply->code) {
	case PW_AUTHENTICATION_ACK:
		radius_auth_stats.total_responses++;
		radius_auth_stats.total_access_accepts++;
		request->listener->stats.total_responses++;
		request->listener->stats.total_access_accepts++;
		if (request->client && request->client->auth) {
			request->client->auth->total_access_accepts++;
			request->client->auth->total_responses++;
		}
		break;

	case PW_AUTHENTICATION_REJECT:
		radius_auth_stats.total_responses++;
		radius_auth_stats.total_access_rejects++;
		request->listener->stats.total_responses++;
		request->listener->stats.total_access_rejects++;
		if (request->client && request->client->auth) {
			request->client->auth->total_access_rejects++;
			request->client->auth->total_responses++;
		}
		break;

	case PW_ACCESS_CHALLENGE:
		radius_auth_stats.total_responses++;
		radius_auth_stats.total_access_challenges++;
		request->listener->stats.total_responses++;
		request->listener->stats.total_access_challenges++;
		if (request->client && request->client->auth) {
			request->client->auth->total_access_challenges++;
			request->client->auth->total_responses++;
		}
		break;

#ifdef WITH_ACCOUNTING
	case PW_ACCOUNTING_RESPONSE:
		radius_acct_stats.total_responses++;
		request->listener->stats.total_responses++;
		if (request->client && request->client->acct) {
			request->client->acct->total_responses++;
		}
		break;
#endif

		/*
		 *	No response, it must have been a bad
		 *	authenticator.
		 */
	case 0:
		if (request->packet->code == PW_AUTHENTICATION_REQUEST) {
			radius_auth_stats.total_bad_authenticators++;
			request->listener->stats.total_bad_authenticators++;
			if (request->client && request->client->auth) {
				request->client->auth->total_bad_authenticators++;
			}
		}
		break;

	default:
		break;
	}

#ifdef WITH_PROXY
	if (!request->proxy || !request->proxy_listener) goto done;	/* simplifies formatting */

	switch (request->proxy->code) {
	case PW_AUTHENTICATION_REQUEST:
		proxy_auth_stats.total_requests += request->num_proxied_requests;
		request->proxy_listener->stats.total_requests += request->num_proxied_requests;
		request->home_server->stats.total_requests += request->num_proxied_requests;
		break;

#ifdef WITH_ACCOUNTING
	case PW_ACCOUNTING_REQUEST:
		proxy_acct_stats.total_requests++;
		request->proxy_listener->stats.total_requests += request->num_proxied_requests;
		request->home_server->stats.total_requests += request->num_proxied_requests;
		break;
#endif

	default:
		break;
	}

	if (!request->proxy_reply) goto done;	/* simplifies formatting */

#undef INC
#define INC(_x) proxy_auth_stats._x += request->num_proxied_responses; request->proxy_listener->stats._x += request->num_proxied_responses; request->home_server->stats._x += request->num_proxied_responses;

	switch (request->proxy_reply->code) {
	case PW_AUTHENTICATION_ACK:
		INC(total_responses);
		INC(total_access_accepts);
		break;

	case PW_AUTHENTICATION_REJECT:
		INC(total_responses);
		INC(total_access_rejects);
		break;

	case PW_ACCESS_CHALLENGE:
		INC(total_responses);
		INC(total_access_challenges);
		break;

#ifdef WITH_ACCOUNTING
	case PW_ACCOUNTING_RESPONSE:
		radius_acct_stats.total_responses++;
		request->proxy_listener->stats.total_responses++;
		request->home_server->stats.total_responses++;
		break;
#endif

	default:
		proxy_auth_stats.total_unknown_types++;
		request->proxy_listener->stats.total_unknown_types++;
		request->home_server->stats.total_unknown_types++;
		break;
	}

 done:
#endif /* WITH_PROXY */

	request->master_state = REQUEST_COUNTED;
}

void radius_stats_init(int flag)
{
	if (!flag) {
		gettimeofday(&radius_start_time, NULL);
		radius_hup_time = radius_start_time; /* it's just nicer this way */
	} else {
		gettimeofday(&radius_hup_time, NULL);
	}
}

void radius_stats_ema(fr_stats_ema_t *ema,
		      struct timeval *start, struct timeval *end)
{
	int micro;
	time_t tdiff;
#ifdef WITH_STATS_DEBUG
	static int n = 0;
#endif
	if (ema->window == 0) return;

	rad_assert(start->tv_sec >= end->tv_sec);

	/*
	 *	Initialize it.
	 */
	if (ema->f1 == 0) {
		if (ema->window > 10000) ema->window = 10000;
		
		ema->f1 =  (2 * F_EMA_SCALE) / (ema->window + 1);
		ema->f10 = (2 * F_EMA_SCALE) / ((10 * ema->window) + 1);
	}


	tdiff = start->tv_sec;
	tdiff -= end->tv_sec;
	
	micro = (int) tdiff;
	if (micro > 40) micro = 40; /* don't overflow 32-bit ints */
	micro *= USEC;
	micro += start->tv_usec;
	micro -= end->tv_usec;
	
	micro *= EMA_SCALE;

	if (ema->ema1 == 0) {
		ema->ema1 = micro;
		ema->ema10 = micro;
	} else {
		int diff;
		
		diff = ema->f1 * (micro - ema->ema1);
		ema->ema1 += (diff / 1000000);
		
		diff = ema->f10 * (micro - ema->ema10);
		ema->ema10 += (diff / 1000000);
	}
	
	
#ifdef WITH_STATS_DEBUG
	DEBUG("time %d %d.%06d\t%d.%06d\t%d.%06d\n",
	      n, micro / PREC, (micro / EMA_SCALE) % USEC,
	      ema->ema1 / PREC, (ema->ema1 / EMA_SCALE) % USEC,
	      ema->ema10 / PREC, (ema->ema10 / EMA_SCALE) % USEC);
	n++;
#endif	
}

#endif /* WITH_STATS */
