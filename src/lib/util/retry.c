/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Handle RFC standard retransmissions
 *
 * @file src/lib/util/retry.c
 *
 * @copyright 2020 Network RADIUS SARL
 */

RCSID("$Id$")

#include <freeradius-devel/util/retry.h>
#include <freeradius-devel/util/rand.h>

/** Initialize a retransmission counter
 *
 * @param[in,out] r the retransmission structure
 * @param now when the retransmission starts
 * @param config the counters to track.  They shouldn't change while the retransmission is happening
 */
int fr_retry_init(fr_retry_t *r, fr_time_t now, fr_retry_config_t const *config)
{
	fr_time_delta_t scale, rt;
	uint128_t	delay;

	memset(r, 0, sizeof(*r));

	r->config = config;

	r->count = 1;
	r->start = now;

	/*
	 *	Initial:
	 *
	 *	RT = IRT + RAND * IRT
	 */
	scale = fr_rand();
	scale -= ((fr_time_delta_t) 1) << 31; /* scale it -2^31..+2^31 */
	scale += ((fr_time_delta_t) 1) << 32; /* multiple it by 1 * 2^32 */
	delay = scale * r->config->irt;
	rt = (fr_time_delta_t) (delay >> 64);

	r->rt = rt;
	r->next = now + rt;

	return 0;
}

/** Initialize a retransmission counter
 *
 * @param[in,out] r the retransmission structure
 * @param now the current time
 * @return
 *	- FR_RETRTY_CONTINUE - continue retransmitting
 *	- FR_RETRY_MRC - stop, maximum retransmission count has been reached
 *	- FR_RETRY_MDR - stop, maximum retransmission duration has been reached.
 */
fr_retry_state_t fr_retry_next(fr_retry_t *r, fr_time_t now)
{
	fr_time_delta_t scale, rt;
	uint128_t	delay;

	/*
	 *	Increment retransmission counter
	 */
	r->count++;

	/*
	 *	We retried too many times.  Fail.
	 */
	if (r->config->mrc && (r->count > r->config->mrc)) {
		return FR_RETRY_MRC;
	}

	/*
	 *	Cap delay at MRD
	 */
	if (r->config->mrd) {
		fr_time_t end;

		end = r->start;
		end += r->config->mrd;

		if (now > end) {
			return FR_RETRY_MRD;
		}
	}

	/*
	 *	RFC 5080 Section 2.2.1
	 *
	 *	RAND gives a random number between -0.1 and +0.1
	 *
	 *	Our random number generator returns 0..2^32, so we
	 *	have to scale everything relative to that.
	 *
	 *	RT = 2*RTprev + RAND*RTprev
	 *	   = RTprev + (2 + RAND)
	 */
	scale = fr_rand();
	scale -= ((fr_time_delta_t) 1) << 31; /* scale it -2^31..+2^31 */
	scale += ((fr_time_delta_t) 1) << 33; /* multiple it by 2 * 2^32 */
	delay = scale * r->rt;
	rt = (fr_time_delta_t) (delay >> 64);

	/*
	 *	Cap delay at MRT.
	 */
	if (r->config->mrt && (rt > r->config->mrt)) {
		scale = fr_rand();
		scale -= ((fr_time_delta_t) 1) << 31; /* scale it -2^31..+2^31 */
		scale += ((fr_time_delta_t) 1) << 32; /* multiple it by 1 * 2^32 */
		delay = scale * r->config->mrt;
		rt = (fr_time_delta_t) (delay >> 64);
	}

	/*
	 *	And finally set the retransmission timer.
	 */
	r->rt = rt;

	/*
	 *	Add in the retransmission delay.  Note that we send
	 *	the packet at "next + rt", and not "now + rt".  That
	 *	way the timer won't drift.
	 */
	r->next += rt;

	return FR_RETRY_CONTINUE;
}
