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
#include <freeradius-devel/util/uint128.h>

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
	r->updated = now;

	/*
	 *	Initial:
	 *
	 *	RT = IRT + RAND * IRT
	 *	   = IRT * (1 + RAND)
	 */
	scale = fr_rand();
	scale += ((fr_time_delta_t) 1) << 32; /* multiple it by 1 * 2^32 */
	scale -= ((fr_time_delta_t) 1) << 31; /* scale it -2^31..+2^31 */

	delay = uint128_mul64(scale, r->config->irt);
	rt = (fr_time_delta_t) uint128_rshift(delay, 32);

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
	r->updated = now;

	/*
	 *	We retried too many times.  Fail.
	 */
	if (r->config->mrc && (r->count > r->config->mrc)) {
		return FR_RETRY_MRC;
	}

redo:
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
	 *	   = RTprev * (2 + RAND)
	 */
	scale = fr_rand();
	scale -= ((fr_time_delta_t) 1) << 31; /* scale it -2^31..+2^31 */
	scale += ((fr_time_delta_t) 1) << 33; /* multiple it by 2 * 2^32 */

	delay = uint128_mul64(scale, r->rt);
	rt = (fr_time_delta_t) uint128_rshift(delay, 32);

	/*
	 *	Cap delay at MRT.
	 *
	 *	RT = MRT + RAND * MRT
	 *	   = MRT * (1 + RAND)
	 */
	if (r->config->mrt && (rt > r->config->mrt)) {
		scale = fr_rand();
		scale -= ((fr_time_delta_t) 1) << 31; /* scale it -2^31..+2^31 */
		scale += ((fr_time_delta_t) 1) << 32; /* multiple it by 1 * 2^32 */

		delay = uint128_mul64(scale, r->config->mrt);
		rt = (fr_time_delta_t) uint128_rshift(delay, 32);
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

	/*
	 *	The "next" retransmission time is in the past, AND
	 *	we're already halfway through the time after that.
	 *	Skip this retransmission, and set the time for the
	 *	next one.
	 *
	 *	i.e. if we weren't serviced for one event, just skip
	 *	it, and go to the next one.
	 */
	if ((r->next + (rt / 2)) < now) goto redo;

	return FR_RETRY_CONTINUE;
}
