#pragma once
/*
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
 */

/**
 * $Id$
 *
 * @brief Calculate smoothed round trip time and round trip time variation.
 * @file util/rtt.h
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(rtt_h, "$Id$")

#include <freeradius-devel/util/time.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	We use *inverse* numbers to avoid numerical calculation issues.
 *
 *	i.e. The bad way is to take two small numbers divide them by
 *	alpha / beta and then add them.  That process can drop the
 *	lower digits.  Instead, we take two small numbers, add them,
 *	and then divide the result by alpha / beta.
 */
#define FR_RTT_IBETA (4)
#define FR_RTT_IALPHA (8)

/** Smoothed round trip time, and the variation of the round trip time
 *
 */
typedef struct {
	fr_time_delta_t	rtt;		//!< smoothed round trip time
	fr_time_delta_t	rttvar;		//!< RTT variation
} fr_rtt_t;

/** Absolute difference between the smoothed round trip time and a new sample
 *
 */
#define FR_RTT_DIFF(_rtt, _t) \
	(\
		fr_time_delta_lt(_rtt, _t) ? \
			fr_time_delta_sub(_t, _rtt) : \
			fr_time_delta_sub(_rtt, _t)\
	)

/** Calculate the new RTT variation from the old values and a new sample
 *
 */
#define FR_RTT_VAR(_rtt, _rttvar, _t) \
	fr_time_delta_div(\
		fr_time_delta_add(\
			fr_time_delta_mul(_rttvar, FR_RTT_IBETA - 1), \
			FR_RTT_DIFF(_rtt, _t)\
		), \
		fr_time_delta_wrap(FR_RTT_IBETA)\
	)

/** Calculate the new smoothed round trip time from the old value and a new sample
 *
 */
#define FR_RTT_SMOOTH(_old, _new) fr_time_delta_wrap((fr_time_delta_unwrap(_new) + (fr_time_delta_unwrap(_old) * (FR_RTT_IALPHA - 1))) / FR_RTT_IALPHA)

/** Calculate the retransmission timeout as SRTT + (K * RTTVAR)
 *
 * @param[in] _rtt	pointer to the #fr_rtt_t.
 * @param[in] _k	integer multiplier for the RTT variation.
 * @return the retransmission timeout, as an #fr_time_delta_t.
 */
#define FR_RTT_RTO(_rtt, _k) \
	fr_time_delta_add((_rtt)->rtt, fr_time_delta_mul((_rtt)->rttvar, (_k)))

/** Update the smoothed round trip time and the variation with a new sample
 *
 * The variation depends on the old RTT, so it is updated first.
 *
 * @param[in,out] r	to update.
 * @param[in] t		new round trip time sample.
 */
static inline void fr_rtt_update(fr_rtt_t *r, fr_time_delta_t t)
{
	r->rttvar = FR_RTT_VAR(r->rtt, r->rttvar, t);
	r->rtt = FR_RTT_SMOOTH(r->rtt, t);
}

#ifdef __cplusplus
}
#endif
