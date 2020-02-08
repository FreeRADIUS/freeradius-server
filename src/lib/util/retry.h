#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Boxed value structures and functions to manipulate them
 *
 * @file src/lib/util/retry.h
 *
 * @copyright 2020 Network RADIUS SARL
 */
RCSIDH(retry_h, "$Id$")

#include <freeradius-devel/util/time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	fr_time_delta_t		irt;			//!< Initial transmission time
	fr_time_delta_t		mrt;			//!< Maximum retransmission time
	fr_time_delta_t		mrd;			//!< Maximum retransmission duration
	uint32_t		mrc;			//!< Maximum retransmission count
} fr_retry_config_t;

typedef struct {
	fr_retry_config_t const	*config;		//!< master configuration
	fr_time_t		start;			//!< when we started the retransmission
	fr_time_t		next;			//!< when the next timer should be set
	fr_time_t		updated;		//!< last update, really a cached "now".
	fr_time_delta_t		rt;			//!< retransmit interval
	uint32_t		count;			//!< number of sent packets
} fr_retry_t;

/*
 *	Anything other than "CONTINUE" means "DONE".  For helpfulness,
 *	we return *why* the timer is done.
 */
typedef enum {
	FR_RETRY_CONTINUE = 0,
	FR_RETRY_MRC,					//!< reached maximum retransmission count
	FR_RETRY_MRD,					//!< reached maximum retransmission duration
} fr_retry_state_t;

int		fr_retry_init(fr_retry_t *r, fr_time_t now, fr_retry_config_t const *config) CC_HINT(nonnull);
fr_retry_state_t fr_retry_next(fr_retry_t *r, fr_time_t now) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
