#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file lib/totp/base.h
 * @brief Common functions for TOTP library
 *
 * @copyright 2023 The FreeRADIUS server project
 */
RCSIDH(totp_h, "$Id$")

#include <freeradius-devel/server/request.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t time_step;		//!< seconds
	uint32_t otp_length;		//!< forced to 6 or 8
	uint32_t lookback_steps;	//!< number of steps to look back
	uint32_t lookback_interval;	//!< interval in seconds between steps
	uint32_t lookforward_steps;	//!< number of steps to look forwards
} fr_totp_t;

int fr_totp_cmp(fr_totp_t const *cfg, request_t *request, time_t now, uint8_t const *key, size_t keylen, char const *totp) CC_HINT(nonnull(1,4,6));

#ifdef __cplusplus
}
#endif
