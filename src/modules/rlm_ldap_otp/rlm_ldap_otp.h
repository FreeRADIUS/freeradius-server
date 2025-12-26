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
 * @file rlm_ldap_otp.h
 * @brief LDAP with local OTP authentication module.
 *
 * @copyright 2025 The FreeRADIUS server project
 */
RCSIDH(rlm_ldap_otp_h, "$Id$")

#include <freeradius-devel/server/request.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t	time_step;
	uint32_t	time_window;
	uint32_t	otp_length;
	uint32_t	lookback_steps;
	uint32_t	lookforward_steps;
} ldap_otp_totp_conf_t;

typedef struct {
	uint32_t	count_window;
	uint32_t	sync_window;
	uint32_t	otp_length;
} ldap_otp_hotp_conf_t;

#ifdef __cplusplus
}
#endif
