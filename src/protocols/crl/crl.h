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

/**
 * $Id$
 *
 * @file protocols/crl/crl.h
 * @brief Constants for the CRL protocol.
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(crl_h, "$Id$")

/** CRL packet codes
 */
typedef enum {
	FR_CRL_INVALID = 0,
	FR_CRL_CRL_FETCH,
	FR_CRL_CRL_REFRESH,
	FR_CRL_FETCH_OK,
	FR_CRL_FETCH_FAIL,
	FR_CRL_CRL_EXPIRE,
	FR_CRL_CODE_MAX,
	FR_CRL_DO_NOT_RESPOND = 255
} fr_crl_packet_code_t;

