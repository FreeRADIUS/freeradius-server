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
#ifndef _FR_DHCPV6_H
#define _FR_DHCPV6_H
/**
 * $Id$
 *
 * @file protocols/dhcpv6/dhcpv6.h
 * @brief Implementation of the DHCPv6 protocol.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 NetworkRADIUS SARL <info@networkradius.com>
 */
RCSIDH(dhcpv6_h, "$Id$")

ssize_t		fr_dhcpv6_encode_option(uint8_t *out, size_t outlen, fr_cursor_t *cursor, void *encoder_ctx);

ssize_t		fr_dhcpv6_decode_option(TALLOC_CTX *ctx, vp_cursor_t *cursor,
					uint8_t const *data, size_t data_len, void *decoder_ctx);
#endif
