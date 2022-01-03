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
#ifdef WITH_TLS
/**
 * $Id$
 *
 *  https://www.openssl.org/docs/manmaster/man7/OPENSSL_NO_DEPRECATED.html
 *
 * @file lib/tls/openssl_user_macros.h
 * @brief Definitions which control which OpenSSL API functions are exposed
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(openssl_user_macros_h, "$Id$")

/*
 *	This changed in OpenSSL 1.1.0 (they allow deprecated interfaces)
 *	But because we're always ahead of the curve we don't need them.
 */
#ifndef OPENSSL_NO_DEPRECATED
#  define OPENSSL_NO_DEPRECATED
#endif

/*
 *	For RH 9, which apparently needs this.
 */
#ifndef OPENSSL_NO_KRB5
#  define OPENSSL_NO_KRB5
#endif
#endif
