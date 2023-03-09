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

/** Functions which we wish were included in the standard talloc distribution
 *
 * @file src/lib/util/talloc.h
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(talloc_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation)
#endif
#include <talloc.h>
#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
#endif

#include <freeradius-devel/autoconf.h>	/* Very easy to miss including in special builds */
#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

TALLOC_CTX	*talloc_aligned_array(TALLOC_CTX *ctx, void **start, size_t alignment, size_t size);

#ifdef __cplusplus
}
#endif
