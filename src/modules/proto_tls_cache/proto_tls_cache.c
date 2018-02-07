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
 * @file proto_tls_cache.c
 * @brief Stub protocol to compile unlang in the tls_cache namespace.
 *
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/unlang.h>
#include <freeradius-devel/dl.h>
#include <freeradius-devel/io/application.h>

/** Compile various unlang sections
 *
 * @param[in] instance	Ctx data for this application.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(UNUSED void *instance, CONF_SECTION *conf)
{
	if (tls_cache_compile(NULL, cf_item_to_section(cf_parent(conf))) < 0) return -1;
	if (tls_ocsp_state_cache_compile(NULL, cf_item_to_section(cf_parent(conf))) < 0) return -1;
	if (tls_ocsp_staple_cache_compile(NULL, cf_item_to_section(cf_parent(conf))) < 0) return -1;

	return 0;
}

fr_app_t proto_tls_cache = {
	.magic		= RLM_MODULE_INIT,
	.name		= "tls_cache",
	.instantiate	= mod_instantiate,
};
