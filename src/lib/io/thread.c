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
 * @brief Common thread instantiation and detach for worker and coordinator threads
 * @file io/thread.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/io/thread.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/syserror.h>

/** Instantiate thread-specific data for modules, virtual servers, xlats, unlang, and TLS
 *
 * @param[in] ctx	to allocate thread-specific data in.
 * @param[in] el	event list for this thread.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el)
{
#ifdef WITH_TLS
	if (fr_openssl_thread_init(main_config->openssl_async_pool_init,
				   main_config->openssl_async_pool_max) < 0) return -1;
#endif

	if (modules_rlm_thread_instantiate(ctx, el) < 0) return -1;

	if (virtual_servers_thread_instantiate(ctx, el) < 0) return -1;
	
	if (xlat_thread_instantiate(ctx, el) < 0) return -1;

	if (unlang_thread_instantiate(ctx) < 0) return -1;

	return 0;
}

/** Detach thread-specific data for modules, virtual servers, xlats
 *
 * Calls detach in reverse order of instantiation.
 */
void fr_thread_detach(void)
{
	xlat_thread_detach();
	virtual_servers_thread_detach();
	modules_rlm_thread_detach();
}
