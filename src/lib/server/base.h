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
 * @file lib/server/base.h
 * @brief Structures, prototypes and global variables for the FreeRADIUS server.
 *
 * @copyright 1999-2018 The FreeRADIUS server project
 */
RCSIDH(base_h, "$Id$")

#include <freeradius-devel/features.h>
#include <freeradius-devel/server/auth.h>
#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/client.h>
#include <freeradius-devel/server/command.h>
#include <freeradius-devel/server/components.h>
#include <freeradius-devel/server/cond_eval.h>
#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/server/crypt.h>
#include <freeradius-devel/server/dependency.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/server/exfile.h>
#include <freeradius-devel/server/listen.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/server/main_loop.h>
#include <freeradius-devel/server/map_proc_priv.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/paircmp.h>
#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/server/password.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/pool.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/regex.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/request_data.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/server/stats.h>
#include <freeradius-devel/server/sysutmp.h>
#include <freeradius-devel/server/tcp.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/trigger.h>
#include <freeradius-devel/server/users_file.h>
#include <freeradius-devel/server/util.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/xlat.h>

#include <freeradius-devel/util/base.h>

int server_init(CONF_SECTION *cs);
void server_free(void);
