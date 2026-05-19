#pragma once

/*
 *   This program is is free software; you can redistribute it and/or modify
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
 * @file lib/redis/cluster_async.h
 * @brief Redis asynchronous cluster management
 *
 * @copyright 2026 The FreeRADIUS server project
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(redis_cluster_async_h, "$Id$")

#include <freeradius-devel/server/trunk.h>
#include <freeradius-devel/io/coord_pair.h>
#include "base.h"
#include "pipeline.h"

#define KEY_SLOTS		16384			//!< Maximum number of keyslots (should not change).

typedef struct fr_redis_ct_key_slot_s fr_redis_ct_key_slot_t;
typedef struct fr_redis_ct_node_s fr_redis_ct_node_t;
typedef struct fr_redis_async_cmd_s fr_redis_async_cmd_t;

fr_redis_ct_key_slot_t const	*fr_redis_ct_slot_by_key(fr_redis_cluster_thread_t *rtcluster, request_t *request,
							 uint8_t const *key, size_t key_len);

fr_redis_ct_node_t const	*fr_redis_ct_master(fr_redis_cluster_thread_t *thread,
						    fr_redis_ct_key_slot_t const *key_slot);

fr_redis_ct_node_t const	*fr_redis_ct_replica(fr_redis_cluster_thread_t *thread,
						     fr_redis_ct_key_slot_t const *key_slot, uint8_t replica_num);

fr_redis_cluster_thread_t	*fr_redis_cluster_thread_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, fr_redis_conf_t *conf);

fr_event_list_t			*fr_redis_cluster_thread_el(fr_redis_cluster_thread_t *thread);

trunk_conf_t const		*fr_redis_cluster_thread_trunk_conf(fr_redis_cluster_thread_t *thread);

int				fr_redis_cluster_thread_map_bootstrap(fr_redis_cluster_thread_t *rtcluster,
								      fr_coord_worker_t *cw,
								      fr_coord_pair_reg_t *coord_pair_reg);

fr_redis_async_rcode_t		fr_redis_cluster_thread_map_get(fr_redis_cluster_thread_t *rtcluster,
								fr_coord_worker_t *cw,
								fr_coord_pair_reg_t *coord_pair_reg);

int				fr_redis_cluster_thread_map_update(fr_redis_cluster_thread_t *thread, fr_pair_list_t const *list);

fr_redis_async_cmd_t		*fr_redis_async_cmd_start(TALLOC_CTX *ctx, request_t *request, fr_redis_async_rcode_t *rcode,
							  fr_redis_cluster_thread_t *rtcluster, uint8_t const *key, size_t key_len,
							  fr_redis_command_set_t *cmds, bool read_only, fr_redis_ct_node_t *node);

fr_redis_ct_node_t		*fr_redis_cluster_thread_node_by_addr(fr_redis_cluster_thread_t *rtcluster,
								      fr_socket_t *addr);
