#pragma once
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
 * @file lib/redis/attrs.h
 * @brief Redis dictionary attributes
 *
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(lib_eap_attrs_h, "$Id$")

#include <freeradius-devel/util/dict.h>

extern fr_dict_t const *dict_redis;

extern fr_dict_attr_t const *attr_redis_packet_type;
extern fr_dict_attr_t const *attr_redis_log_prefix;
extern fr_dict_attr_t const *attr_redis_max_nodes;
extern fr_dict_attr_t const *attr_redis_bootstrap_node;
extern fr_dict_attr_t const *attr_redis_bootstrap_port;
extern fr_dict_attr_t const *attr_redis_username;
extern fr_dict_attr_t const *attr_redis_password;
extern fr_dict_attr_t const *attr_redis_cluster_id;
extern fr_dict_attr_t const *attr_redis_shard;
extern fr_dict_attr_t const *attr_redis_slot;
extern fr_dict_attr_t const *attr_redis_slot_start;
extern fr_dict_attr_t const *attr_redis_slot_end;
extern fr_dict_attr_t const *attr_redis_node;
extern fr_dict_attr_t const *attr_redis_node_endpoint;
extern fr_dict_attr_t const *attr_redis_node_port;
extern fr_dict_attr_t const *attr_redis_node_role;
extern fr_dict_attr_t const *attr_redis_force_update;
