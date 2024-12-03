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
 * @file lib/bio/fd_config.c
 * @brief BIO abstractions for configuring file descriptors.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/util/perm.h>

#include <freeradius-devel/bio/fd_priv.h>

#if 0
static fr_table_num_sorted_t socket_type_names[] = {
	{ L("udp"),		SOCK_DGRAM			},
	{ L("datagram"),	SOCK_DGRAM			},
	{ L("tcp"),		SOCK_STREAM			},
	{ L("stream"),		SOCK_STREAM			},
};
static size_t socket_type_names_len = NUM_ELEMENTS(socket_type_names);

static int socket_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	int type;
	char const *name = cf_pair_value(cf_item_to_pair(ci));

	type = fr_table_value_by_str(socket_type_names, name, -1);
	if (type < 0) {
		cf_log_err(ci, "Invalid protocol name \"%s\"", name);
		return -1;
	}

	*(int *) out = type;

	return 0;
}
#endif

#define FR_READ  (1)
#define FR_WRITE (2)

static fr_table_num_sorted_t mode_names[] = {
	{ L("read-only"),		FR_READ			},
	{ L("read-write"),		FR_READ | FR_WRITE	},
	{ L("ro"),			FR_READ			},
	{ L("rw"),			FR_READ | FR_WRITE	}
};
static size_t mode_names_len = NUM_ELEMENTS(mode_names);

static int mode_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	int mode;
	char const *name = cf_pair_value(cf_item_to_pair(ci));

	mode = fr_table_value_by_str(mode_names, name, 0);
	if (!mode) {
		cf_log_err(ci, "Invalid mode name \"%s\"", name);
		return -1;
	}

	if ((mode & FR_WRITE) == 0) {
		*(int *) out = O_RDWR;
	} else {
		*(int *) out = O_RDONLY;
	}

	return 0;
}

static const conf_parser_t peercred_config[] = {
	{ FR_CONF_OFFSET("uid", fr_bio_fd_config_t, uid), .func = cf_parse_uid },
	{ FR_CONF_OFFSET("gid", fr_bio_fd_config_t, gid), .func = cf_parse_gid },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t udp_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, fr_bio_fd_config_t, dst_ipaddr), },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4addr", FR_TYPE_IPV4_ADDR, 0, fr_bio_fd_config_t, dst_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6addr", FR_TYPE_IPV6_ADDR, 0, fr_bio_fd_config_t, dst_ipaddr) },

	{ FR_CONF_OFFSET("port", fr_bio_fd_config_t, dst_port) },

	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipv4addr", FR_TYPE_IPV4_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipv6addr", FR_TYPE_IPV6_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },

	{ FR_CONF_OFFSET("src_port", fr_bio_fd_config_t, src_port) },

	{ FR_CONF_OFFSET("interface", fr_bio_fd_config_t, interface) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, recv_buff) },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, send_buff) },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t tcp_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, fr_bio_fd_config_t, dst_ipaddr), },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4addr", FR_TYPE_IPV4_ADDR, 0, fr_bio_fd_config_t, dst_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6addr", FR_TYPE_IPV6_ADDR, 0, fr_bio_fd_config_t, dst_ipaddr) },

	{ FR_CONF_OFFSET("port", fr_bio_fd_config_t, dst_port) },

	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipv4addr", FR_TYPE_IPV4_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipv6addr", FR_TYPE_IPV6_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },

	{ FR_CONF_OFFSET("src_port", fr_bio_fd_config_t, src_port) },

	{ FR_CONF_OFFSET("interface", fr_bio_fd_config_t, interface) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, recv_buff) },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, send_buff) },

	{ FR_CONF_OFFSET("delay_tcp_writes", fr_bio_fd_config_t, tcp_delay) },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t unix_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_REQUIRED, fr_bio_fd_config_t, filename), },

	{ FR_CONF_OFFSET("permissions", fr_bio_fd_config_t, perm), .dflt = "0600", .func = cf_parse_permissions },

	{ FR_CONF_OFFSET("mode", fr_bio_fd_config_t, flags), .dflt = "read-only", .func = mode_parse },

	{ FR_CONF_OFFSET("mkdir", fr_bio_fd_config_t, mkdir) },

	{ FR_CONF_POINTER("peercred", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) peercred_config },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t file_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_REQUIRED, fr_bio_fd_config_t, filename), },

	{ FR_CONF_OFFSET("permissions", fr_bio_fd_config_t, perm), .dflt = "0600", .func = cf_parse_permissions },

	{ FR_CONF_OFFSET("mkdir", fr_bio_fd_config_t, mkdir) },


	CONF_PARSER_TERMINATOR
};

static fr_table_ptr_sorted_t transport_names[] = {
	{ L("file"),		file_config },
	{ L("tcp"),		tcp_config },
	{ L("unix"),		unix_config },
	{ L("udp"),		udp_config },
};
static size_t transport_names_len = NUM_ELEMENTS(transport_names);

/** Parse "transport" and then set the subconfig
 *
 */
static int transport_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	int socket_type = SOCK_STREAM;
	conf_parser_t const *rules;
	char const *name = cf_pair_value(cf_item_to_pair(ci));
	fr_bio_fd_config_t *fd_config = parent;

	rules = fr_table_value_by_str(transport_names, name, NULL);
	if (!rules) {
		cf_log_err(ci, "Invalid transport name \"%s\"", name);
		return -1;
	}

	if (cf_section_rules_push(cf_item_to_section(cf_parent(ci)), rules) < 0) {
		cf_log_perr(ci, "Failed updating parse rules");
		return -1;
	}

	if (strcmp(name, "udp") == 0) socket_type = SOCK_DGRAM;

	fd_config->socket_type = socket_type;
	*(char const **) out = name;

	return 0;
}

const conf_parser_t fr_bio_fd_config[] = {
	{ FR_CONF_OFFSET("transport", fr_bio_fd_config_t, socket_type), .func = transport_parse },

	{ FR_CONF_OFFSET("async", fr_bio_fd_config_t, async), .dflt = "true" },

	CONF_PARSER_TERMINATOR
};
