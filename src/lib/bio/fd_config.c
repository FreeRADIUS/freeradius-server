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
 * @brief BIO abstractions for configuring file descriptors
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/util/perm.h>

#include <freeradius-devel/bio/fd_priv.h>

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


static int uid_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	struct passwd *pwd;
	uid_t *uid = (uid_t *) out;
	char const *name = cf_pair_value(cf_item_to_pair(ci));

	if (fr_perm_getpwnam(ctx, &pwd, name) < 0) {
		cf_log_perr(ci, "Failed getting uid from name %s", name);
		return -1;
	}

	*uid = pwd->pw_uid;
	talloc_free(pwd);
	return 0;
}

static int gid_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	gid_t *gid = (gid_t *) out;
	char const *name = cf_pair_value(cf_item_to_pair(ci));

	if (fr_perm_gid_from_str(ctx, gid, name) < 0) {
		cf_log_perr(ci, "Failed getting gid from name %s", name);
		return -1;
	}

	return 0;
}

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

static int perm_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	mode_t mode;
	char const *name = cf_pair_value(cf_item_to_pair(ci));

	if (fr_perm_mode_from_str(&mode, name) < 0) {
		cf_log_perr(ci, "Invalid permissions string");
		return -1;
	}

	*(mode_t *) out = mode;

	return 0;
}


const conf_parser_t fr_bio_fd_config[] = {
	{ FR_CONF_OFFSET("uid", fr_bio_fd_config_t, socket_type), .func = socket_type_parse },

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

	/*
	 *	Unix socket information
	 */
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_REQUIRED, fr_bio_fd_config_t, filename), },

	{ FR_CONF_OFFSET("uid", fr_bio_fd_config_t, uid), .func = uid_parse },
	{ FR_CONF_OFFSET("gid", fr_bio_fd_config_t, gid), .func = gid_parse },

	{ FR_CONF_OFFSET("perm", fr_bio_fd_config_t, perm), .func = perm_parse, .dflt = "0600" },

	{ FR_CONF_OFFSET("mode", fr_bio_fd_config_t, flags), .func = mode_parse, .dflt = "read-only" },

	{ FR_CONF_OFFSET("mkdir", fr_bio_fd_config_t, mkdir) },

	{ FR_CONF_OFFSET("async", fr_bio_fd_config_t, async), .dflt = "true" },

	{ FR_CONF_OFFSET("delay_tcp_writes", fr_bio_fd_config_t, tcp_delay) },

	CONF_PARSER_TERMINATOR
};
