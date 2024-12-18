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

static fr_table_num_sorted_t mode_names[] = {
	{ L("read-only"),		O_RDONLY       	},
	{ L("read-write"),		O_RDWR		},
	{ L("ro"),			O_RDONLY       	},
	{ L("rw"),			O_RDWR		},
};
static size_t mode_names_len = NUM_ELEMENTS(mode_names);

static int mode_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	int mode;
	char const *name = cf_pair_value(cf_item_to_pair(ci));

	mode = fr_table_value_by_str(mode_names, name, -1);
	if (mode < 0) {
		cf_log_err(ci, "Invalid mode name \"%s\"", name);
		return -1;
	}

	*(int *) out = mode;

	return 0;
}

/** Parse "transport" and then set the subconfig
 *
 */
static int common_transport_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule, fr_table_ptr_sorted_t const *transport_table, size_t transport_table_len)
{
	int socket_type = SOCK_STREAM;
	conf_parser_t const *rules;
	char const *name = cf_pair_value(cf_item_to_pair(ci));
	fr_bio_fd_config_t *fd_config = parent;
	CONF_SECTION *cs, *subcs;

	rules = fr_table_value_by_str(transport_table, name, NULL);
	if (!rules) {
		cf_log_err(ci, "Invalid transport name \"%s\"", name);
		return -1;
	}

	cs = cf_item_to_section(cf_parent(ci));

	/*
	 *      Find the relevant subsection.  Note that we don't do anything with it, as we push a parse
	 *      rule in the parent which then points to the subsection.
	 */
	subcs = cf_section_find(cs, name, NULL);
	if (!subcs) {
		cf_log_perr(ci, "Failed finding transport configuration section %s { ... }", name);
		return -1;
	}

	/*
	 *	Note that these offsets will get interpreted as being offsets from base of the subsection.
	 *	i.e. the parent section and the subsection have to be parsed with the same base pointer.
	 */
	if (cf_section_rules_push(cs, rules) < 0) {
		cf_log_perr(ci, "Failed updating parse rules");
		return -1;
	}

	if (strcmp(name, "udp") == 0) socket_type = SOCK_DGRAM;

	/*
	 *	Client sockets are always connected.
	 */
	fd_config->socket_type = socket_type;
	*(char const **) out = name;

	return 0;
}

static const conf_parser_t client_udp_sub_config[] = {
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

static conf_parser_t const client_udp_config[] = {
	{ FR_CONF_POINTER("udp", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) client_udp_sub_config },

	CONF_PARSER_TERMINATOR
};


static const conf_parser_t client_udp_unconnected_sub_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipv4addr", FR_TYPE_IPV4_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipv6addr", FR_TYPE_IPV6_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },

	{ FR_CONF_OFFSET("interface", fr_bio_fd_config_t, interface) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, recv_buff) },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, send_buff) },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const client_udp_unconnected_config[] = {
	{ FR_CONF_POINTER("udp", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) client_udp_unconnected_sub_config },

	CONF_PARSER_TERMINATOR
};


static const conf_parser_t client_tcp_sub_config[] = {
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

static conf_parser_t const client_tcp_config[] = {
	{ FR_CONF_POINTER("tcp", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) client_tcp_sub_config },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t client_file_sub_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_REQUIRED, fr_bio_fd_config_t, filename), },

	{ FR_CONF_OFFSET("permissions", fr_bio_fd_config_t, perm), .dflt = "0600", .func = cf_parse_permissions },

	{ FR_CONF_OFFSET("mode", fr_bio_fd_config_t, flags), .dflt = "read-write", .func = mode_parse },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const client_file_config[] = {
	{ FR_CONF_POINTER("file", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) client_file_sub_config },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t client_unix_sub_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_REQUIRED, fr_bio_fd_config_t, path), },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const client_unix_config[] = {
	{ FR_CONF_POINTER("unix", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) client_unix_sub_config },

	CONF_PARSER_TERMINATOR
};

static fr_table_ptr_sorted_t client_transport_names[] = {
	{ L("file"),		client_file_config },
	{ L("tcp"),		client_tcp_config },
	{ L("udp"),		client_udp_config },
	{ L("unix"),		client_unix_config },
};
static size_t client_transport_names_len = NUM_ELEMENTS(client_transport_names);

/** Parse "transport" and then set the subconfig
 *
 */
static int client_transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	fr_bio_fd_config_t *fd_config = parent;

	/*
	 *	Unconnected UDP sockets can only take src_ipaddr, but not port, and not dst_ipaddr.
	 */
	if (fd_config->type == FR_BIO_FD_UNCONNECTED) {
		char const *name = cf_pair_value(cf_item_to_pair(ci));
		CONF_SECTION *cs = cf_item_to_section(cf_parent(ci));

		if (strcmp(name, "udp") != 0) {
			cf_log_err(ci, "Invalid transport for unconnected UDP socket");
			return -1;
		}

		if (cf_section_rules_push(cs, client_udp_unconnected_config) < 0) {
			cf_log_perr(ci, "Failed updating parse rules");
			return -1;
		}

		fd_config->socket_type = SOCK_DGRAM;
		*(char const **) out = name;

		return 0;
	}

	if (fd_config->type == FR_BIO_FD_INVALID) fd_config->type = FR_BIO_FD_CONNECTED;

	return common_transport_parse(ctx, out, parent, ci, rule,
				      client_transport_names, client_transport_names_len);
}

/*
 *	Client uses src_ipaddr for our address, and ipaddr for their address.
 */
const conf_parser_t fr_bio_fd_client_config[] = {
	{ FR_CONF_OFFSET("transport", fr_bio_fd_config_t, transport), .func = client_transport_parse },

	{ FR_CONF_OFFSET("async", fr_bio_fd_config_t, async), .dflt = "true" },

	CONF_PARSER_TERMINATOR
};

/*
 *	Server configuration
 *
 *	"ipaddr" is src_ipaddr
 *	There's no "dst_ipaddr" or "src_ipaddr" in the config.
 *
 *	Files have permissions which can be set.
 */

static const conf_parser_t server_udp_sub_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, fr_bio_fd_config_t, src_ipaddr), },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4addr", FR_TYPE_IPV4_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6addr", FR_TYPE_IPV6_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },

	{ FR_CONF_OFFSET("port", fr_bio_fd_config_t, src_port) },

	{ FR_CONF_OFFSET("interface", fr_bio_fd_config_t, interface) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, recv_buff) },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, send_buff) },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const server_udp_config[] = {
	{ FR_CONF_POINTER("udp", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) server_udp_sub_config },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t server_tcp_sub_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, fr_bio_fd_config_t, src_ipaddr), },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4addr", FR_TYPE_IPV4_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6addr", FR_TYPE_IPV6_ADDR, 0, fr_bio_fd_config_t, src_ipaddr) },

	{ FR_CONF_OFFSET("port", fr_bio_fd_config_t, src_port) },

	{ FR_CONF_OFFSET("interface", fr_bio_fd_config_t, interface) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, recv_buff) },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, send_buff) },

	{ FR_CONF_OFFSET("delay_tcp_writes", fr_bio_fd_config_t, tcp_delay) },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const server_tcp_config[] = {
	{ FR_CONF_POINTER("tcp", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) server_tcp_sub_config },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t server_file_sub_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_REQUIRED, fr_bio_fd_config_t, filename), },

	{ FR_CONF_OFFSET("permissions", fr_bio_fd_config_t, perm), .dflt = "0600", .func = cf_parse_permissions },

	{ FR_CONF_OFFSET("mkdir", fr_bio_fd_config_t, mkdir) },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const server_file_config[] = {
	{ FR_CONF_POINTER("file", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) server_file_sub_config },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t server_peercred_config[] = {
	{ FR_CONF_OFFSET("uid", fr_bio_fd_config_t, uid), .func = cf_parse_uid },
	{ FR_CONF_OFFSET("gid", fr_bio_fd_config_t, gid), .func = cf_parse_gid },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t server_unix_sub_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_REQUIRED, fr_bio_fd_config_t, path), },

	{ FR_CONF_OFFSET("permissions", fr_bio_fd_config_t, perm), .dflt = "0600", .func = cf_parse_permissions },

	{ FR_CONF_OFFSET("mode", fr_bio_fd_config_t, flags), .dflt = "read-only", .func = mode_parse },

	{ FR_CONF_OFFSET("mkdir", fr_bio_fd_config_t, mkdir) },

	{ FR_CONF_POINTER("peercred", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) server_peercred_config },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const server_unix_config[] = {
	{ FR_CONF_POINTER("unix", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) server_unix_sub_config },

	CONF_PARSER_TERMINATOR
};

/*
 *	@todo - move this to client/server config in the same struct?
 */
static fr_table_ptr_sorted_t server_transport_names[] = {
	{ L("file"),		server_file_config },
	{ L("tcp"),		server_tcp_config },
	{ L("udp"),		server_udp_config },
	{ L("unix"),		server_unix_config },
};
static size_t server_transport_names_len = NUM_ELEMENTS(server_transport_names);

/** Parse "transport" and then set the subconfig
 *
 */
static int server_transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	int rcode;
	fr_bio_fd_config_t *fd_config = parent;

	fd_config->server = true;

	rcode = common_transport_parse(ctx, out, parent, ci, rule,
				       server_transport_names, server_transport_names_len);
	if (rcode < 0) return rcode;

	/*
	 *	Automatically set the BIO type, too.
	 */
	if (fd_config->socket_type == SOCK_DGRAM) {
		fd_config->type = FR_BIO_FD_UNCONNECTED;
	} else {
		fd_config->type = FR_BIO_FD_LISTEN;
	}

	return 0;
}

/*
 *	Server uses ipaddr for our address, and doesn't use src_ipaddr.
 */
const conf_parser_t fr_bio_fd_server_config[] = {
	{ FR_CONF_OFFSET("transport", fr_bio_fd_config_t, transport), .func = server_transport_parse },

	{ FR_CONF_OFFSET("async", fr_bio_fd_config_t, async), .dflt = "true" },

	CONF_PARSER_TERMINATOR
};
