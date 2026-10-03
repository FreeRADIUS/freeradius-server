/*
 *   This program is free software; you can redistribute it and/or modify
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
	{ L("wo"),			O_WRONLY       	},
	{ L("write-only"),		O_WRONLY       	},
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

/** Parse a socket buffer size, and check that it fits into the "int" taken by setsockopt()
 *
 *  Note that this function parses a plain integer.  cf_table_parse_uint32() looks the value up in
 *  a table taken from rule->uctx, and these rules have no uctx.
 */
static int send_recv_buf_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	int		ret;
	uint32_t	size;

	ret = cf_pair_parse_value(ctx, out, parent, ci, rule);
	if (ret < 0) return ret;

	size = *(uint32_t *) out;
	if (size > INT_MAX) {
		cf_log_err(ci, "Invalid value - it is too large");
		return -1;
	}

	return 0;
}

/** Mapping table of transport names to the transport types/
 */
static fr_table_num_sorted_t transport_types[] = {
	{ L("file"),		FR_BIO_FD_TRANSPORT_FILE	},
	{ L("tcp"),		FR_BIO_FD_TRANSPORT_TCP		},
	{ L("udp"),		FR_BIO_FD_TRANSPORT_UDP		},
	{ L("unix"),		FR_BIO_FD_TRANSPORT_UNIX	},
};
static size_t transport_types_len = NUM_ELEMENTS(transport_types);

/** Parse "transport" and then set the subconfig
 *
 */
static int common_transport_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule,
				  conf_parser_t const *transport_table[FR_BIO_FD_TRANSPORT_SIZE])
{
	int socket_type = SOCK_STREAM;
	conf_parser_t const *rules;
	char const *name = cf_pair_value(cf_item_to_pair(ci));
	fr_bio_fd_config_t *fd_config = parent;
	CONF_SECTION *cs, *subcs;
	fr_bio_fd_transport_t transport_type;

	transport_type = fr_table_value_by_str(transport_types, name, FR_BIO_FD_TRANSPORT_INVALID);
	if (transport_type == FR_BIO_FD_TRANSPORT_INVALID) {
	invalid:
		cf_log_err(ci, "Invalid transport name \"%s\"", name);
		return -1;
	}

	/*
	 *	A NULL entry means that this side does not allow that transport.
	 */
	rules = transport_table[transport_type];
	if (!rules) goto invalid;

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

	if (transport_type == FR_BIO_FD_TRANSPORT_UDP) socket_type = SOCK_DGRAM;

	/*
	 *	Client sockets are always connected.
	 */
	fd_config->socket_type = socket_type;
	fd_config->transport_type = transport_type;
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
	{ FR_CONF_OFFSET("src_port_start", fr_bio_fd_config_t, src_port_start) },
	{ FR_CONF_OFFSET("src_port_end", fr_bio_fd_config_t, src_port_end) },

	{ FR_CONF_OFFSET("interface", fr_bio_fd_config_t, interface) },

#if (defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)) || defined(IP_DONTFRAG)
	{ FR_CONF_OFFSET("exceed_mtu", fr_bio_fd_config_t, exceed_mtu), .dflt = "yes" },
#endif

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, recv_buff), .func = send_recv_buf_parse },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, send_buff), .func = send_recv_buf_parse },

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

	{ FR_CONF_OFFSET("src_port_start", fr_bio_fd_config_t, src_port_start) },
	{ FR_CONF_OFFSET("src_port_end", fr_bio_fd_config_t, src_port_end) },

#if (defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)) || defined(IP_DONTFRAG)
	{ FR_CONF_OFFSET("exceed_mtu", fr_bio_fd_config_t, exceed_mtu), .dflt = "yes" },
#endif

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, recv_buff), .func = send_recv_buf_parse },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, send_buff), .func = send_recv_buf_parse },

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
	{ FR_CONF_OFFSET("src_port_start", fr_bio_fd_config_t, src_port_start) },
	{ FR_CONF_OFFSET("src_port_end", fr_bio_fd_config_t, src_port_end) },

	{ FR_CONF_OFFSET("interface", fr_bio_fd_config_t, interface) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, recv_buff), .func = send_recv_buf_parse },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, send_buff), .func = send_recv_buf_parse },

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

static conf_parser_t const *client_transport_configs[FR_BIO_FD_TRANSPORT_SIZE] = {
	[FR_BIO_FD_TRANSPORT_FILE] = client_file_config,
	[FR_BIO_FD_TRANSPORT_TCP]  = client_tcp_config,
	[FR_BIO_FD_TRANSPORT_UDP]  = client_udp_config,
	[FR_BIO_FD_TRANSPORT_UNIX] = client_unix_config,
};

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
		fd_config->transport_type = FR_BIO_FD_TRANSPORT_UDP;
		*(char const **) out = name;

		return 0;
	}

	if (fd_config->type == FR_BIO_FD_INVALID) fd_config->type = FR_BIO_FD_CONNECTED;

	return common_transport_parse(ctx, out, parent, ci, rule, client_transport_configs);
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

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, recv_buff), .func = send_recv_buf_parse },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, send_buff), .func = send_recv_buf_parse },

#if (defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)) || defined(IP_DONTFRAG)
	{ FR_CONF_OFFSET("exceed_mtu", fr_bio_fd_config_t, exceed_mtu), .dflt = "yes" },
#endif

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

	{ FR_CONF_OFFSET_IS_SET("backlog", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, backlog) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, recv_buff), .func = send_recv_buf_parse },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, fr_bio_fd_config_t, send_buff), .func = send_recv_buf_parse },

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
static conf_parser_t const *server_transport_configs[FR_BIO_FD_TRANSPORT_SIZE] = {
	[FR_BIO_FD_TRANSPORT_FILE] = server_file_config,
	[FR_BIO_FD_TRANSPORT_TCP]  = server_tcp_config,
	[FR_BIO_FD_TRANSPORT_UDP]  = server_udp_config,
	[FR_BIO_FD_TRANSPORT_UNIX] = server_unix_config,
};

/** Parse "transport" and then set the subconfig
 *
 */
static int server_transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	int rcode;
	fr_bio_fd_config_t *fd_config = parent;

	fd_config->server = true;

	rcode = common_transport_parse(ctx, out, parent, ci, rule, server_transport_configs);
	if (rcode < 0) return rcode;

	/*
	 *	Automatically set the BIO type, too.
	 *
	 *	A server reads datagrams from anyone, and listens for new stream connections.  A file is
	 *	neither: it is opened and then read or written, which is what a connected bio does.
	 */
	switch (fd_config->transport_type) {
	case FR_BIO_FD_TRANSPORT_UDP:
		fd_config->type = FR_BIO_FD_UNCONNECTED;
		break;

	case FR_BIO_FD_TRANSPORT_TCP:
	case FR_BIO_FD_TRANSPORT_UNIX:
		fd_config->type = FR_BIO_FD_LISTEN;
		break;

	case FR_BIO_FD_TRANSPORT_FILE:
		fd_config->type = FR_BIO_FD_CONNECTED;

		/*
		 *	A server reads and writes its file.  There is no "mode" item for a server file, so
		 *	the default is the only mode, and 'flags' would otherwise be left as O_RDONLY, which
		 *	is zero.
		 */
		fd_config->flags = O_RDWR;
		break;

	case FR_BIO_FD_TRANSPORT_INVALID:
		fr_assert(0);
		return -1;
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
