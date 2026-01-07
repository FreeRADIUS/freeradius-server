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
 * @file lib/server/client.h
 * @brief API to add client definitions to the server, both on startup and at runtime.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(clients_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/cf_util.h>

typedef struct fr_client_s fr_client_t;
typedef struct fr_client_list_s fr_client_list_t;

/** Callback for retrieving values when building client sections
 *
 * Example:
 @code{.c}
   int _client_value_cb(char **out, CONF_PAIR const *cp, void *data)
   {
   	my_result *result = data;
   	char *value;

   	value = get_attribute_from_result(result, cf_pair_value(cp));
   	if (!value) {
   		*out = NULL;
   		return 0;
   	}

   	*out = talloc_strdup(value);
   	free_attribute(value);

   	if (!*out) return -1;
   	return 0;
   }
 @endcode
 *
 * @param[out] out Where to write a pointer to the talloced value buffer.
 * @param[in] cp The value of the CONF_PAIR specifies the attribute name to retrieve from the result.
 * @param[in] data Pointer to the result struct to copy values from.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*client_value_cb_t)(char **out, CONF_PAIR const *cp, void *data);

#include <freeradius-devel/util/time.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/socket.h>
#include <freeradius-devel/server/stats.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/radius/radius.h>

/** Describes a host allowed to send packets to the server
 *
 */
struct fr_client_s {
	fr_rb_node_t		node;			//!< Entry in the client tree.

	fr_ipaddr_t		ipaddr;			//!< IPv4/IPv6 address of the host.
	fr_ipaddr_t		src_ipaddr;		//!< IPv4/IPv6 address to send responses
							//!< from (family must match ipaddr).

	char const		*longname;		//!< Client identifier.
	char const		*shortname;		//!< Client nickname.

	char const		*secret;		//!< Secret PSK.

	/** Require RADIUS message authenticator for incoming packets
	 */
	fr_radius_require_ma_t	require_message_authenticator;

	/** Whether require_message_authenticator is set in the configuration.
	 */
	bool			require_message_authenticator_is_set;

	/** Whether to allow Proxy-State in incoming packets that don't contain a message authenticator.
	 *
	 * If Proxy-State is included, but Message-Authenticator is not, then an
	 * attacker can potentially forge responses.
	 */
	fr_radius_limit_proxy_state_t			limit_proxy_state;

	/** Whether limit_proxy_state is set in the configuration.
	 */
	bool			limit_proxy_state_is_set;

	bool			received_message_authenticator;	//!< Whether we've seen a message authenticator
								///< from this client in any previous packets.

	bool			seen_first_packet;		//!< Whether we've seen a packet from this client.
	bool			first_packet_no_proxy_state;	//!< Whether that first packet contained a Proxy-State
								///< attribute.

	bool			protocol_error;		//!< Whether the client supports Protocol-Error
	bool			dynamic;		//!< Whether the client was dynamically defined.
	bool			active;			//!< for dynamic clients
	bool			use_connected;		//!< do we use connected sockets for this client

#ifdef WITH_TLS
	bool			tls_required;		//!< whether TLS encryption is required.
#endif

#ifdef NAS_VIOLATES_RFC
	bool			allow_vulnerable_clients; //!< for vendors who violate the RFCs.
#endif

	char const		*nas_type;		//!< Type of client (arbitrary).

	char const 		*server;		//!< Name of the virtual server client is associated with.
	CONF_SECTION		*server_cs;		//!< Virtual server that the client is associated with

	int			number;			//!< Unique client number.

	CONF_SECTION	 	*cs;			//!< CONF_SECTION that was parsed to generate the client.

#ifdef WITH_STATS
	fr_stats_t		auth;			//!< Authentication stats.
	fr_stats_t		acct;			//!< Accounting stats.
#endif

	fr_time_delta_t		response_window;	//!< How long the client has to respond.

	int			proto;			//!< Protocol number.
	fr_socket_limit_t	limit;			//!< Connections per client (TCP clients only).
};

fr_client_list_t	*client_list_init(CONF_SECTION *cs);

void		client_list_free(void);

fr_client_list_t	*client_list_parse_section(CONF_SECTION *section, int proto, bool tls_required);

void		client_free(fr_client_t *client);

bool		client_add(fr_client_list_t *clients, fr_client_t *client);

void		client_delete(fr_client_list_t *clients, fr_client_t *client);

fr_client_t	*client_afrom_request(TALLOC_CTX *ctx, request_t *request);

int		client_map_section(CONF_SECTION *out, CONF_SECTION const *map, client_value_cb_t func, void *data);

fr_client_t	*client_afrom_cs(TALLOC_CTX *ctx, CONF_SECTION *cs, CONF_SECTION *server_cs, size_t extra);

fr_client_t	*client_find(fr_client_list_t const *clients, fr_ipaddr_t const *ipaddr, int proto);

fr_client_t	*client_findbynumber(fr_client_list_t const *clients, int number);

fr_client_t	*client_read(char const *filename, CONF_SECTION *server_cs, bool check_dns);

fr_client_t	*client_from_request(request_t *request);
#ifdef __cplusplus
}
#endif
