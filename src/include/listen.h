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
#ifndef _FR_LISTEN_H
#define _FR_LISTEN_H
#include <freeradius-devel/pcap.h>
/**
 * $Id$
 *
 * @file include/listen.h
 * @brief Listener API.  Binds sockets to protocol encoders/decoders.
 *
 * @copyright 2015  The FreeRADIUS server project
 */
RCSIDH(listen_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	Types of listeners.
 *
 *	Ordered by priority!
 */
typedef enum RAD_LISTEN_TYPE {
	RAD_LISTEN_NONE = 0,
	RAD_LISTEN_PROXY,
	RAD_LISTEN_AUTH,
	RAD_LISTEN_ACCT,
	RAD_LISTEN_DETAIL,
	RAD_LISTEN_VQP,
	RAD_LISTEN_DHCP,
	RAD_LISTEN_COMMAND,
	RAD_LISTEN_COA,
	RAD_LISTEN_MAX
} RAD_LISTEN_TYPE;

typedef enum RAD_LISTEN_STATUS {
	RAD_LISTEN_STATUS_INIT = 0,
	RAD_LISTEN_STATUS_KNOWN,
	RAD_LISTEN_STATUS_FROZEN,
	RAD_LISTEN_STATUS_EOL,
	RAD_LISTEN_STATUS_REMOVE_NOW
} RAD_LISTEN_STATUS;

typedef struct rad_listen rad_listen_t;
typedef struct fr_protocol_t fr_protocol_t;

typedef int (*rad_listen_recv_t)(rad_listen_t *);
typedef int (*rad_listen_send_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_print_t)(rad_listen_t const *, char *, size_t);
typedef void (*rad_listen_debug_t)(REQUEST *, RADIUS_PACKET *, bool received);
typedef int (*rad_listen_encode_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_decode_t)(rad_listen_t *, REQUEST *);

struct rad_listen {
	rad_listen_t		*next; /* should be rbtree stuff */
	fr_protocol_t		*proto;

	/*
	 *	For normal sockets.
	 */
	RAD_LISTEN_TYPE		type;
	int			fd;
	char const		*server;	//!< Name of the virtual server that the listener is associated with
	CONF_SECTION		*server_cs;	//!< Virtual server that the listener is associated with
	int			status;

#ifdef WITH_TCP
	int			count;
	bool			dual;
	rbtree_t		*children;
	rad_listen_t		*parent;
#endif
	bool			nodup;

#ifdef WITH_TLS
	fr_tls_conf_t	*tls;
#endif

	rad_listen_recv_t	recv;
	rad_listen_send_t	send;
	rad_listen_encode_t	encode;
	rad_listen_decode_t	decode;
	rad_listen_debug_t	debug;
	rad_listen_print_t	print;

	/*
	 *	Events associated with this listener
	 */
	struct timeval		when;
	fr_event_t		*ev;

	CONF_SECTION const	*cs;
	void			*data;

#ifdef WITH_STATS
	fr_stats_t		stats;
#endif
};

#ifdef HAVE_LIBPCAP
typedef const char* (*rad_pcap_filter_builder)(rad_listen_t *);
#endif

/*
 *	This shouldn't really be exposed...
 */
typedef struct listen_socket_t {
	/*
	 *	For normal sockets.
	 */
	fr_ipaddr_t		my_ipaddr;
	uint16_t		my_port;

	char const		*interface;

#ifdef HAVE_LIBPCAP
	fr_pcap_t		*pcap;
	fr_pcap_type_t		pcap_type;
	rad_pcap_filter_builder	pcap_filter_builder;
#endif

	int			broadcast;
	time_t			rate_time;
	uint32_t		rate_pps_old;
	uint32_t		rate_pps_now;
	uint32_t		max_rate;

	/* for outgoing sockets */
	home_server_t		*home;
	fr_ipaddr_t		other_ipaddr;
	uint16_t		other_port;

	int			proto;


	uint32_t		recv_buff;	//!< Socket receive buffer size we only allow
						//!< configuration of SO_RCVBUF, as SO_SNDBUF
						//!< controls the maximum datagram size.

#ifdef WITH_TCP
	/* for a proxy connecting to home servers */
	time_t			last_packet;
	time_t			opened;

	fr_socket_limit_t	limit;
	struct listen_socket_t	*parent;
	RADCLIENT		*client;

	RADIUS_PACKET  	 	*packet; /* for reading partial packets */
#endif

#ifdef WITH_TLS
	tls_session_t		*tls_session;
	REQUEST			*request; /* horrible hacks */
	VALUE_PAIR		*cert_vps;
	pthread_mutex_t		mutex;
	uint8_t			*data;
	size_t			partial;
#endif

	RADCLIENT_LIST		*clients;
} listen_socket_t;

int listen_bootstrap(CONF_SECTION *server, CONF_SECTION *cs, char const *server_name);
int listen_compile(CONF_SECTION *server_cs, CONF_SECTION *listen_cs);
void listen_free(rad_listen_t **head);
int listen_init(rad_listen_t **head, bool spawn_flag);
rad_listen_t *proxy_new_listener(TALLOC_CTX *ctx, home_server_t *home, uint16_t src_port);
RADCLIENT *client_listener_find(rad_listen_t *listener, fr_ipaddr_t const *ipaddr, uint16_t src_port);

#ifdef __cplusplus
}
#endif
#endif /* _FR_LISTEN_H */
