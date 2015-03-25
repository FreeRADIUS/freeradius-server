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
#ifndef LISTEN_H
#define LISTEN_H
/**
 * $Id$
 *
 * @file listen.h
 * @brief The listener API.
 *
 * @copyright 2015  The FreeRADIUS server project
 */

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

typedef int (*rad_listen_recv_t)(rad_listen_t *);
typedef int (*rad_listen_send_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_print_t)(rad_listen_t const *, char *, size_t);
typedef int (*rad_listen_encode_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_decode_t)(rad_listen_t *, REQUEST *);

struct rad_listen {
	rad_listen_t *next; /* should be rbtree stuff */

	/*
	 *	For normal sockets.
	 */
	RAD_LISTEN_TYPE	type;
	int		fd;
	char const	*server;
	int		status;
#ifdef WITH_TCP
	int		count;
	bool		dual;
	rbtree_t	*children;
	rad_listen_t	*parent;
#endif
	bool		nodup;
	bool		synchronous;
	uint32_t	workers;

#ifdef WITH_TLS
	fr_tls_server_conf_t *tls;
#endif

	rad_listen_recv_t recv;
	rad_listen_send_t send;
	rad_listen_encode_t encode;
	rad_listen_decode_t decode;
	rad_listen_print_t print;

	CONF_SECTION const *cs;
	void		*data;

#ifdef WITH_STATS
	fr_stats_t	stats;
#endif
};

/*
 *	This shouldn't really be exposed...
 */
typedef struct listen_socket_t {
	/*
	 *	For normal sockets.
	 */
	fr_ipaddr_t	my_ipaddr;
	uint16_t	my_port;

	char const	*interface;
#ifdef SO_BROADCAST
	int		broadcast;
#endif
	time_t		rate_time;
	uint32_t	rate_pps_old;
	uint32_t	rate_pps_now;
	uint32_t	max_rate;

	/* for outgoing sockets */
	home_server_t	*home;
	fr_ipaddr_t	other_ipaddr;
	uint16_t	other_port;

	int		proto;

#ifdef WITH_TCP
	/* for a proxy connecting to home servers */
	time_t		last_packet;
	time_t		opened;
	fr_event_t	*ev;

	fr_socket_limit_t limit;

	struct listen_socket_t *parent;
	RADCLIENT	*client;

	RADIUS_PACKET   *packet; /* for reading partial packets */
#endif

#ifdef WITH_TLS
	tls_session_t	*ssn;
	REQUEST		*request; /* horrible hacks */
	VALUE_PAIR	*certs;
	pthread_mutex_t mutex;
	uint8_t		*data;
	size_t		partial;
#endif

	RADCLIENT_LIST	*clients;
} listen_socket_t;
#endif /* LISTEN_H */

