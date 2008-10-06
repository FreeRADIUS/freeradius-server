/*
 * smodule.h	Interface to the server-side module system.
 *
 * Version:	$Id$
 *
 */

#ifndef FR_SMODULE_H
#define FR_SMODULE_H

#include <freeradius-devel/ident.h>
RCSIDH(smodules_h, "$Id$")

typedef struct rad_listen_t rad_listen_t;
typedef		int (*RAD_REQUEST_FUNP)(REQUEST *);
typedef int (*rad_listen_recv_t)(rad_listen_t *, RAD_REQUEST_FUNP *, REQUEST **);
typedef int (*rad_listen_send_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_print_t)(rad_listen_t *, char *, size_t);
typedef int (*rad_listen_encode_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_decode_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_parse_t)(CONF_SECTION *, rad_listen_t *);
typedef void (*rad_listen_free_t)(rad_listen_t *);

/*
 *	Types of listeners.
 *
 *	Ordered by priority!
 */
typedef enum RAD_LISTEN_TYPE {
	RAD_LISTEN_NONE = 0,
#ifdef WITH_PROXY
	RAD_LISTEN_PROXY,
#endif
	RAD_LISTEN_AUTH,
#ifdef WITH_ACCOUNTING
	RAD_LISTEN_ACCT,
#endif
#ifdef WITH_DETAIL
	RAD_LISTEN_DETAIL,
#endif
#ifdef WITH_VMPS
	RAD_LISTEN_VQP,
#endif
#ifdef WITH_DHCP
	RAD_LISTEN_DHCP,
#endif
#ifdef WITH_COMMAND_SOCKET
	RAD_LISTEN_COMMAND,
#endif
	RAD_LISTEN_MAX
} RAD_LISTEN_TYPE;


struct rad_listen_t {
	struct rad_listen_t *next; /* should be rbtree stuff */

	/*
	 *	For normal sockets.
	 */
	RAD_LISTEN_TYPE	type;
	int		fd;
	const char	*server;
	int		status;

	const struct frs_module_t *frs;
	rad_listen_recv_t recv;
	rad_listen_send_t send;
	rad_listen_encode_t encode;
	rad_listen_decode_t decode;
	rad_listen_print_t print;

	void		*data;

#ifdef WITH_STATS
	fr_stats_t	stats;
#endif
};

#define RAD_LISTEN_STATUS_INIT   (0)
#define RAD_LISTEN_STATUS_KNOWN  (1)
#define RAD_LISTEN_STATUS_CLOSED (2)
#define RAD_LISTEN_STATUS_FINISH (3)

#define FRS_MODULE_MAGIC_NUMBER ((uint32_t) (0xf5ee4ad2))
#define FRS_MODULE_INIT FRS_MODULE_MAGIC_NUMBER

typedef struct frs_module_t {
	uint32_t		magic;
	RAD_LISTEN_TYPE		type;
	/*
	 *	FIXME: Add flag for TCP sockets
	 */
	const char		*name;
	rad_listen_parse_t	parse;
	rad_listen_free_t	free;
	rad_listen_recv_t	recv;
	rad_listen_send_t	send;
	rad_listen_print_t	print;
	rad_listen_encode_t	encode;
	rad_listen_decode_t	decode;
} frs_module_t;

extern rad_listen_t *listen_alloc(const char *name);
extern int listen_socket_parse(CONF_SECTION *cs, rad_listen_t *this);

/*
 *	FIXME: This should be done in the "parse" routine,
 *	and it should allocated a fixed buffer..
 */
extern int listen_socket_print(rad_listen_t *this,
			       char *buffer, size_t bufsize);

/*
 *	This is pretty bad.
 */
typedef struct listen_socket_t {
	/*
	 *	For normal sockets.
	 */
	fr_ipaddr_t	ipaddr;
	int		port;
#ifdef SO_BINDTODEVICE
	const char	*interface;
#endif
	RADCLIENT_LIST	*clients;
} listen_socket_t;

#endif /* FR_SMODULE_H */
