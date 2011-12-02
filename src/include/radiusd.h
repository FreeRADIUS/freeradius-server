#ifndef RADIUSD_H
#define RADIUSD_H
/**
 * @file radiusd.h
 * @brief	Structures, prototypes and global variables
 *		for the FreeRADIUS server.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 1999,2000,2002,2003,2004,2005,2006,2007,2008  The FreeRADIUS server project
 *
 */

#include <freeradius-devel/ident.h>
RCSIDH(radiusd_h, "$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/radpaths.h>
#include <freeradius-devel/conf.h>
#include <freeradius-devel/conffile.h>
#include <freeradius-devel/event.h>
#include <freeradius-devel/connection.h>

typedef struct auth_req REQUEST;

#ifdef HAVE_PTHREAD_H
#include	<pthread.h>
#endif

#ifndef NDEBUG
#define REQUEST_MAGIC (0xdeadbeef)
#endif

/*
 *	New defines for minimizing the size of the server, to strip
 *	out functionality.
 */
#ifndef WITHOUT_PROXY
#define WITH_PROXY (1)
#endif

#ifndef WITHOUT_UNLANG
#define WITH_UNLANG (1)
#endif

#ifndef WITHOUT_ACCOUNTING
#define WITH_ACCOUNTING (1)
#endif

#ifdef WITH_ACCOUNTING
#ifndef WITHOUT_DETAIL
#define WITH_DETAIL (1)
#endif
#endif

#ifdef WITH_ACCOUNTING
#ifndef WITHOUT_SESSION_MGMT
#define WITH_SESSION_MGMT (1)
#endif
#endif

#ifndef WITHOUT_DYNAMIC_CLIENTS
#define WITH_DYNAMIC_CLIENTS (1)
#endif

#ifndef WITHOUT_STATS
#define WITH_STATS
#endif

#ifndef WITHOUT_COMMAND_SOCKET
#ifdef HAVE_SYS_UN_H
#define WITH_COMMAND_SOCKET (1)
#endif
#endif

#ifndef WITHOUT_COA
#define WITH_COA (1)
#ifndef WITH_PROXY
#error WITH_COA requires WITH_PROXY
#endif
#endif

#ifdef WITHOUT_TLS
#ifndef HAVE_OPENSSL_SSL_H
#error TLS requires OpenSSL
#endif
#else
#ifdef HAVE_OPENSSL_SSL_H
#ifndef WITH_TLS
#ifndef NO_OPENSSL
#define WITH_TLS (1)
#endif
#endif
#endif
#endif

/*
 *	WITH_VMPS is handled by src/include/autoconf.h
 */
#ifdef WITHOUT_VMPS
#undef WITH_VMPS
#endif

#ifdef WITH_TLS
#include <freeradius-devel/tls.h>
#endif

#include <freeradius-devel/stats.h>
#include <freeradius-devel/realms.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	See util.c
 */
typedef struct request_data_t request_data_t;

typedef struct radclient {
	fr_ipaddr_t		ipaddr;
	int			prefix;
	char			*longname;
	char			*secret;
	char			*shortname;
	int			message_authenticator;
	char			*nastype;
	char			*login;
	char			*password;
	char			*server;
	int			number;	/* internal use only */
	const CONF_SECTION	*cs;
#ifdef WITH_STATS
	fr_stats_t		auth;
#ifdef WITH_ACCOUNTING
	fr_stats_t		acct;
#endif
#ifdef WITH_COA
	fr_stats_t		coa;
	fr_stats_t		dsc;
#endif
#endif

	int			proto;
#ifdef WITH_TCP
	int			max_connections;
	int			num_connections;
#endif

#ifdef WITH_DYNAMIC_CLIENTS
	int			lifetime;
	int			dynamic; /* was dynamically defined */
	time_t			created;
	time_t			last_new_client;
	char			*client_server;
	int			rate_limit;
#endif

#ifdef WITH_COA
	char			*coa_name;
	home_server		*coa_server;
	home_pool_t		*coa_pool;
#endif
} RADCLIENT;

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
#ifdef WITH_COA
	RAD_LISTEN_COA,
#endif
	RAD_LISTEN_MAX
} RAD_LISTEN_TYPE;


/*
 *	For listening on multiple IP's and ports.
 */
typedef struct rad_listen_t rad_listen_t;
typedef		void (*radlog_func_t)(int, int, REQUEST *, const char *, ...);

typedef		void (*fr_request_process_t)(REQUEST *, int);
/*
 *  Function handler for requests.
 */
typedef		int (*RAD_REQUEST_FUNP)(REQUEST *);

#define REQUEST_DATA_REGEX (0xadbeef00)
#define REQUEST_MAX_REGEX (8)

struct auth_req {
#ifndef NDEBUG
	uint32_t		magic; /* for debugging only */
#endif
	RADIUS_PACKET		*packet;
#ifdef WITH_PROXY
	RADIUS_PACKET		*proxy;
#endif
	RADIUS_PACKET		*reply;
#ifdef WITH_PROXY
	RADIUS_PACKET		*proxy_reply;
#endif
	VALUE_PAIR		*config_items;
	VALUE_PAIR		*username;
	VALUE_PAIR		*password;

	fr_request_process_t	process;
	RAD_REQUEST_FUNP	handle;
	struct main_config_t	*root;

	request_data_t		*data;
	RADCLIENT		*client;
#ifdef HAVE_PTHREAD_H
	pthread_t    		child_pid;
#endif
	time_t			timestamp;
	unsigned int	       	number; /* internal server number */

	rad_listen_t		*listener;
#ifdef WITH_PROXY
	rad_listen_t		*proxy_listener;
#endif


	int                     simul_max; /* see modcall.c && xlat.c */
#ifdef WITH_SESSION_MGMT
	int                     simul_count;
	int                     simul_mpp; /* WEIRD: 1 is false, 2 is true */
#endif

	int			options; /* miscellanous options */
	const char		*module; /* for debugging unresponsive children */
	const char		*component; /* ditto */

	int			delay;

	int			master_state;
	int			child_state;
	RAD_LISTEN_TYPE		priority;

	int			timer_action;
	fr_event_t		*ev;

	int			in_request_hash;
#ifdef WITH_PROXY
	int			in_proxy_hash;

	home_server	       	*home_server;
	home_pool_t		*home_pool; /* for dynamic failover */

	struct timeval		proxy_retransmit;

	int			num_proxied_requests;
	int			num_proxied_responses;
#endif

	const char		*server;
	REQUEST			*parent;
	radlog_func_t		radlog;	/* logging function, if set */
#ifdef WITH_COA
	REQUEST			*coa;
	int			num_coa_requests;
#endif
};				/* REQUEST typedef */

#define RAD_REQUEST_OPTION_NONE            (0)
#define RAD_REQUEST_OPTION_DEBUG           (1)
#define RAD_REQUEST_OPTION_DEBUG2          (2)
#define RAD_REQUEST_OPTION_DEBUG3          (3)
#define RAD_REQUEST_OPTION_DEBUG4          (4)

#define REQUEST_ACTIVE 		(1)
#define REQUEST_STOP_PROCESSING (2)
#define REQUEST_COUNTED	        (3)

#define REQUEST_QUEUED		(1)
#define REQUEST_RUNNING		(2)
#define REQUEST_PROXIED		(3)
#define REQUEST_REJECT_DELAY	(4)
#define REQUEST_CLEANUP_DELAY	(5)
#define REQUEST_DONE		(6)

typedef struct radclient_list RADCLIENT_LIST;

typedef enum pair_lists {
	PAIR_LIST_UNKNOWN = 0,
	PAIR_LIST_REQUEST,
	PAIR_LIST_REPLY,
	PAIR_LIST_CONTROL,
#ifdef WITH_PROXY
	PAIR_LIST_PROXY_REQUEST,
	PAIR_LIST_PROXY_REPLY,
#endif
#ifdef WITH_COA
	PAIR_LIST_COA,
	PAIR_LIST_COA_REPLY,
	PAIR_LIST_DM,
	PAIR_LIST_DM_REPLY
#endif
} pair_lists_t;

extern const FR_NAME_NUMBER pair_lists[];

typedef struct pair_list {
	const char		*name;
	VALUE_PAIR		*check;
	VALUE_PAIR		*reply;
	int			lineno;
	int			order;
	struct pair_list	*next;
	struct pair_list	*lastdefault;
} PAIR_LIST;

typedef int (*rad_listen_recv_t)(rad_listen_t *);
typedef int (*rad_listen_send_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_print_t)(const rad_listen_t *, char *, size_t);
typedef int (*rad_listen_encode_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_decode_t)(rad_listen_t *, REQUEST *);

struct rad_listen_t {
	struct rad_listen_t *next; /* should be rbtree stuff */

	/*
	 *	For normal sockets.
	 */
	RAD_LISTEN_TYPE	type;
	int		fd;
	const char	*server;
	int		status;
#ifdef WITH_TCP
	int		count;
#endif

#ifdef WITH_TLS
	fr_tls_server_conf_t *tls;
#endif

	rad_listen_recv_t recv;
	rad_listen_send_t send;
	rad_listen_encode_t encode;
	rad_listen_decode_t decode;
	rad_listen_print_t print;

	const CONF_SECTION *cs;
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
	int		my_port;

	const char	*interface;
#ifdef SO_BROADCAST
	int		broadcast;
#endif
	
	/* for outgoing sockets */
	home_server	*home;
	fr_ipaddr_t	other_ipaddr;
	int		other_port;

	int		proto;

#ifdef WITH_TCP
  	/* for a proxy connecting to home servers */
	time_t		last_packet;
	time_t		opened;
	fr_event_t	*ev;

	/* for clients connecting to the server */
	int		max_connections;
	int		num_connections;
	struct listen_socket_t *parent;
	RADCLIENT	*client;

	RADIUS_PACKET   *packet; /* for reading partial packets */
#endif

#ifdef WITH_TLS
	tls_session_t	*ssn;
	REQUEST		*request; /* horrible hacks */
	VALUE_PAIR	*certs;
	pthread_mutex_t mutex;
#endif

	RADCLIENT_LIST	*clients;
} listen_socket_t;

#define RAD_LISTEN_STATUS_INIT   (0)
#define RAD_LISTEN_STATUS_KNOWN  (1)
#define RAD_LISTEN_STATUS_REMOVE_FD (2)
#define RAD_LISTEN_STATUS_CLOSED (3)
#define RAD_LISTEN_STATUS_FINISH (4)

typedef enum radlog_dest_t {
  RADLOG_STDOUT = 0,
  RADLOG_FILES,
  RADLOG_SYSLOG,
  RADLOG_STDERR,
  RADLOG_NULL,
  RADLOG_NUM_DEST
} radlog_dest_t;

typedef struct main_config_t {
	struct main_config *next;
	int		refcount;
	fr_ipaddr_t	myip;	/* from the command-line only */
	int		port;	/* from the command-line only */
	int		log_auth;
	int		log_auth_badpass;
	int		log_auth_goodpass;
	int		allow_core_dumps;
	int		debug_level;
#ifdef WITH_PROXY
	int		proxy_requests;
#endif
	int		reject_delay;
	int		status_server;
	int		max_request_time;
	int		cleanup_delay;
	int		max_requests;
#ifdef DELETE_BLOCKED_REQUESTS
	int		kill_unresponsive_children;
#endif
	char		*log_file;
	char		*checkrad;
	const char      *pid_file;
	rad_listen_t	*listen;
	int		syslog_facility;
	int		radlog_fd;
	radlog_dest_t	radlog_dest;
	CONF_SECTION	*config;
	const char	*name;
	const char	*auth_badpass_msg;
	const char	*auth_goodpass_msg;
} MAIN_CONFIG_T;

#define DEBUG	if(debug_flag)log_debug
#define DEBUG2  if (debug_flag > 1)log_debug
#define DEBUG3  if (debug_flag > 2)log_debug
#define DEBUG4  if (debug_flag > 3)log_debug

#if __GNUC__ >= 3
#define RDEBUG(fmt, ...)   if(request && request->radlog) request->radlog(L_DBG, 1, request, fmt, ## __VA_ARGS__)
#define RDEBUG2(fmt, ...)  if(request && request->radlog) request->radlog(L_DBG, 2, request, fmt, ## __VA_ARGS__)
#define RDEBUG3(fmt, ...)  if(request && request->radlog) request->radlog(L_DBG, 3, request, fmt, ## __VA_ARGS__)
#define RDEBUG4(fmt, ...)  if(request && request->radlog) request->radlog(L_DBG, 4, request, fmt, ## __VA_ARGS__)
#else
#define RDEBUG  DEBUG
#define RDEBUG2 DEBUG2
#define RDEBUG3 DEBUG3
#define RDEBUG4 DEBUG4
#endif

#define SECONDS_PER_DAY		86400
#define MAX_REQUEST_TIME	30
#define CLEANUP_DELAY		5
#define MAX_REQUESTS		256
#define RETRY_DELAY             5
#define RETRY_COUNT             3
#define DEAD_TIME               120

#define L_DBG			1
#define L_AUTH			2
#define L_INFO			3
#define L_ERR			4
#define L_PROXY			5
#define L_ACCT			6
#define L_CONS			128

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
/*
 *	This definition of true as NOT false is definitive. :) Making
 *	it '1' can cause problems on stupid platforms.  See articles
 *	on C portability for more information.
 */
#define TRUE (!FALSE)
#endif

/* for paircompare_register */
typedef int (*RAD_COMPARE_FUNC)(void *instance, REQUEST *,VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR **);

typedef enum request_fail_t {
  REQUEST_FAIL_UNKNOWN = 0,
  REQUEST_FAIL_NO_THREADS,	/* no threads to handle it */
  REQUEST_FAIL_DECODE,		/* rad_decode didn't like it */
  REQUEST_FAIL_PROXY,		/* call to proxy modules failed */
  REQUEST_FAIL_PROXY_SEND,	/* proxy_send didn't like it */
  REQUEST_FAIL_NO_RESPONSE,	/* we weren't told to respond, so we reject */
  REQUEST_FAIL_HOME_SERVER,	/* the home server didn't respond */
  REQUEST_FAIL_HOME_SERVER2,	/* another case of the above */
  REQUEST_FAIL_HOME_SERVER3,	/* another case of the above */
  REQUEST_FAIL_NORMAL_REJECT,	/* authentication failure */
  REQUEST_FAIL_SERVER_TIMEOUT	/* the server took too long to process the request */
} request_fail_t;

/*
 *	Global variables.
 *
 *	We really shouldn't have this many.
 */
extern const char	*progname;
extern int		debug_flag;
extern const char	*radacct_dir;
extern const char	*radlog_dir;
extern const char	*radlib_dir;
extern char		*radius_dir;
extern const char	*radius_libdir;
extern uint32_t		expiration_seconds;
extern int		log_stripped_names;
extern int		log_auth_detail;
extern const char      *radiusd_version;
void			radius_signal_self(int flag);

#define RADIUS_SIGNAL_SELF_NONE		(0)
#define RADIUS_SIGNAL_SELF_HUP		(1 << 0)
#define RADIUS_SIGNAL_SELF_TERM		(1 << 1)
#define RADIUS_SIGNAL_SELF_EXIT		(1 << 2)
#define RADIUS_SIGNAL_SELF_DETAIL	(1 << 3)
#define RADIUS_SIGNAL_SELF_NEW_FD	(1 << 4)
#define RADIUS_SIGNAL_SELF_MAX		(1 << 5)


/*
 *	Function prototypes.
 */

/* acct.c */
int		rad_accounting(REQUEST *);

/* session.c */
int		rad_check_ts(uint32_t nasaddr, unsigned int port, const char *user,
			     const char *sessionid);
int		session_zap(REQUEST *request, uint32_t nasaddr,
			    unsigned int port, const char *user,
			    const char *sessionid, uint32_t cliaddr,
			    char proto,int session_time);

/* radiusd.c */
#undef debug_pair
void		debug_pair(VALUE_PAIR *);
void		debug_pair_list(VALUE_PAIR *);
int		log_err (char *);

/* util.c */
void (*reset_signal(int signo, void (*func)(int)))(int);
void		request_free(REQUEST **request);
int		rad_mkdir(char *directory, int mode);
int		rad_checkfilename(const char *filename);
void		*rad_malloc(size_t size); /* calls exit(1) on error! */
void		*rad_calloc(size_t size); /* calls exit(1) on error! */
REQUEST		*request_alloc(void);
REQUEST		*request_alloc_fake(REQUEST *oldreq);
REQUEST		*request_alloc_coa(REQUEST *request);
int		request_data_add(REQUEST *request,
				 void *unique_ptr, int unique_int,
				 void *opaque, void (*free_opaque)(void *));
void		*request_data_get(REQUEST *request,
				  void *unique_ptr, int unique_int);
void		*request_data_reference(REQUEST *request,
				  void *unique_ptr, int unique_int);
int		rad_copy_string(char *dst, const char *src);
int		rad_copy_variable(char *dst, const char *from);

/* client.c */
RADCLIENT_LIST	*clients_init(void);
void		clients_free(RADCLIENT_LIST *clients);
RADCLIENT_LIST	*clients_parse_section(CONF_SECTION *section);
void		client_free(RADCLIENT *client);
int		client_add(RADCLIENT_LIST *clients, RADCLIENT *client);
#ifdef WITH_DYNAMIC_CLIENTS
void		client_delete(RADCLIENT_LIST *clients, RADCLIENT *client);
RADCLIENT	*client_create(RADCLIENT_LIST *clients, REQUEST *request);
#endif
RADCLIENT	*client_find(const RADCLIENT_LIST *clients,
			     const fr_ipaddr_t *ipaddr, int proto);

RADCLIENT	*client_findbynumber(const RADCLIENT_LIST *clients,
				     int number);
RADCLIENT	*client_find_old(const fr_ipaddr_t *ipaddr);
int		client_validate(RADCLIENT_LIST *clients, RADCLIENT *master,
				RADCLIENT *c);
RADCLIENT	*client_read(const char *filename, int in_server, int flag);


/* files.c */
int		pairlist_read(const char *file, PAIR_LIST **list, int complain);
void		pairlist_free(PAIR_LIST **);

/* version.c */
void		version(void);

/* log.c */
int		vradlog(int, const char *, va_list ap);
int		radlog(int, const char *, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 2, 3)))
#endif
;
int		log_debug(const char *, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 1, 2)))
#endif
;
void 		vp_listdebug(VALUE_PAIR *vp);
void radlog_request(int lvl, int priority, REQUEST *request, const char *msg, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 4, 5)))
#endif
;

/* auth.c */
char	*auth_name(char *buf, size_t buflen, REQUEST *request, int do_cli);
int		rad_authenticate (REQUEST *);
int		rad_postauth(REQUEST *);

/* exec.c */
pid_t radius_start_program(const char *cmd, REQUEST *request,
			int exec_wait,
			int *input_fd,
			int *output_fd,
			VALUE_PAIR *input_pairs,
			int shell_escape);
int radius_readfrom_program(int fd, pid_t pid, int timeout, char *answer, int left);
int		radius_exec_program(const char *,  REQUEST *, int,
				    char *user_msg, int msg_len,
				    VALUE_PAIR *input_pairs,
				    VALUE_PAIR **output_pairs,
					int shell_escape);
void exec_trigger(REQUEST *request, CONF_SECTION *cs, const char *name);

/* timestr.c */
int		timestr_match(char *, time_t);

/* valuepair.c */
int		paircompare_register(unsigned int attr, int otherattr,
				     RAD_COMPARE_FUNC func,
				     void *instance);
void		paircompare_unregister(unsigned int attr, RAD_COMPARE_FUNC func);
int		paircompare(REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check,
			    VALUE_PAIR **reply);
void		pairxlatmove(REQUEST *, VALUE_PAIR **to, VALUE_PAIR **from);
int radius_compare_vps(REQUEST *request, VALUE_PAIR *check, VALUE_PAIR *vp);
int radius_callback_compare(REQUEST *req, VALUE_PAIR *request,
			    VALUE_PAIR *check, VALUE_PAIR *check_pairs,
			    VALUE_PAIR **reply_pairs);
int radius_find_compare(unsigned int attribute);
VALUE_PAIR	*radius_paircreate(REQUEST *request, VALUE_PAIR **vps,
				   unsigned int attribute, unsigned int vendor, int type);
VALUE_PAIR *radius_pairmake(REQUEST *request, VALUE_PAIR **vps,
			    const char *attribute, const char *value,
			    int operator);

/* xlat.c */
typedef size_t (*RADIUS_ESCAPE_STRING)(char *out, size_t outlen, const char *in);

int            radius_xlat(char * out, int outlen, const char *fmt,
			   REQUEST * request, RADIUS_ESCAPE_STRING func);
typedef size_t (*RAD_XLAT_FUNC)(void *instance, REQUEST *, char *, char *, size_t, RADIUS_ESCAPE_STRING func);
int		xlat_register(const char *module, RAD_XLAT_FUNC func,
			      void *instance);
void		xlat_unregister(const char *module, RAD_XLAT_FUNC func);
void		xlat_free(void);

/* threads.c */
extern		int thread_pool_init(CONF_SECTION *cs, int *spawn_flag);
extern		int thread_pool_addrequest(REQUEST *, RAD_REQUEST_FUNP);
extern		pid_t rad_fork(void);
extern		pid_t rad_waitpid(pid_t pid, int *status);
extern          int total_active_threads(void);
extern          void thread_pool_lock(void);
extern          void thread_pool_unlock(void);
extern		void thread_pool_queue_stats(int *array);

#ifndef HAVE_PTHREAD_H
#define rad_fork(n) fork()
#define rad_waitpid(a,b) waitpid(a,b, 0)
#endif

/* mainconfig.c */
/* Define a global config structure */
extern struct main_config_t mainconfig;

int read_mainconfig(int reload);
int free_mainconfig(void);
void hup_mainconfig(void);
void fr_suid_down(void);
void fr_suid_up(void);
void fr_suid_down_permanent(void);

/* listen.c */
void listen_free(rad_listen_t **head);
int listen_init(CONF_SECTION *cs, rad_listen_t **head, int spawn_flag);
int proxy_new_listener(home_server *home, int src_port);
RADCLIENT *client_listener_find(rad_listen_t *listener,
				const fr_ipaddr_t *ipaddr, int src_port);

#ifdef WITH_STATS
RADCLIENT_LIST *listener_find_client_list(const fr_ipaddr_t *ipaddr,
					  int port);
#endif
rad_listen_t *listener_find_byipaddr(const fr_ipaddr_t *ipaddr, int port,
				     int proto);
int rad_status_server(REQUEST *request);

/* event.c */
int radius_event_init(CONF_SECTION *cs, int spawn_flag);
void radius_event_free(void);
int radius_event_process(void);
int event_new_fd(rad_listen_t *listener);
void revive_home_server(void *ctx);
void mark_home_server_dead(home_server *home, struct timeval *when);

/* evaluate.c */
int radius_evaluate_condition(REQUEST *request, int modreturn, int depth,
			      const char **ptr, int evaluate_it, int *presult);
int radius_update_attrlist(REQUEST *request, CONF_SECTION *cs,
			   VALUE_PAIR *input_vps, const char *name);
void radius_pairmove(REQUEST *request, VALUE_PAIR **to, VALUE_PAIR *from);

VALUE_PAIR **radius_list(REQUEST *request, pair_lists_t list);
pair_lists_t radius_list_name(const char **name, pair_lists_t unknown);
int radius_ref_request(REQUEST **request, const char **name);
int radius_get_vp(REQUEST *request, const char *name, VALUE_PAIR **vp_p);

#ifdef WITH_TLS
/*
 *	For run-time patching of which function handles which socket.
 */
int dual_tls_recv(rad_listen_t *listener);
int dual_tls_send(rad_listen_t *listener, REQUEST *request);
int proxy_tls_recv(rad_listen_t *listener);
int proxy_tls_send(rad_listen_t *listener, REQUEST *request);
#endif

#ifdef __cplusplus
}
#endif

#endif /*RADIUSD_H*/
