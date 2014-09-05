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
#ifndef RADIUSD_H
#define RADIUSD_H
/*
 * $Id$
 *
 * @file radiusd.h
 * @brief Structures, prototypes and global variables for the FreeRADIUS server.
 *
 * @copyright 1999-2000,2002-2008  The FreeRADIUS server project
 */

RCSIDH(radiusd_h, "$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/radpaths.h>
#include <freeradius-devel/conf.h>
#include <freeradius-devel/conffile.h>
#include <freeradius-devel/event.h>
#include <freeradius-devel/connection.h>

typedef struct rad_request REQUEST;

#include <freeradius-devel/log.h>

#ifdef HAVE_PTHREAD_H
#  include <pthread.h>
#else
#  include <sys/wait.h>
#endif

#ifndef NDEBUG
#  define REQUEST_MAGIC (0xdeadbeef)
#endif

/*
 *	WITH_VMPS is handled by src/include/features.h
 */
#ifdef WITHOUT_VMPS
#  undef WITH_VMPS
#endif

#ifdef WITH_TLS
#  include <freeradius-devel/tls.h>
#endif

#include <freeradius-devel/stats.h>
#include <freeradius-devel/realms.h>
#include <freeradius-devel/map.h>

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	See util.c
 */
typedef struct request_data_t request_data_t;

typedef struct radclient {
	fr_ipaddr_t		ipaddr;
	fr_ipaddr_t		src_ipaddr;
	char const		*longname;
	char const		*secret;
	char const		*shortname;
	bool			message_authenticator;
	char const		*nas_type;
	char const		*login;
	char const		*password;
	char const 		*server;
	int			number;	/* internal use only */
	CONF_SECTION const 	*cs;
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

	struct timeval		response_window;

	int			proto;
#ifdef WITH_TCP
	fr_socket_limit_t	limit;
#endif
#ifdef WITH_TLS
	bool			tls_required;
#endif

#ifdef WITH_DYNAMIC_CLIENTS
	uint32_t		lifetime;
	uint32_t		dynamic; /* was dynamically defined */
	time_t			created;
	time_t			last_new_client;
	char const		*client_server;
	bool			rate_limit;
#endif

#ifdef WITH_COA
	char const		*coa_name;
	home_server_t		*coa_server;
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

/** Return codes indicating the result of the module call
 *
 * All module functions must return one of the codes listed below (apart from
 * RLM_MODULE_NUMCODES, which is used to check for validity).
 */
typedef enum rlm_rcodes {
	RLM_MODULE_REJECT = 0,	//!< Immediately reject the request.
	RLM_MODULE_FAIL,	//!< Module failed, don't reply.
	RLM_MODULE_OK,		//!< The module is OK, continue.
	RLM_MODULE_HANDLED,	//!< The module handled the request, so stop.
	RLM_MODULE_INVALID,	//!< The module considers the request invalid.
	RLM_MODULE_USERLOCK,	//!< Reject the request (user is locked out).
	RLM_MODULE_NOTFOUND,	//!< User not found.
	RLM_MODULE_NOOP,	//!< Module succeeded without doing anything.
	RLM_MODULE_UPDATED,	//!< OK (pairs modified).
	RLM_MODULE_NUMCODES,	//!< How many valid return codes there are.
	RLM_MODULE_UNKNOWN	//!< Error resolving rcode (should not be
				//!< returned by modules).
} rlm_rcode_t;
extern const FR_NAME_NUMBER modreturn_table[];

/*
 *	For listening on multiple IP's and ports.
 */
typedef struct rad_listen_t rad_listen_t;

typedef		void (*fr_request_process_t)(REQUEST *, int);
/*
 *  Function handler for requests.
 */
typedef		int (*RAD_REQUEST_FUNP)(REQUEST *);

#define REQUEST_DATA_REGEX (0xadbeef00)
#define REQUEST_MAX_REGEX (8)

#if defined(WITH_VERIFY_PTR)
#  define VERIFY_REQUEST(_x) verify_request(__FILE__, __LINE__, _x)
#else
/*
 *  Even if were building without WITH_VERIFY_PTR
 *  the pointer must not be NULL when these various macros are used
 *  so we can add some sneaky asserts.
 */
#  define VERIFY_REQUEST(_x) rad_assert(_x)
#endif

typedef enum {
	REQUEST_ACTIVE = 1,
	REQUEST_STOP_PROCESSING,
	REQUEST_COUNTED
} rad_master_state_t;
#define REQUEST_MASTER_NUM_STATES (REQUEST_COUNTED + 1)

typedef enum {
	REQUEST_QUEUED = 1,
	REQUEST_RUNNING,
	REQUEST_PROXIED,
	REQUEST_RESPONSE_DELAY,
	REQUEST_CLEANUP_DELAY,
	REQUEST_DONE
} rad_child_state_t;
#define REQUEST_CHILD_NUM_STATES (REQUEST_DONE + 1)

struct rad_request {
#ifndef NDEBUG
	uint32_t		magic; 		//!< Magic number used to detect memory corruption,
						//!< or request structs that have not been properly initialised.
#endif
	RADIUS_PACKET		*packet;	//!< Incoming request.
#ifdef WITH_PROXY
	RADIUS_PACKET		*proxy;		//!< Outgoing request.
#endif
	RADIUS_PACKET		*reply;		//!< Outgoing response.
#ifdef WITH_PROXY
	RADIUS_PACKET		*proxy_reply;	//!< Incoming response.
#endif
	VALUE_PAIR		*config_items;	//!< VALUE_PAIRs used to set per request parameters
						//!< for modules and the server core at runtime.
	VALUE_PAIR		*username;	//!< Cached username VALUE_PAIR.
	VALUE_PAIR		*password;	//!< Cached password VALUE_PAIR.

	fr_request_process_t	process;	//!< The function to call to move the request through the state machine.

	RAD_REQUEST_FUNP	handle;		//!< The function to call to move the request through the
						//!< various server configuration sections.

	struct main_config_t	*root;		//!< Pointer to the main config hack to try and deal with hup.

	request_data_t		*data;		//!< Request metadata.

	RADCLIENT		*client;	//!< The client that originally sent us the request.

#ifdef HAVE_PTHREAD_H
	pthread_t    		child_pid;	//!< Current thread handling the request.
#endif
	time_t			timestamp;	//!< When the request was received.
	unsigned int	       	number; 	//!< Monotonically increasing request number. Reset on server restart.

	rad_listen_t		*listener;	//!< The listener that received the request.
#ifdef WITH_PROXY
	rad_listen_t		*proxy_listener;//!< Listener for outgoing requests.
#endif

	rlm_rcode_t		rcode;		//!< Last rcode returned by a module

	int			simul_max;	//!< Maximum number of concurrent sessions for this user.
#ifdef WITH_SESSION_MGMT
	int			simul_count;	//!< The current number of sessions for this user.
	int			simul_mpp; 	//!< WEIRD: 1 is false, 2 is true.
#endif

	char const		*module;	//!< Module the request is currently being processed by.
	char const		*component; 	//!< Section the request is in.

	int			delay;

	rad_master_state_t	master_state;
	rad_child_state_t	child_state;
	RAD_LISTEN_TYPE		priority;

	int			response_delay;
	int			timer_action;
	fr_event_t		*ev;

	bool			in_request_hash;
#ifdef WITH_PROXY
	bool			in_proxy_hash;

	home_server_t	       	*home_server;
	home_pool_t		*home_pool;	//!< For dynamic failover

	struct timeval		proxy_retransmit;

	uint32_t		num_proxied_requests;
	uint32_t		num_proxied_responses;
#endif

	char const		*server;
	REQUEST			*parent;

	struct {
		radlog_func_t	func;		//!< Function to call to output log messages about this
						//!< request.

		log_debug_t	lvl;		//!< Request options, currently just holds the debug level or
						//!< the request.

		uint8_t		indent;		//!< By how much to indent log messages. uin8_t so it's obvious
						//!< when a request has been exdented too much.
	} log;

#ifdef WITH_COA
	REQUEST			*coa;		//!< CoA request originated by this request.
	uint32_t		num_coa_requests;//!< Counter for number of requests sent including
						//!< retransmits.
#endif
};				/* REQUEST typedef */

#define RAD_REQUEST_OPTION_NONE		(0)
#define RAD_REQUEST_OPTION_DEBUG	(1)
#define RAD_REQUEST_OPTION_DEBUG2	(2)
#define RAD_REQUEST_OPTION_DEBUG3	(3)
#define RAD_REQUEST_OPTION_DEBUG4	(4)

typedef struct radclient_list RADCLIENT_LIST;

typedef int (*rad_listen_recv_t)(rad_listen_t *);
typedef int (*rad_listen_send_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_print_t)(rad_listen_t const *, char *, size_t);
typedef int (*rad_listen_encode_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_decode_t)(rad_listen_t *, REQUEST *);

struct rad_listen_t {
	struct rad_listen_t *next; /* should be rbtree stuff */

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

#define RAD_LISTEN_STATUS_INIT       (0)
#define RAD_LISTEN_STATUS_KNOWN      (1)
#define RAD_LISTEN_STATUS_EOL 	     (2)
#define RAD_LISTEN_STATUS_REMOVE_NOW (3)

typedef struct main_config_t {
	struct main_config *next;
	fr_ipaddr_t	myip;	/* from the command-line only */
	uint16_t	port;	/* from the command-line only */
	bool		log_auth;
	bool		log_auth_badpass;
	bool		log_auth_goodpass;
	bool		allow_core_dumps;
	uint32_t	debug_level;
	bool		daemonize;
#ifdef WITH_PROXY
	bool		proxy_requests;
#endif
	uint32_t	reject_delay;
	bool		status_server;
	char const	*allow_vulnerable_openssl;

	uint32_t	max_request_time;
	uint32_t	cleanup_delay;
	uint32_t	max_requests;
	char const	*log_file;
	char const	*dictionary_dir;
	char const	*checkrad;
	char const      *pid_file;
	rad_listen_t	*listen;
	int		syslog_facility;
	CONF_SECTION	*config;
	char const	*name;
	char const	*auth_badpass_msg;
	char const	*auth_goodpass_msg;
	bool		debug_memory;
	bool		memory_report;
	char const	*panic_action;
	char const	*denied_msg;
	struct timeval	init_delay; /* initial request processing delay */
} MAIN_CONFIG_T;

#define SECONDS_PER_DAY		86400
#define MAX_REQUEST_TIME	30
#define CLEANUP_DELAY		5
#define MAX_REQUESTS		256
#define RETRY_DELAY		5
#define RETRY_COUNT		3
#define DEAD_TIME		120
#define EXEC_TIMEOUT		10

/* for paircompare_register */
typedef int (*RAD_COMPARE_FUNC)(void *instance, REQUEST *,VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR **);

typedef enum request_fail {
	REQUEST_FAIL_UNKNOWN = 0,
	REQUEST_FAIL_NO_THREADS,	//!< No threads to handle it.
	REQUEST_FAIL_DECODE,		//!< Rad_decode didn't like it.
	REQUEST_FAIL_PROXY,		//!< Call to proxy modules failed.
	REQUEST_FAIL_PROXY_SEND,	//!< Proxy_send didn't like it.
	REQUEST_FAIL_NO_RESPONSE,	//!< We weren't told to respond, so we reject.
	REQUEST_FAIL_HOME_SERVER,	//!< The home server didn't respond.
	REQUEST_FAIL_HOME_SERVER2,	//!< Another case of the above.
	REQUEST_FAIL_HOME_SERVER3,	//!< Another case of the above.
	REQUEST_FAIL_NORMAL_REJECT,	//!< Authentication failure.
	REQUEST_FAIL_SERVER_TIMEOUT	//!< The server took too long to process the request.
} request_fail_t;

/*
 *	Global variables.
 *
 *	We really shouldn't have this many.
 */
extern char const	*progname;
extern log_debug_t	debug_flag;
extern char const	*radacct_dir;
extern char const	*radlog_dir;
extern char const	*radlib_dir;
extern bool		log_stripped_names;
extern char const	*radiusd_version;
void			radius_signal_self(int flag);

typedef enum {
	RADIUS_SIGNAL_SELF_NONE		= (0),
	RADIUS_SIGNAL_SELF_HUP		= (1 << 0),
	RADIUS_SIGNAL_SELF_TERM		= (1 << 1),
	RADIUS_SIGNAL_SELF_EXIT		= (1 << 2),
	RADIUS_SIGNAL_SELF_DETAIL	= (1 << 3),
	RADIUS_SIGNAL_SELF_NEW_FD	= (1 << 4),
	RADIUS_SIGNAL_SELF_MAX		= (1 << 5)
} radius_signal_t;
/*
 *	Function prototypes.
 */

/* acct.c */
int		rad_accounting(REQUEST *);

/* session.c */
int		rad_check_ts(uint32_t nasaddr, uint32_t nas_port, char const *user, char const *sessionid);
int		session_zap(REQUEST *request, uint32_t nasaddr,
			    uint32_t nas_port, char const *user,
			    char const *sessionid, uint32_t cliaddr,
			    char proto, int session_time);

/* radiusd.c */
#undef debug_pair
void		debug_pair(VALUE_PAIR *);
void		debug_pair_list(VALUE_PAIR *);
void 		rdebug_pair_list(int, REQUEST *, VALUE_PAIR *);
int		log_err (char *);

/* util.c */
#define MEM(x) if (!(x)) { ERROR("Out of memory"); exit(1); }
void (*reset_signal(int signo, void (*func)(int)))(int);
int		rad_mkdir(char *directory, mode_t mode);
void		*rad_malloc(size_t size); /* calls exit(1) on error! */
void		rad_const_free(void const *ptr);
REQUEST		*request_alloc(TALLOC_CTX *ctx);
REQUEST		*request_alloc_fake(REQUEST *oldreq);
REQUEST		*request_alloc_coa(REQUEST *request);
int		request_data_add(REQUEST *request,
				 void *unique_ptr, int unique_int,
				 void *opaque, bool free_opaque);
void		*request_data_get(REQUEST *request,
				  void *unique_ptr, int unique_int);
void		*request_data_reference(REQUEST *request,
				  void *unique_ptr, int unique_int);
int		rad_copy_string(char *dst, char const *src);
int		rad_copy_string_bare(char *dst, char const *src);
int		rad_copy_variable(char *dst, char const *from);
uint32_t	rad_pps(uint32_t *past, uint32_t *present, time_t *then, struct timeval *now);
int		rad_expand_xlat(REQUEST *request, char const *cmd,
				int max_argc, char *argv[], bool can_fail,
				size_t argv_buflen, char *argv_buf);
#ifdef HAVE_REGEX
void		rad_regcapture(REQUEST *request, int compare, char const *value,
			       regmatch_t rxmatch[]);
#endif
void		verify_request(char const *file, int line, REQUEST *request);	/* only for special debug builds */
#ifdef HAVE_GRP_H
bool		fr_getgid(char const *name, gid_t *gid);
#endif

/* client.c */
RADCLIENT_LIST	*clients_init(CONF_SECTION *cs);
void		clients_free(RADCLIENT_LIST *clients);
RADCLIENT_LIST	*clients_parse_section(CONF_SECTION *section, bool tls_required);
void		client_free(RADCLIENT *client);
int		client_add(RADCLIENT_LIST *clients, RADCLIENT *client);
#ifdef WITH_DYNAMIC_CLIENTS
void		client_delete(RADCLIENT_LIST *clients, RADCLIENT *client);
RADCLIENT	*client_from_request(RADCLIENT_LIST *clients, REQUEST *request);
#endif
RADCLIENT	*client_from_query(TALLOC_CTX *ctx, char const *identifier, char const *secret, char const *shortname,
				   char const *type, char const *server, bool require_ma) CC_HINT(nonnull(2, 3));

RADCLIENT	*client_find(RADCLIENT_LIST const *clients,
			     fr_ipaddr_t const *ipaddr, int proto);

RADCLIENT	*client_findbynumber(RADCLIENT_LIST const *clients,
				     int number);
RADCLIENT	*client_find_old(fr_ipaddr_t const *ipaddr);
bool		client_validate(RADCLIENT_LIST *clients, RADCLIENT *master, RADCLIENT *c);
RADCLIENT	*client_read(char const *filename, int in_server, int flag);


/* files.c */
int		pairlist_read(TALLOC_CTX *ctx, char const *file, PAIR_LIST **list, int complain);
void		pairlist_free(PAIR_LIST **);

/* version.c */
int		rad_check_lib_magic(uint64_t magic);
int 		ssl_check_consistency(void);
char const	*ssl_version_by_num(uint64_t version);
char const	*ssl_version_range(uint64_t low, uint64_t high);
char const	*ssl_version(void);
void		version(void);

/* auth.c */
char	*auth_name(char *buf, size_t buflen, REQUEST *request, bool do_cli);
int		rad_authenticate (REQUEST *);
int		rad_postauth(REQUEST *);
int		rad_virtual_server(REQUEST *);

/* exec.c */
pid_t radius_start_program(char const *cmd, REQUEST *request, bool exec_wait,
			   int *input_fd, int *output_fd,
			   VALUE_PAIR *input_pairs, bool shell_escape);
int radius_readfrom_program(REQUEST *request, int fd, pid_t pid, int timeout,
			    char *answer, int left);
int radius_exec_program(REQUEST *request, char const *cmd, bool exec_wait, bool shell_escape,
			char *user_msg, size_t msg_len, int timeout,
			VALUE_PAIR *input_pairs, VALUE_PAIR **output_pairs);
void exec_trigger(REQUEST *request, CONF_SECTION *cs, char const *name, int quench)
     CC_HINT(nonnull (3));

/* valuepair.c */
int paircompare_register(DICT_ATTR const *attribute, DICT_ATTR const *from,
	  bool first_only, RAD_COMPARE_FUNC func, void *instance);
void		paircompare_unregister(DICT_ATTR const *attr, RAD_COMPARE_FUNC func);
void		paircompare_unregister_instance(void *instance);
int		paircompare(REQUEST *request, VALUE_PAIR *req_list,
			    VALUE_PAIR *check, VALUE_PAIR **rep_list);
value_pair_tmpl_t *radius_xlat2tmpl(TALLOC_CTX *ctx, xlat_exp_t *xlat);
int		radius_xlat_do(REQUEST *request, VALUE_PAIR *vp);
int radius_compare_vps(REQUEST *request, VALUE_PAIR *check, VALUE_PAIR *vp);
int radius_callback_compare(REQUEST *request, VALUE_PAIR *req,
			    VALUE_PAIR *check, VALUE_PAIR *check_pairs,
			    VALUE_PAIR **reply_pairs);
int radius_find_compare(DICT_ATTR const *attribute);
VALUE_PAIR	*radius_paircreate(TALLOC_CTX *ctx, VALUE_PAIR **vps, unsigned int attribute, unsigned int vendor);

void module_failure_msg(REQUEST *request, char const *fmt, ...) CC_HINT(format (printf, 2, 3));
void vmodule_failure_msg(REQUEST *request, char const *fmt, va_list ap) CC_HINT(format (printf, 2, 0));

int radius_get_vp(VALUE_PAIR **out, REQUEST *request, char const *name);
int radius_copy_vp(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, char const *name);


/*
 *	Less code == fewer bugs
 *
 * @param _a attribute
 * @param _b value
 * @param _c op
 */
#define pairmake_packet(_a, _b, _c) pairmake(request->packet, &request->packet->vps, _a, _b, _c)
#define pairmake_reply(_a, _b, _c) pairmake(request->reply, &request->reply->vps, _a, _b, _c)
#define pairmake_config(_a, _b, _c) pairmake(request, &request->config_items, _a, _b, _c)


/* xlat.c */
typedef size_t (*RADIUS_ESCAPE_STRING)(REQUEST *, char *out, size_t outlen, char const *in, void *arg);

ssize_t radius_xlat(char *out, size_t outlen, REQUEST *request, char const *fmt, RADIUS_ESCAPE_STRING escape,
		    void *escape_ctx)
	CC_HINT(nonnull (1 ,3 ,4));

ssize_t radius_axlat(char **out, REQUEST *request, char const *fmt, RADIUS_ESCAPE_STRING escape, void *escape_ctx)
	CC_HINT(nonnull (1, 2, 3));

ssize_t radius_axlat_struct(char **out, REQUEST *request, xlat_exp_t const *xlat, RADIUS_ESCAPE_STRING escape,
			    void *ctx)
	CC_HINT(nonnull (1, 2, 3));

typedef ssize_t (*RAD_XLAT_FUNC)(void *instance, REQUEST *, char const *, char *, size_t);
int		xlat_register(char const *module, RAD_XLAT_FUNC func, RADIUS_ESCAPE_STRING escape,
			      void *instance);
void		xlat_unregister(char const *module, RAD_XLAT_FUNC func, void *instance);
ssize_t		xlat_fmt_to_ref(uint8_t const **out, REQUEST *request, char const *fmt);
void		xlat_free(void);

/* threads.c */
int	thread_pool_init(CONF_SECTION *cs, bool *spawn_flag);
void	thread_pool_stop(void);
int	thread_pool_addrequest(REQUEST *, RAD_REQUEST_FUNP);
pid_t	rad_fork(void);
pid_t	rad_waitpid(pid_t pid, int *status);
int	total_active_threads(void);
void	thread_pool_lock(void);
void	thread_pool_unlock(void);
void	thread_pool_queue_stats(int array[RAD_LISTEN_MAX], int pps[2]);

#ifndef HAVE_PTHREAD_H
#  define rad_fork(n) fork()
#  define rad_waitpid(a,b) waitpid(a,b, 0)
#endif

/* main_config.c */
/* Define a global config structure */
extern struct main_config_t main_config;

void set_radius_dir(TALLOC_CTX *ctx, char const *path);
char const *get_radius_dir(void);
int main_config_init(void);
int main_config_free(void);
void main_config_hup(void);
void hup_logfile(void);
void fr_suid_down(void);
void fr_suid_up(void);
void fr_suid_down_permanent(void);

/* listen.c */
void listen_free(rad_listen_t **head);
int listen_init(CONF_SECTION *cs, rad_listen_t **head, bool spawn_flag);
rad_listen_t *proxy_new_listener(home_server_t *home, uint16_t src_port);
RADCLIENT *client_listener_find(rad_listen_t *listener, fr_ipaddr_t const *ipaddr, uint16_t src_port);

#ifdef WITH_STATS
RADCLIENT_LIST *listener_find_client_list(fr_ipaddr_t const *ipaddr, uint16_t port);
#endif
rad_listen_t *listener_find_byipaddr(fr_ipaddr_t const *ipaddr, uint16_t port, int proto);
int rad_status_server(REQUEST *request);

/* event.c */
typedef enum event_corral_t {
	EVENT_CORRAL_MAIN = 0,	//!< Always main thread event list
	EVENT_CORRAL_AUX	//!< Maybe main thread or one shared by modules
} event_corral_t;

fr_event_list_t *radius_event_list_corral(event_corral_t hint);
int radius_event_init(TALLOC_CTX *ctx);
int radius_event_start(CONF_SECTION *cs, bool spawn_flag);
void radius_event_free(void);
int radius_event_process(void);
void radius_update_listener(rad_listen_t *listener);
void revive_home_server(void *ctx);
void mark_home_server_dead(home_server_t *home, struct timeval *when);

/* evaluate.c */
typedef struct fr_cond_t fr_cond_t;
int radius_expand_tmpl(char **out, REQUEST *request, value_pair_tmpl_t const *vpt);
int radius_evaluate_tmpl(REQUEST *request, int modreturn, int depth,
			 value_pair_tmpl_t const *vpt);
int radius_evaluate_map(REQUEST *request, int modreturn, int depth,
			fr_cond_t const *c);
int radius_evaluate_cond(REQUEST *request, int modreturn, int depth,
			 fr_cond_t const *c);
void radius_pairmove(REQUEST *request, VALUE_PAIR **to, VALUE_PAIR *from, bool do_xlat) CC_HINT(nonnull);

#ifdef WITH_TLS
/*
 *	For run-time patching of which function handles which socket.
 */
int dual_tls_recv(rad_listen_t *listener);
int dual_tls_send(rad_listen_t *listener, REQUEST *request);
int proxy_tls_recv(rad_listen_t *listener);
int proxy_tls_send(rad_listen_t *listener, REQUEST *request);
#endif

/*
 *	For radmin over TCP.
 */
#define PW_RADMIN_PORT 18120

#ifdef __cplusplus
}
#endif

#endif /*RADIUSD_H*/
