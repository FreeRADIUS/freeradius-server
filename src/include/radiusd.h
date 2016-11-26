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
#ifndef _FR_RADIUSD_H
#define _FR_RADIUSD_H
/**
 * $Id$
 *
 * @file include/radiusd.h
 * @brief Structures, prototypes and global variables for the FreeRADIUS server.
 *
 * @copyright 1999-2000,2002-2008  The FreeRADIUS server project
 */
RCSIDH(radiusd_h, "$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/conf.h>
#include <freeradius-devel/conffile.h>
#include <freeradius-devel/event.h>
#include <freeradius-devel/heap.h>

typedef struct rad_request REQUEST;

#include <freeradius-devel/log.h>

#include <pthread.h>

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
#include <freeradius-devel/xlat.h>
#include <freeradius-devel/tmpl.h>
#include <freeradius-devel/map.h>
#include <freeradius-devel/clients.h>
#include <freeradius-devel/process.h>
/*
 *	All POSIX systems should have these headers
 */
#include <pwd.h>
#include <grp.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	See util.c
 */
typedef struct request_data_t request_data_t;



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
	RLM_MODULE_YIELD,	//!< for unlang
	RLM_MODULE_UNKNOWN,	//!< Error resolving rcode (should not be
				//!< returned by modules).
} rlm_rcode_t;
extern const FR_NAME_NUMBER modreturn_table[];

typedef	rlm_rcode_t (*RAD_REQUEST_FUNP)(REQUEST *);

/** Main server configuration
 *
 * The parsed version of the main server config.
 */
typedef struct main_config {
	char const	*name;				//!< Name of the daemon, usually 'radiusd'.
	CONF_SECTION	*config;			//!< Root of the server config.

	bool		log_auth;			//!< Log authentication attempts.
	bool		log_auth_badpass;		//!< Log successful authentications.
	bool		log_auth_goodpass;		//!< Log failed authentications.
	char const	*auth_badpass_msg;		//!< Additional text to append to successful auth messages.
	char const	*auth_goodpass_msg;		//!< Additional text to append to failed auth messages.

	char const	*denied_msg;			//!< Additional text to append if the user is already logged
							//!< in (simultaneous use check failed).

	bool		daemonize;			//!< Should the server daemonize on startup.
	bool		spawn_workers;			//!< Should the server spawn threads.
	char const      *pid_file;			//!< Path to write out PID file.

#ifdef WITH_PROXY
	bool		proxy_requests;			//!< Toggle to enable/disable proxying globally.
#endif
	struct timeval	reject_delay;			//!< How long to wait before sending an Access-Reject.
	bool		status_server;			//!< Whether to respond to status-server messages.


	uint32_t	max_request_time;		//!< How long a request can be processed for before
							//!< timing out.
	uint32_t	cleanup_delay;			//!< How long before cleaning up cached responses.
	uint32_t	continuation_timeout;		//!< How long to wait before cleaning up state entries.
	uint32_t	max_requests;
	bool		drop_requests;			//!< Administratively disable request processing.

	char const	*log_file;
	int		syslog_facility;

	char const	*dictionary_dir;		//!< Where to load dictionaries from.

	char const	*checkrad;			//!< Script to use to determine if a user is already
							//!< connected.

	rad_listen_t	*listen;			//!< Head of a linked list of listeners.

	struct timeval	init_delay;			//!< Initial request processing delay.

	size_t		talloc_pool_size;		//!< Size of pool to allocate to hold each #REQUEST.

	uint8_t       	state_server_id;		//!< Sets a specific byte in the state to allow the
							//!< authenticating server to be identified in packet
							//!< captures.

	bool		write_pid;			//!< write the PID file

#ifdef ENABLE_OPENSSL_VERSION_CHECK
	char const	*allow_vulnerable_openssl;	//!< The CVE number of the last security issue acknowledged.
#endif

#ifdef WITH_CONF_WRITE
	char const	*write_dir;			//!< where the normalized config is written
#endif

	fr_dict_t	*dict;				//!< Main dictionary.


	/*
	 *	Debugging options
	 */
	bool		allow_core_dumps;		//!< Whether the server is allowed to drop a core when
							//!< receiving a fatal signal.

	char const	*panic_action;			//!< Command to execute if the server receives a fatal
							//!< signal.

	uint32_t	debug_level;			//!< The base log level for the server.

	bool		talloc_memory_report;		//!< Print a memory report on what's left unfreed.
							//!< Can only be used when the server is running in single
							//!< threaded mode.

	size_t		talloc_memory_limit;		//!< Limit the amount of talloced memory the server uses.
							//!< Only applicable in single threaded mode.
} main_config_t;

#ifdef WITH_VERIFY_PTR
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

typedef enum fr_request_state_t {
	REQUEST_INIT = 0,
	REQUEST_RECV,
	REQUEST_PROCESS,
	REQUEST_SEND,
	REQUEST_OTHER_1,
	REQUEST_OTHER_2,
	REQUEST_OTHER_3,
	REQUEST_OTHER_4,
} fr_request_state_t;

struct rad_request {
#ifndef NDEBUG
	uint32_t		magic; 		//!< Magic number used to detect memory corruption,
						//!< or request structs that have not been properly initialised.
#endif
	uint64_t		number; 	//!< Monotonically increasing request number. Reset on server restart.

	fr_event_list_t		*el;		//!< thread-specific event list.
	fr_heap_t		*backlog;	//!< thread-specific backlog
	fr_request_state_t	request_state;	//!< state for the various protocol handlers.

	request_data_t		*data;		//!< Request metadata.

	RAD_LISTEN_TYPE		priority;

	rad_listen_t		*listener;	//!< The listener that received the request.
	RADCLIENT		*client;	//!< The client that originally sent us the request.

	RADIUS_PACKET		*packet;	//!< Incoming request.
	VALUE_PAIR		*username;	//!< Cached username #VALUE_PAIR from request #RADIUS_PACKET.
	VALUE_PAIR		*password;	//!< Cached password #VALUE_PAIR from request #RADIUS_PACKET.

	RADIUS_PACKET		*reply;		//!< Outgoing response.

	VALUE_PAIR		*control;	//!< #VALUE_PAIR (s) used to set per request parameters
						//!< for modules and the server core at runtime.

	uint64_t		seq_start;	//!< State sequence ID.  Stable identifier for a sequence of requests
						//!< and responses.
	TALLOC_CTX		*state_ctx;	//!< for request->state
	VALUE_PAIR		*state;		//!< #VALUE_PAIR (s) available over the lifetime of the authentication
						//!< attempt. Useful where the attempt involves a sequence of
						//!< many request/challenge packets, like OTP, and EAP.

	rad_master_state_t	master_state;	//!< Set by the master thread to signal the child that's currently
						//!< working with the request, to do something.
	rad_child_state_t	child_state;

	pthread_t    		child_pid;	//!< Current thread handling the request.
	void			*thread_ctx;	//!< for request_queue_extract()

	fr_request_process_t	process;	//!< The function to call to move the request through the state machine.

	RAD_REQUEST_FUNP	handle;		//!< The function to call to move the request through the
						//!< various server configuration sections.

	rlm_rcode_t		rcode;		//!< Last rcode returned by a module
	char const		*server;	//!< name of the virtual server which is processing the request.
	CONF_SECTION		*server_cs;	//!< virtual server which is processing the request.

	char const		*component; 	//!< Section the request is in.
	char const		*module;	//!< Module the request is currently being processed by.

	void			*stack;		//!< unlang interpreter stack.

	REQUEST			*parent;

#ifdef WITH_PROXY
	REQUEST			*proxy;		//!< proxied packet

	home_server_t	       	*home_server;
	home_pool_t		*home_pool;	//!< For dynamic failover
#endif

	struct timeval		response_delay;	//!< How long to wait before sending Access-Rejects.
	fr_event_timer_t		*ev;		//!< Event in event loop tied to this request.

	int			delay;		//!< incrementing delay for various timers
	int			heap_id;	//!< entry in the queue / heap of incoming packets

	main_config_t		*root;		//!< Pointer to the main config hack to try and deal with hup.

	int			simul_max;	//!< Maximum number of concurrent sessions for this user.
#ifdef WITH_SESSION_MGMT
	int			simul_count;	//!< The current number of sessions for this user.
	int			simul_mpp; 	//!< WEIRD: 1 is false, 2 is true.
#endif

	bool			in_request_hash;
#ifdef WITH_PROXY
	bool			in_proxy_hash;
#endif

	struct {
		radlog_func_t	func;		//!< Function to call to output log messages about this
						//!< request.

		log_lvl_t	lvl;		//!< Controls the verbosity of debug statements regarding
						//!< the request.

		uint8_t		unlang_indent;	//!< By how much to indent log messages. uin8_t so it's obvious
						//!< when a request has been exdented too much.
		uint8_t		module_indent;	//!< Indentation after the module prefix name.

		fr_log_t	*output;	//!< Output log destination.  Over-rides the global one.
	} log;

	uint32_t		options;	//!< mainly for proxying EAP-MSCHAPv2.

#ifdef WITH_COA
	REQUEST			*coa;		//!< CoA request originated by this request.
#endif
};				/* REQUEST typedef */

#define RAD_REQUEST_LVL_NONE	(0)		//!< No debug messages should be printed.
#define RAD_REQUEST_LVL_DEBUG	(1)
#define RAD_REQUEST_LVL_DEBUG2	(2)
#define RAD_REQUEST_LVL_DEBUG3	(3)
#define RAD_REQUEST_LVL_DEBUG4	(4)

#define RAD_REQUEST_OPTION_COA	(1 << 0)
#define RAD_REQUEST_OPTION_CTX	(1 << 1)

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
extern log_lvl_t	rad_debug_lvl;
extern log_lvl_t	req_debug_lvl;
extern char const	*radacct_dir;
extern char const	*radlog_dir;
extern char const	*radlib_dir;
extern bool		log_stripped_names;
extern char const	*radiusd_version;
extern char const	*radiusd_version_short;
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
rlm_rcode_t	rad_accounting(REQUEST *);

rlm_rcode_t    	rad_coa_recv(REQUEST *request);

/* session.c */
int		rad_check_ts(uint32_t nasaddr, uint32_t nas_port, char const *user, char const *sessionid);
int		session_zap(REQUEST *request, uint32_t nasaddr,
			    uint32_t nas_port, char const *user,
			    char const *sessionid, uint32_t cliaddr,
			    char proto, int session_time);

/* radiusd.c */
#undef debug_pair
void		debug_pair(VALUE_PAIR *);
void		rdebug_pair(log_lvl_t level, REQUEST *, VALUE_PAIR *, char const *);
void 		rdebug_pair_list(log_lvl_t level, REQUEST *, VALUE_PAIR *, char const *);
void		rdebug_proto_pair_list(log_lvl_t level, REQUEST *, VALUE_PAIR *, char const *);
int		log_err (char *);

/* util.c */
#define MEM(x) if (!(x)) { ERROR("%s[%u] OUT OF MEMORY", __FILE__, __LINE__); _fr_exit_now(__FILE__, __LINE__, 1); }
void (*reset_signal(int signo, void (*func)(int)))(int);
int		rad_mkdir(char *directory, mode_t mode, uid_t uid, gid_t gid);
size_t		rad_filename_make_safe(UNUSED REQUEST *request, char *out, size_t outlen,
				       char const *in, UNUSED void *arg);
size_t		rad_filename_escape(UNUSED REQUEST *request, char *out, size_t outlen,
				    char const *in, UNUSED void *arg);
ssize_t		rad_filename_unescape(char *out, size_t outlen, char const *in, size_t inlen);
void		talloc_const_free(void const *ptr);
char		*rad_ajoin(TALLOC_CTX *ctx, char const **argv, int argc, char c);
REQUEST		*request_alloc(TALLOC_CTX *ctx);
REQUEST		*request_alloc_fake(REQUEST *oldreq);
REQUEST		*request_alloc_coa(REQUEST *request);
REQUEST		*request_alloc_proxy(REQUEST *request);
int		request_data_add(REQUEST *request, void const *unique_ptr, int unique_int, void *opaque,
				 bool free_on_replace, bool free_on_parent, bool persist);
void		*request_data_get(REQUEST *request, void const *unique_ptr, int unique_int);
void		*request_data_reference(REQUEST *request, void const *unique_ptr, int unique_int);

int		request_data_by_persistance(request_data_t **out, REQUEST *request, bool persist);
void		request_data_restore(REQUEST *request, request_data_t *entry);

#ifdef WITH_VERIFY_PTR
bool		request_data_verify_parent(TALLOC_CTX *parent, request_data_t *entry);
#endif

int		rad_copy_string(char *dst, char const *src);
int		rad_copy_string_bare(char *dst, char const *src);
int		rad_copy_variable(char *dst, char const *from);
uint32_t	rad_pps(uint32_t *past, uint32_t *present, time_t *then, struct timeval *now);
int		rad_expand_xlat(REQUEST *request, char const *cmd,
				int max_argc, char const *argv[], bool can_fail,
				size_t argv_buflen, char *argv_buf);

char const	*rad_default_log_dir(void);
char const	*rad_default_lib_dir(void);
char const	*rad_default_raddb_dir(void);
char const	*rad_default_run_dir(void);
char const	*rad_default_sbin_dir(void);
char const	*rad_radacct_dir(void);

#ifdef WITH_VERIFY_PTR
void		verify_request(char const *file, int line, REQUEST *request);	/* only for special debug builds */
#endif
void		rad_mode_to_str(char out[10], mode_t mode);
void		rad_mode_to_oct(char out[5], mode_t mode);
int		rad_getpwuid(TALLOC_CTX *ctx, struct passwd **out, uid_t uid);
int		rad_getpwnam(TALLOC_CTX *ctx, struct passwd **out, char const *name);
int		rad_getgrgid(TALLOC_CTX *ctx, struct group **out, gid_t gid);
int		rad_getgrnam(TALLOC_CTX *ctx, struct group **out, char const *name);
int		rad_getgid(TALLOC_CTX *ctx, gid_t *out, char const *name);
char		*rad_asprint_uid(TALLOC_CTX *ctx, uid_t uid);
char		*rad_asprint_gid(TALLOC_CTX *ctx, gid_t gid);
void		rad_file_error(int num);
int		rad_seuid(uid_t uid);
int		rad_segid(gid_t gid);

void		rad_suid_set_down_uid(uid_t uid);
void		rad_suid_down(void);
void		rad_suid_up(void);
void		rad_suid_down_permanent(void);
/* regex.c */

#ifdef HAVE_REGEX
/*
 *	Increasing this is essentially free
 *	It just increases memory usage. 12-16 bytes for each additional subcapture.
 */
#  define REQUEST_MAX_REGEX 32

void	regex_sub_to_request(REQUEST *request, regex_t **preg, char const *value,
			     size_t len, regmatch_t rxmatch[], size_t nmatch);

int	regex_request_to_sub(TALLOC_CTX *ctx, char **out, REQUEST *request, uint32_t num);

/*
 *	Named capture groups only supported by PCRE.
 */
#  ifdef HAVE_PCRE
int	regex_request_to_sub_named(TALLOC_CTX *ctx, char **out, REQUEST *request, char const *name);
#  endif
#endif

/* files.c */
int		pairlist_read(TALLOC_CTX *ctx, char const *file, PAIR_LIST **list, int complain);
void		pairlist_free(PAIR_LIST **);

/* version.c */
int		rad_check_lib_magic(uint64_t magic);
int 		ssl_check_consistency(void);
char const	*ssl_version_by_num(uint32_t version);
char const	*ssl_version_num(void);
char const	*ssl_version_range(uint32_t low, uint32_t high);
char const	*ssl_version(void);
int		version_feature_add(CONF_SECTION *cs, char const *name, bool enabled);
int		version_number_add(CONF_SECTION *cs, char const *name, char const *version);
void		version_init_features(CONF_SECTION *cs);
void		version_numbers_init(CONF_SECTION *cs);
void		version_print(void);

/* auth.c */
char	*auth_name(char *buf, size_t buflen, REQUEST *request, bool do_cli);
rlm_rcode_t    	rad_authenticate (REQUEST *);
rlm_rcode_t    	rad_postauth(REQUEST *);
rlm_rcode_t    	rad_virtual_server(REQUEST *);

/* exec.c */
extern pid_t	(*rad_fork)(void);
extern pid_t	(*rad_waitpid)(pid_t pid, int *status);

pid_t radius_start_program(char const *cmd, REQUEST *request, bool exec_wait,
			   int *input_fd, int *output_fd,
			   VALUE_PAIR *input_pairs, bool shell_escape);
int radius_readfrom_program(int fd, pid_t pid, int timeout,
			    char *answer, int left);
int radius_exec_program(TALLOC_CTX *ctx, char *out, size_t outlen, VALUE_PAIR **output_pairs,
			REQUEST *request, char const *cmd, VALUE_PAIR *input_pairs,
			bool exec_wait, bool shell_escape, int timeout) CC_HINT(nonnull (5, 6));
void trigger_exec_init(CONF_SECTION *cs);
int trigger_exec(REQUEST *request, CONF_SECTION *cs, char const *name, bool quench, VALUE_PAIR *args)
		  CC_HINT(nonnull (3));
void trigger_exec_free(void);
VALUE_PAIR *trigger_args_afrom_server(TALLOC_CTX *ctx, char const *server, uint16_t port);

/* valuepair.c */
int paircompare_register_byname(char const *name, fr_dict_attr_t const *from,
				bool first_only, RAD_COMPARE_FUNC func, void *instance);
int paircompare_register(fr_dict_attr_t const *attribute, fr_dict_attr_t const *from,
			 bool first_only, RAD_COMPARE_FUNC func, void *instance);
void		paircompare_unregister(fr_dict_attr_t const *attr, RAD_COMPARE_FUNC func);
void		paircompare_unregister_instance(void *instance);
int		paircompare(REQUEST *request, VALUE_PAIR *req_list,
			    VALUE_PAIR *check, VALUE_PAIR **rep_list);
vp_tmpl_t	*xlat_to_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_t *xlat);
xlat_exp_t		*xlat_from_tmpl_attr(TALLOC_CTX *ctx, vp_tmpl_t *vpt);
int		radius_xlat_do(REQUEST *request, VALUE_PAIR *vp);
int radius_compare_vps(REQUEST *request, VALUE_PAIR *check, VALUE_PAIR *vp);
int radius_callback_compare(REQUEST *request, VALUE_PAIR *req,
			    VALUE_PAIR *check, VALUE_PAIR *check_pairs,
			    VALUE_PAIR **reply_pairs);
int radius_find_compare(fr_dict_attr_t const *attribute);
VALUE_PAIR	*radius_pair_create(TALLOC_CTX *ctx, VALUE_PAIR **vps, unsigned int attribute, unsigned int vendor);

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
#define pair_make_request(_a, _b, _c) fr_pair_make(request->packet, &request->packet->vps, _a, _b, _c)
#define pair_make_reply(_a, _b, _c) fr_pair_make(request->reply, &request->reply->vps, _a, _b, _c)
#define pair_make_config(_a, _b, _c) fr_pair_make(request, &request->control, _a, _b, _c)

/* threads.c */
fr_event_list_t	*thread_event_list(void);
int		thread_pool_bootstrap(CONF_SECTION *cs, bool *spawn_workers);
int		thread_pool_init(void);
void		thread_pool_stop(void);

/*
 *	In threads.c
 */
void request_enqueue(REQUEST *request);
void request_queue_extract(REQUEST *request);

REQUEST *request_setup(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
		       RADCLIENT *client, RAD_REQUEST_FUNP fun);
bool request_limit(rad_listen_t *listener, RADCLIENT *client, RADIUS_PACKET *packet);

int request_receive(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
		    RADCLIENT *client, RAD_REQUEST_FUNP fun);

/* main_config.c */
/* Define a global config structure */
extern bool			log_dates_utc;
extern main_config_t		main_config;
extern bool			event_loop_started;

void set_radius_dir(TALLOC_CTX *ctx, char const *path);
char const *get_radius_dir(void);
int main_config_init(void);
int main_config_free(void);
void main_config_hup(void);
void hup_logfile(void);

#ifdef WITH_STATS
RADCLIENT_LIST *listener_find_client_list(fr_ipaddr_t const *ipaddr, uint16_t port, int proto);
#endif
rad_listen_t *listener_find_byipaddr(fr_ipaddr_t const *ipaddr, uint16_t port, int proto);
rlm_rcode_t rad_status_server(REQUEST *request);

/* event.c */
typedef enum event_corral_t {
	EVENT_CORRAL_MAIN = 0,	//!< Always main thread event list
	EVENT_CORRAL_AUX	//!< Maybe main thread or one shared by modules
} event_corral_t;

fr_event_list_t *radius_event_list_corral(event_corral_t hint);
int radius_event_init(TALLOC_CTX *ctx);
int radius_event_start(bool spawn_flag);
void radius_event_free(void);
int radius_event_process(void);
void radius_update_listener(rad_listen_t *listener);
void revive_home_server(struct timeval *now, void *ctx);
void mark_home_server_dead(home_server_t *home, struct timeval *when);

/* evaluate.c */
typedef struct fr_cond_t fr_cond_t;
int cond_eval_tmpl(REQUEST *request, int modreturn, int depth,
			 vp_tmpl_t const *vpt);
int cond_eval_map(REQUEST *request, int modreturn, int depth,
			fr_cond_t const *c);
int cond_eval(REQUEST *request, int modreturn, int depth,
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

#endif /* _FR_RADIUSD_H */
