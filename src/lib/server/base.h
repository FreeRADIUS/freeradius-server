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
 * @file lib/server/base.h
 * @brief Structures, prototypes and global variables for the FreeRADIUS server.
 *
 * @copyright 1999-2000,2002-2008  The FreeRADIUS server project
 */
RCSIDH(radiusd_h, "$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/heap.h>

typedef struct rad_request REQUEST;

#include <freeradius-devel/server/log.h>

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

#include <freeradius-devel/server/stats.h>
#include <freeradius-devel/server/realms.h>
#include <freeradius-devel/server/xlat.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/clients.h>
#include <freeradius-devel/server/process.h>
#include <freeradius-devel/server/dependency.h>

/*
 *  Let any external program building against the library know what
 *  features the library was built with.
 */
#include <freeradius-devel/features.h>

/*
 *	All POSIX systems should have these headers
 */
#include <pwd.h>
#include <grp.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WITH_TCP
#  include <freeradius-devel/server/tcp.h>
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
	RLM_MODULE_REJECT = 0,				//!< Immediately reject the request.
	RLM_MODULE_FAIL,				//!< Module failed, don't reply.
	RLM_MODULE_OK,					//!< The module is OK, continue.
	RLM_MODULE_HANDLED,				//!< The module handled the request, so stop.
	RLM_MODULE_INVALID,				//!< The module considers the request invalid.
	RLM_MODULE_USERLOCK,				//!< Reject the request (user is locked out).
	RLM_MODULE_NOTFOUND,				//!< User not found.
	RLM_MODULE_NOOP,				//!< Module succeeded without doing anything.
	RLM_MODULE_UPDATED,				//!< OK (pairs modified).
	RLM_MODULE_NUMCODES,				//!< How many valid return codes there are.
	RLM_MODULE_YIELD,				//!< for unlang.
	RLM_MODULE_UNKNOWN,				//!< Error resolving rcode (should not be
							//!< returned by modules).
} rlm_rcode_t;
extern const FR_NAME_NUMBER modreturn_table[];

typedef	rlm_rcode_t (*RAD_REQUEST_FUNP)(REQUEST *);

/** Main server configuration
 *
 * The parsed version of the main server config.
 */
typedef struct {
	char const	*name;				//!< Name of the daemon, usually 'radiusd'.
	bool		overwrite_config_name;		//!< Overwrite the configured name, as this
							///< was specified by the user on the command line.
	CONF_SECTION	*root_cs;			//!< Root of the server config.

	bool		daemonize;			//!< Should the server daemonize on startup.
	bool		spawn_workers;			//!< Should the server spawn threads.
	char const      *pid_file;			//!< Path to write out PID file.

	uint32_t	max_request_time;		//!< How long a request can be processed for before
							//!< timing out.

	uint32_t	num_networks;			//!< number of network threads
	uint32_t	num_workers;			//!< number of network threads

	bool		drop_requests;			//!< Administratively disable request processing.

	char const	*log_dir;
	char const	*local_state_dir;
	char const	*chroot_dir;
#ifdef WITH_CONF_WRITE
	char const	*write_dir;			//!< where the normalized config is written
#endif

	bool		reverse_lookups;
	bool		hostname_lookups;

	char const	*radacct_dir;
	char const	*lib_dir;
	char const	*sbin_dir;
	char const	*run_dir;
	char const	*raddb_dir;			//!< Path to raddb directory

	char const	*prefix;

	char const	*log_dest;

	char const	*log_file;
	bool		do_colourise;

	bool		log_dates_utc;
	bool		*log_timestamp;
	bool		log_timestamp_is_set;

	int32_t		syslog_facility;

	char const	*dict_dir;			//!< Where to load dictionaries from.

	struct timeval	init_delay;			//!< Initial request processing delay.

	size_t		talloc_pool_size;		//!< Size of pool to allocate to hold each #REQUEST.

	bool		write_pid;			//!< write the PID file

#ifdef HAVE_SETUID
	uid_t		server_uid;			//!< UID we're running as.
	gid_t		server_gid;			//!< GID we're runing as.
	uid_t		uid;				//!< UID we should run as.
	bool		uid_is_set;
	gid_t		gid;				//!< GID we should run as.
	bool		gid_is_set;
#endif

#ifdef ENABLE_OPENSSL_VERSION_CHECK
	char const	*allow_vulnerable_openssl;	//!< The CVE number of the last security issue acknowledged.
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
#  define REQUEST_VERIFY(_x) request_verify(__FILE__, __LINE__, _x)
#else
/*
 *  Even if were building without WITH_VERIFY_PTR
 *  the pointer must not be NULL when these various macros are used
 *  so we can add some sneaky asserts.
 */
#  define REQUEST_VERIFY(_x) rad_assert(_x)
#endif

typedef enum {
	REQUEST_ACTIVE = 1,
	REQUEST_STOP_PROCESSING,
	REQUEST_COUNTED
} rad_master_state_t;
#define REQUEST_MASTER_NUM_STATES (REQUEST_COUNTED + 1)

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

/*
 *	Forward declaration for new async listeners.
 */
typedef struct fr_async_t fr_async_t;

struct rad_request {
#ifndef NDEBUG
	uint32_t		magic; 		//!< Magic number used to detect memory corruption,
						//!< or request structs that have not been properly initialised.
#endif
	uint64_t		number; 	//!< Monotonically increasing request number. Reset on server restart.
	uint64_t		child_number; 	//!< Monotonically increasing number for children of this request
	char const		*name;		//!< for debug printing, as (%d) is no longer sufficient

	fr_dict_t const		*dict;		//!< Dictionary of the protocol that this request belongs to.

	fr_event_list_t		*el;		//!< thread-specific event list.
	fr_heap_t		*backlog;	//!< thread-specific backlog
	fr_request_state_t	request_state;	//!< state for the various protocol handlers.

	fr_dlist_head_t		data;		//!< Request metadata.

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

	fr_request_process_t	process;	//!< The function to call to move the request through the state machine.

	rlm_rcode_t		rcode;		//!< Last rcode returned by a module
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
	fr_event_timer_t const	*ev;		//!< Event in event loop tied to this request.

	int32_t			runnable_id;	//!< entry in the queue / heap of runnable packets
	int32_t			time_order_id;	//!< entry in the queue / heap of time ordered packets

	main_config_t const	*config;	//!< Pointer to the main config hack to try and deal with hup.

	struct {
		log_dst_t	*dst;		//!< First in a list of log destinations.

		fr_log_lvl_t	lvl;		//!< Log messages with lvl >= to this should be logged.

		uint8_t		unlang_indent;	//!< By how much to indent log messages. uin8_t so it's obvious
						//!< when a request has been exdented too much.
		uint8_t		module_indent;	//!< Indentation after the module prefix name.
	} log;

	uint32_t		options;	//!< mainly for proxying EAP-MSCHAPv2.

	fr_async_t		*async;		//!< for new async listeners
};				/* REQUEST typedef */

#define RAD_REQUEST_LVL_NONE	(0)		//!< No debug messages should be printed.
#define RAD_REQUEST_LVL_DEBUG	(1)
#define RAD_REQUEST_LVL_DEBUG2	(2)
#define RAD_REQUEST_LVL_DEBUG3	(3)
#define RAD_REQUEST_LVL_DEBUG4	(4)

#define RAD_REQUEST_OPTION_CTX	(1 << 1)
#define RAD_REQUEST_OPTION_DETAIL (1 << 2)

#define SECONDS_PER_DAY		86400
#define MAX_REQUEST_TIME	30
#define CLEANUP_DELAY		5
#define RETRY_DELAY		5
#define RETRY_COUNT		3
#define DEAD_TIME		120
#define EXEC_TIMEOUT		10

/* for paircmp_register */
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
extern fr_log_lvl_t	rad_debug_lvl;
extern fr_log_lvl_t	req_debug_lvl;
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


/* radiusd.c */
int		fr_crypt_check(char const *password, char const *reference_crypt);

int		log_err (char *);

/* util.c */
void (*reset_signal(int signo, void (*func)(int)))(int);
int		rad_mkdir(char *directory, mode_t mode, uid_t uid, gid_t gid);
size_t		rad_filename_make_safe(UNUSED REQUEST *request, char *out, size_t outlen,
				       char const *in, UNUSED void *arg);
size_t		rad_filename_escape(UNUSED REQUEST *request, char *out, size_t outlen,
				    char const *in, UNUSED void *arg);
ssize_t		rad_filename_unescape(char *out, size_t outlen, char const *in, size_t inlen);
char		*rad_ajoin(TALLOC_CTX *ctx, char const **argv, int argc, char c);
REQUEST		*request_alloc(TALLOC_CTX *ctx);
REQUEST		*request_alloc_fake(REQUEST *oldreq);
REQUEST		*request_alloc_proxy(REQUEST *request);
REQUEST		*request_alloc_detachable(REQUEST *request);
int		request_detach(REQUEST *fake);

void		request_data_list_init(fr_dlist_head_t *data);

#define request_data_add(_request, _unique_ptr, _unique_int, _opaque, _free_on_replace, _free_on_parent, _persist) \
		_request_data_add(_request, _unique_ptr, _unique_int, NULL, _opaque,  \
				  _free_on_replace, _free_on_parent, _persist)

#define request_data_talloc_add(_request, _unique_ptr, _unique_int, _type, _opaque, _free_on_replace, _free_on_parent, _persist) \
		_request_data_add(_request, _unique_ptr, _unique_int, STRINGIFY(_type), _opaque, \
				  _free_on_replace, _free_on_parent, _persist)

int		_request_data_add(REQUEST *request, void const *unique_ptr, int unique_int, char const *type, void *opaque,
				  bool free_on_replace, bool free_on_parent, bool persist);
void		*request_data_get(REQUEST *request, void const *unique_ptr, int unique_int);
void		*request_data_reference(REQUEST *request, void const *unique_ptr, int unique_int);

int		request_data_by_persistance(fr_dlist_head_t *out, REQUEST *request, bool persist);
void		request_data_restore(REQUEST *request, fr_dlist_head_t *in);

#ifdef WITH_VERIFY_PTR
bool		request_data_verify_parent(TALLOC_CTX *parent, fr_dlist_head_t *entry);
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
char const	*rad_default_radacct_dir(void);

#ifdef WITH_VERIFY_PTR
void		request_verify(char const *file, int line, REQUEST const *request);	/* only for special debug builds */
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
bool		rad_suid_is_down_permanent(void);
/* regex.c */

#ifdef HAVE_REGEX
/*
 *	Increasing this is essentially free
 *	It just increases memory usage. 12-16 bytes for each additional subcapture.
 */
#  define REQUEST_MAX_REGEX 32

void	regex_sub_to_request(REQUEST *request, regex_t **preg, char const *value,
			     size_t len, regmatch_t **rxmatch, size_t nmatch);

int	regex_request_to_sub(TALLOC_CTX *ctx, char **out, REQUEST *request, uint32_t num);

/*
 *	Named capture groups only supported by PCRE.
 */
#  if defined(HAVE_REGEX_PCRE2) || defined(HAVE_REGEX_PCRE)
int	regex_request_to_sub_named(TALLOC_CTX *ctx, char **out, REQUEST *request, char const *name);
#  endif
#endif

/* users_file.c */
int		pairlist_read(TALLOC_CTX *ctx, char const *file, PAIR_LIST **list, int complain);
void		pairlist_free(PAIR_LIST **);

/* auth.c */
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
void trigger_exec_init(CONF_SECTION const *cs);
int trigger_exec(REQUEST *request, CONF_SECTION const *cs, char const *name, bool quench, VALUE_PAIR *args)
		  CC_HINT(nonnull (3));
void trigger_exec_free(void);
VALUE_PAIR *trigger_args_afrom_server(TALLOC_CTX *ctx, char const *server, uint16_t port);

vp_tmpl_t	*xlat_to_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_t *xlat);
xlat_exp_t	*xlat_from_tmpl_attr(TALLOC_CTX *ctx, vp_tmpl_t *vpt);

/* paircmp.c */
int		paircmp_pairs(REQUEST *request, VALUE_PAIR *check, VALUE_PAIR *vp);

int		paircmp(REQUEST *request, VALUE_PAIR *req_list, VALUE_PAIR *check, VALUE_PAIR **rep_list);

int		paircmp_find(fr_dict_attr_t const *da);

int		paircmp_register_by_name(char const *name, fr_dict_attr_t const *from,
					 bool first_only, RAD_COMPARE_FUNC func, void *instance);

int		paircmp_register(fr_dict_attr_t const *attribute, fr_dict_attr_t const *from,
				 bool first_only, RAD_COMPARE_FUNC func, void *instance);

void		paircmp_unregister(fr_dict_attr_t const *attr, RAD_COMPARE_FUNC func);

void		paircmp_unregister_instance(void *instance);

int		paircmp_init(void);

void		paircmp_free(void);

/** Allocate a VALUE_PAIR in the request list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_add_request(_attr, _da) fr_pair_add_by_da(request->packet, _attr, &request->packet->vps, _da)

/** Allocate a VALUE_PAIR in the reply list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_add_reply(_attr, _da) fr_pair_add_by_da(request->reply, _attr, &request->reply->vps, _da)

/** Allocate a VALUE_PAIR in the control list
 *
 * @param[in] _attr	allocated.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define pair_add_control(_attr, _da) fr_pair_add_by_da(request, _attr, &request->control, _da)

/** Return or allocate a VALUE_PAIR in the request list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_request(_attr, _da) fr_pair_update_by_da(request->packet, _attr, &request->packet->vps, _da)

/** Return or allocate a VALUE_PAIR in the reply list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_reply(_attr, _da) fr_pair_update_by_da(request->reply, _attr, &request->reply->vps, _da)

/** Return or allocate a VALUE_PAIR in the control list
 *
 * @param[in] _attr	allocated or found.
 * @param[in] _da	#fr_dict_attr_t of the pair to be found or allocated.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
#define pair_update_control(_attr, _da) fr_pair_update_by_da(request, _attr, &request->control, _da)

/** Return or allocate a VALUE_PAIR in the request list
 *
 * @param[in] _da	#fr_dict_attr_t of the pair(s) to be deleted.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_request(_da) fr_pair_delete_by_da(&request->packet->vps, _da)

/** Return or allocate a VALUE_PAIR in the reply list
 *
 * @param[in] _da	#fr_dict_attr_t of the pair(s) to be deleted.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_reply(_da) fr_pair_delete_by_da(&request->reply->vps, _da)

/** Return or allocate a VALUE_PAIR in the control list
 *
 * @param[in] _da	#fr_dict_attr_t of the pair(s) to be deleted.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
#define pair_delete_control(_da) fr_pair_delete_by_da(&request->control, _da)

/* threads.c */
int		thread_pool_bootstrap(CONF_SECTION *cs, bool *spawn_workers);
int		thread_pool_init(void);
void		thread_pool_stop(void);

/*
 *	In threads.c
 */
void request_enqueue(REQUEST *request);
void request_queue_extract(REQUEST *request);

extern struct timeval sd_watchdog_interval;
REQUEST *request_setup(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
		       RADCLIENT *client, RAD_REQUEST_FUNP fun);

int request_receive(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
		    RADCLIENT *client, RAD_REQUEST_FUNP fun);

/* main_config.c */
/* Define a global config structure */
extern main_config_t const	*main_config;

void			main_config_name_set_default(main_config_t *config, char const *name, bool overwrite_config);
void			main_config_raddb_dir_set(main_config_t *config, char const *path);
void			main_config_dict_dir_set(main_config_t *config, char const *path);

main_config_t		*main_config_alloc(TALLOC_CTX *ctx);
int			main_config_init(main_config_t *config);
int			main_config_free(main_config_t **config);
void			main_config_hup(main_config_t *config);
void			hup_logfile(main_config_t *config);


/* process.c */
fr_event_list_t *fr_global_event_list(void);
int radius_event_init(void);
int radius_event_start(bool spawn_flag);
void radius_event_free(void);
int radius_event_process(void);
void radius_update_listener(rad_listen_t *listener);
void revive_home_server(fr_event_list_t *el, struct timeval *now, void *ctx);
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

#ifdef __cplusplus
}
#endif
