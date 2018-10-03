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


#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/heap.h>

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
#include <freeradius-devel/server/client.h>
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

void	regex_sub_to_request(REQUEST *request, regex_t **preg, fr_regmatch_t **regmatch);

int	regex_request_to_sub(TALLOC_CTX *ctx, char **out, REQUEST *request, uint32_t num);

/*
 *	Named capture groups only supported by PCRE.
 */
#  if defined(HAVE_REGEX_PCRE2) || defined(HAVE_REGEX_PCRE)
int	regex_request_to_sub_named(TALLOC_CTX *ctx, char **out, REQUEST *request, char const *name);
#  endif
#endif

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

/* process.c */
fr_event_list_t *fr_global_event_list(void);
int radius_event_init(void);
int radius_event_start(bool spawn_flag);
void radius_event_free(void);
int radius_event_process(void);
void radius_update_listener(rad_listen_t *listener);
void revive_home_server(fr_event_list_t *el, struct timeval *now, void *ctx);
void mark_home_server_dead(home_server_t *home, struct timeval *when);


#ifdef __cplusplus
}
#endif
