/*
 * radiusd.h	Structures, prototypes and global variables
 *		for the Cistron Radius server.
 *
 * Version:	$Id$
 *
 */

#include "libradius.h"
#include "radpaths.h"
#include "conf.h"
#include "missing.h"

#include <sys/time.h>

#if HAVE_PTHREAD_H
#include	<pthread.h>
typedef pthread_t child_pid_t ;
#define child_kill pthread_kill
#else
typedef pid_t child_pid_t;
#define child_kill kill
#endif

#define NO_SUCH_CHILD_PID (0)

typedef struct auth_req {
	RADIUS_PACKET		*packet;
	RADIUS_PACKET		*proxy;
	RADIUS_PACKET		*reply;
	RADIUS_PACKET		*proxy_reply;
	VALUE_PAIR		*config_items;
	VALUE_PAIR		*username;
	VALUE_PAIR		*password;
	char			secret[32];
	child_pid_t    		child_pid;
	time_t			timestamp;

	/* Could almost keep a const char * here instead of a _copy_ of the
	 * secret... but what if the RADCLIENT structure is freed because it was
	 * taken out of the config file and SIGHUPed? */
	char			proxysecret[32];
	int			proxy_is_replicate;
	int			proxy_try_count;
	time_t			proxy_next_try;

	int			finished;
	struct auth_req		*prev;
	struct auth_req		*next;
} REQUEST;

/*
 *  Function handler for requests.
 */
typedef		int (*RAD_REQUEST_FUNP)(REQUEST *);

typedef struct radclient {
	uint32_t		ipaddr;
	char			longname[256];
	u_char			secret[32];
	char			shortname[32];
	struct radclient	*next;
} RADCLIENT;

typedef struct nas {
	uint32_t		ipaddr;
	char			longname[256];
	char			shortname[32];
	char			nastype[32];
	struct nas		*next;
} NAS;

typedef struct realm {
	char			realm[64];
	char			server[64];
	uint32_t		ipaddr;
	u_char			secret[32];
	int			auth_port;
	int			acct_port;
	int			striprealm;
	int			trusted;
	int			notsuffix;
	struct realm		*next;
} REALM;

typedef struct pair_list {
	char			*name;
	VALUE_PAIR		*check;
	VALUE_PAIR		*reply;
	int			lineno;
	struct pair_list	*next;
} PAIR_LIST;

#define DEBUG	if(debug_flag)log_debug
#define DEBUG2  if (debug_flag > 1)log_debug

#define SECONDS_PER_DAY		86400
#define MAX_REQUEST_TIME	30
#define CLEANUP_DELAY		5
#define MAX_REQUESTS		256
/* FIXME: these two should be command-line options */
#define RETRY_DELAY             5
#define RETRY_COUNT             3

#define L_DBG			1
#define L_AUTH			2
#define L_INFO			3
#define L_ERR			4
#define L_PROXY			5
#define L_CONS			128

#ifndef FALSE
#  define FALSE 0
#endif
#ifndef TRUE
#  define TRUE 1
#endif

/* for paircompare_register */
typedef int (*COMPARE)(VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR **);

/*
 *	Global variables.
 */
extern const char	*progname;
extern int		debug_flag;
extern const char	*radacct_dir;
extern const char	*radlog_dir;
extern const char	*radius_dir;
extern const char	*radius_libdir;
extern uint32_t		expiration_seconds;
extern int		radius_pid;
extern int		use_dbm;
extern int		log_stripped_names;
extern int		cache_passwd;
extern uint32_t		myip;
extern int		log_auth_detail;
extern int		log_auth;
extern int		log_auth_pass;
extern int		auth_port;
extern int		acct_port;
extern int		proxy_port;
extern int		proxyfd;

/*
 *	Function prototypes.
 */

/* acct.c */
int		rad_accounting(REQUEST *);

/* radutmp.c */
int		radutmp_add(REQUEST *);
int		radutmp_zap(uint32_t nas, int port, char *user, time_t t);
int		radutmp_checksimul(char *name, VALUE_PAIR *, int maxsimul);

/* radiusd.c */
void		debug_pair(FILE *, VALUE_PAIR *);
int		log_err (char *);
void		sig_cleanup(int);
void		remove_from_request_list(REQUEST *);
int		rad_respond (REQUEST *);

/* util.c */
void (*reset_signal(int signo, void (*func)(int)))(int);
void		request_free(REQUEST *request);
RADIUS_PACKET *	build_reply(int code, REQUEST *request,
			    VALUE_PAIR *vps, const char *user_msg);

/* files.c */
RADCLIENT	*client_find(uint32_t ipno);
char		*client_name(uint32_t ipno);
REALM		*realm_find(const char *);
PAIR_LIST	*pairlist_read(const char *file, int complain);
void		pairlist_free(PAIR_LIST **);
int		read_config_files(void);

/* nas.c */
int		read_naslist_file(char *);
NAS		*nas_find(uint32_t ipno);
char		*nas_name(uint32_t ipno);
char		*nas_name2(RADIUS_PACKET *r);
NAS		*nas_findbyname(char *nasname);

/* version.c */
void		version(void);

/* log.c */
int		log(int, const char *, ...);
int		log_debug(const char *, ...);

/* pam.c */
#ifdef WITH_PAM
int		pam_pass(char *name, char *passwd, const char *pamauth);
#define PAM_DEFAULT_TYPE    "radius"
#endif

/* proxy.c */
int proxy_send(REQUEST *request);
struct timeval *proxy_setuptimeout(struct timeval *);
void proxy_retry(void);

/* auth.c */
char		*auth_name(char *buf, size_t buflen, REQUEST *request, int do_cli);
int		rad_authenticate (REQUEST *);

/* exec.c */
char		*radius_xlate(char *output, size_t outputlen,
			      const char *fmt,
			      VALUE_PAIR *req, VALUE_PAIR *reply);
int		radius_exec_program(const char *, VALUE_PAIR *, VALUE_PAIR **,
			int, const char **user_msg);

/* timestr.c */
int		timestr_match(char *, time_t);

/* valuepair.c */
int		paircompare_register(int attr, int otherattr, COMPARE func);
void		paircompare_unregister(int attr, COMPARE func);
int		paircmp(VALUE_PAIR *request, VALUE_PAIR *check,
			VALUE_PAIR **reply);
void		pair_builtincompare_init(void);

/* xlat.c */
int            radius_xlat2(char * out, int outlen, char *str,
                            REQUEST * request, VALUE_PAIR *reply);

#ifdef WITH_THREAD_POOL
/* threads.c */
extern		int thread_pool_init(int num_threads);
extern		int thread_pool_clean(void);
#endif
