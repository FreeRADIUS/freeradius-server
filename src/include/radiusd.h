#ifndef RADIUSD_H
#define RADIUSD_H
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

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_PTHREAD_H
#include	<pthread.h>
typedef pthread_t child_pid_t;
#define child_kill pthread_kill
#else
typedef pid_t child_pid_t;
#define child_kill kill
#endif

#define NO_SUCH_CHILD_PID (child_pid_t) (0)

#ifndef NDEBUG
#define REQUEST_MAGIC (0xdeadbeef)
#endif

typedef struct auth_req {
#ifndef NDEBUG
	uint32_t		magic; /* for debugging only */
#endif
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
	int			number; /* internal server number */

	/* Could almost keep a const char * here instead of a _copy_ of the
	 * secret... but what if the RADCLIENT structure is freed because it was
	 * taken out of the config file and SIGHUPed? */
	char			proxysecret[32];
	int			proxy_is_replicate;
	int			proxy_try_count;
	time_t			proxy_next_try;

	int                     simul_max;
	int                     simul_count;
	int                     simul_mpp; /* WEIRD: 1 is false, 2 is true */

	int			finished;
	void			**container;
} REQUEST;

/*
 *  Function handler for requests.
 */
typedef		int (*RAD_REQUEST_FUNP)(REQUEST *);

typedef struct radclient {
	uint32_t		ipaddr;
	uint32_t		netmask;
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
	int			notrealm;
	struct realm		*next;
} REALM;

typedef struct pair_list {
	char			*name;
	VALUE_PAIR		*check;
	VALUE_PAIR		*reply;
	int			lineno;
	struct pair_list	*next;
	struct pair_list	*lastdefault;
} PAIR_LIST;

typedef struct main_config_t {
	int		log_auth;
	int		log_auth_badpass;
	int		log_auth_goodpass;
	int		do_usercollide;
	char 	*do_lower_user;
	char	*do_lower_pass;
	char	*do_nospace_user;
	char	*do_nospace_pass;
	char		*nospace_time;
} MAIN_CONFIG_T;

#define DEBUG	if(debug_flag)log_debug
#define DEBUG2  if (debug_flag > 1)log_debug

#define SECONDS_PER_DAY		86400
#define MAX_REQUEST_TIME	30
#define CLEANUP_DELAY		5
#define MAX_REQUESTS		256
#define RETRY_DELAY             5
#define RETRY_COUNT             3

#define L_DBG			1
#define L_AUTH			2
#define L_INFO			3
#define L_ERR			4
#define L_PROXY			5
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
typedef int (*RAD_COMPARE_FUNC)(void *instance, VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR **);

/*
 *	Global variables.
 */
extern const char	*progname;
extern int		debug_flag;
extern const char	*radacct_dir;
extern const char	*radlog_dir;
extern const char	*radlib_dir;
extern const char	*radius_dir;
extern const char	*radius_libdir;
extern uint32_t		expiration_seconds;
extern int		use_dbm;
extern int		log_stripped_names;
extern uint32_t		myip;
extern int		log_auth_detail;
extern int		auth_port;
extern int		acct_port;
extern int		proxy_port;
extern int		proxyfd;
extern int		proxy_retry_count;
extern int		proxy_retry_delay;

/* Define a global config structure */
extern struct main_config_t mainconfig;

/*
 *	Function prototypes.
 */

/* acct.c */
int		rad_accounting(REQUEST *);

/* radutmp.c */
int		radutmp_add(REQUEST *);
int		radutmp_zap(uint32_t nas, int port, char *user, time_t t);
int		radutmp_checksimul(char *name, VALUE_PAIR *, int maxsimul);

/* session.c */
int		rad_check_ts(uint32_t nasaddr, int port, const char *user,
			     const char *sessionid);
int		session_zap(uint32_t nasaddr, int port, const char *user,
			    const char *sessionid, uint32_t cliaddr,
			    char proto, time_t t);

/* radiusd.c */
void		debug_pair(FILE *, VALUE_PAIR *);
int		log_err (char *);
void		sig_cleanup(int);
int		rad_respond(REQUEST *, RAD_REQUEST_FUNP fun);

/* util.c */
void (*reset_signal(int signo, void (*func)(int)))(int);
void		request_free(REQUEST **request);
int		rad_mkdir(char *directory, int mode);
int		rad_checkfilename(const char *filename);
void		*rad_malloc(size_t size); /* calls exit(1) on error! */
void		xfree(const char *ptr);

/* client.c */
int		read_clients_file(const char *file);
RADCLIENT	*client_find(uint32_t ipno);
const char	*client_name(uint32_t ipno);
void		client_walk(void);

/* files.c */
REALM		*realm_find(const char *);
REALM		*realm_findbyaddr(uint32_t ipno);
int		pairlist_read(const char *file, PAIR_LIST **list, int complain);
void		pairlist_free(PAIR_LIST **);
int		read_config_files(void);

/* nas.c */
int		read_naslist_file(char *);
NAS		*nas_find(uint32_t ipno);
const char	*nas_name(uint32_t ipno);
const char	*nas_name2(RADIUS_PACKET *r);
NAS		*nas_findbyname(char *nasname);

/* version.c */
void		version(void);

/* log.c */
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

/* proxy.c */
int proxy_receive(REQUEST *request);
int proxy_send(REQUEST *request);

/* auth.c */
char	*auth_name(char *buf, size_t buflen, REQUEST *request, int do_cli);
int		rad_authenticate (REQUEST *);
VALUE_PAIR	*rad_getpass(REQUEST *request);

/* exec.c */
int		radius_exec_program(const char *,  REQUEST *,
				    int, const char **user_msg);

/* timestr.c */
int		timestr_match(char *, time_t);

/* valuepair.c */
int		paircompare_register(int attr, int otherattr,
				     RAD_COMPARE_FUNC func,
				     void *instance);
void		paircompare_unregister(int attr, RAD_COMPARE_FUNC func);
int		paircmp(VALUE_PAIR *request, VALUE_PAIR *check,
			VALUE_PAIR **reply);
int             simplepaircmp(VALUE_PAIR *, VALUE_PAIR *);
void		pair_builtincompare_init(void);

/* xlat.c */
int            radius_xlat2(char * out, int outlen, const char *fmt,
                            REQUEST * request);

#ifdef WITH_THREAD_POOL
/* threads.c */
extern		int thread_pool_init(void);
extern		int thread_pool_clean(time_t now);
#endif
#endif /*RADIUSD_H*/
