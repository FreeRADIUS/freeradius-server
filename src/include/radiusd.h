#ifndef RADIUSD_H
#define RADIUSD_H
/*
 * radiusd.h	Structures, prototypes and global variables
 *		for the FreeRADIUS server.
 *
 * Version:	$Id$
 *
 */
#include "libradius.h"
#include "radpaths.h"
#include "conf.h"
#include "missing.h"
#include "conffile.h"

#include <stdarg.h>

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
	int			options; /* miscellanous options */
	void			**container;
} REQUEST;

#define RAD_REQUEST_OPTION_NONE            (0)
#define RAD_REQUEST_OPTION_LOGGED_CHILD    (1 << 0)
#define RAD_REQUEST_OPTION_DELAYED_REJECT  (1 << 1)

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
	char			nastype[32];
	char			login[32];
	char			password[32];
	struct radclient	*next;
} RADCLIENT;

typedef struct nas {
	uint32_t		ipaddr;
	char			longname[256];
	char			shortname[32];
	char			nastype[32];
	struct nas		*next;
} NAS;

typedef struct _realm {
	char			realm[64];
	char			server[64];
	uint32_t		ipaddr;
	uint32_t		acct_ipaddr;
	u_char			secret[32];
	int			auth_port;
	int			acct_port;
	int			striprealm;
	int			trusted;
	int			notrealm;
	int			active;
	time_t			wakeup;
	int			acct_active;
	time_t			acct_wakeup;
	int			ldflag;
	int			chose;
	int			node;
	int			total;
	struct _realm		*next;
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
	struct main_config *next;
	time_t		config_dead_time;
	uint32_t	myip;
	int		log_auth;
	int		log_auth_badpass;
	int		log_auth_goodpass;
	int		do_usercollide;
	int		allow_core_dumps;
	int		debug_level;
	int		proxy_requests;
	int		proxy_synchronous;
	int		proxy_dead_time;
	int		proxy_retry_count;
	int		proxy_retry_delay;
	int		proxy_fallback;
	int		max_proxies;
	int		reject_delay;
	int		status_server;
	int		max_request_time;
	int		cleanup_delay;
	int		max_requests;
	int		kill_unresponsive_children;
	char 		*do_lower_user;
	char		*do_lower_pass;
	char		*do_nospace_user;
	char		*do_nospace_pass;
	char		*nospace_time;
	char		*log_file;
	char		*checkrad;
	const char      *pid_file;
	const char	*uid_name;
	const char	*gid_name;
	CONF_SECTION	*config;
	RADCLIENT	*clients;
	REALM		*realms;
} MAIN_CONFIG_T;

#define DEBUG	if(debug_flag)log_debug
#define DEBUG2  if (debug_flag > 1)log_debug

#define SECONDS_PER_DAY		86400
#define MAX_REQUEST_TIME	30
#define CLEANUP_DELAY		5
#define MAX_REQUESTS		256
#define RETRY_DELAY             5
#define RETRY_COUNT             3
#define DEAD_TIME               120
#define MAX_PROXIES		15

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
typedef int (*RAD_COMPARE_FUNC)(void *instance, REQUEST *,VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR **);

typedef enum radlog_dest_t {
  RADLOG_FILES = 0,
  RADLOG_SYSLOG,
  RADLOG_STDOUT,
  RADLOG_STDERR,
  RADLOG_NULL
} radlog_dest_t;

/*
 *	Global variables.
 */
extern const char	*progname;
extern int		debug_flag;
extern int		syslog_facility;
extern const char	*radacct_dir;
extern const char	*radlog_dir;
extern const char	*radlib_dir;
extern const char	*radius_dir;
extern const char	*radius_libdir;
extern radlog_dest_t	radlog_dest;
extern uint32_t		expiration_seconds;
extern int		log_stripped_names;
extern int		log_auth_detail;
extern int		auth_port;
extern int		acct_port;
extern int		proxy_port;
extern int		proxyfd;
extern const char      *radiusd_version;

/*
 *	Function prototypes.
 */

/* acct.c */
int		rad_accounting(REQUEST *);

/* session.c */
int		rad_check_ts(uint32_t nasaddr, int port, const char *user,
			     const char *sessionid);
int		session_zap(int fd, uint32_t nasaddr, int port, const char *user,
			    const char *sessionid, uint32_t cliaddr,
			    char proto, time_t t);

/* radiusd.c */
void		debug_pair(FILE *, VALUE_PAIR *);
int		log_err (char *);
void		sig_cleanup(int);
void		queue_sig_cleanup(int);
int		rad_process(REQUEST *, int);
int		rad_respond(REQUEST *, RAD_REQUEST_FUNP fun);

/* util.c */
void (*reset_signal(int signo, void (*func)(int)))(int);
void		request_free(REQUEST **request);
int		rad_mkdir(char *directory, int mode);
int		rad_checkfilename(const char *filename);
void		*rad_malloc(size_t size); /* calls exit(1) on error! */
void		xfree(const char *ptr);
void		rad_assert_fail (const char *file, unsigned int line);

/* client.c */
int		read_clients_file(const char *file);
RADCLIENT	*client_find(uint32_t ipno);
const char	*client_name(uint32_t ipno);
void		client_walk(void);
void		clients_free(RADCLIENT *cl);

/* files.c */
REALM		*realm_find(const char *, int);
REALM		*realm_findbyaddr(uint32_t ipno, int port);
void		realm_free(REALM *cl);
void		realm_disable(uint32_t ipno, int port);
int		pairlist_read(const char *file, PAIR_LIST **list, int complain);
void		pairlist_free(PAIR_LIST **);
int		read_config_files(void);
int		read_realms_file(const char *file);
extern		void check_proxies(int);

/* nas.c */
int		read_naslist_file(char *);
NAS		*nas_find(uint32_t ipno);
const char	*nas_name(uint32_t ipno);
const char	*nas_name2(RADIUS_PACKET *r);
char  *		nas_name3(char *buf, size_t buflen, uint32_t ipno);
NAS		*nas_findbyname(char *nasname);

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

/* proxy.c */
int proxy_receive(REQUEST *request);
int proxy_send(REQUEST *request);

/* auth.c */
char	*auth_name(char *buf, size_t buflen, REQUEST *request, int do_cli);
int		rad_authenticate (REQUEST *);
VALUE_PAIR	*rad_getpass(REQUEST *request);
int             rad_check_return(VALUE_PAIR *list);
int		rad_check_password(REQUEST *request);

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
int		paircmp(REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check,
			VALUE_PAIR **reply);
int		simplepaircmp(REQUEST *, VALUE_PAIR *, VALUE_PAIR *);
void		pair_builtincompare_init(void);
void		pairxlatmove(REQUEST *, VALUE_PAIR **to, VALUE_PAIR **from);

/* xlat.c */
typedef int (*RADIUS_ESCAPE_STRING)(char *out, int outlen, const char *in);

int            radius_xlat(char * out, int outlen, const char *fmt,
			   REQUEST * request, RADIUS_ESCAPE_STRING func);
typedef int (*RAD_XLAT_FUNC)(void *instance, REQUEST *, char *, char *, int, RADIUS_ESCAPE_STRING func);
int		xlat_register(const char *module, RAD_XLAT_FUNC func, void *instance);
void		xlat_unregister(const char *module, RAD_XLAT_FUNC func);


/* threads.c */
extern		int thread_pool_init(void);
extern		int thread_pool_clean(time_t now);
extern		void rad_exec_init(void);
extern		pid_t rad_fork(int exec_wait);
extern		pid_t rad_waitpid(pid_t pid, int *status, int options);
extern		int rad_savepid(pid_t pid, int status);

#ifndef HAVE_PTHREAD_H
#define rad_fork(n) fork()
#define rad_waitpid waitpid
#endif

/* mainconfig.h */
/* Define a global config structure */
extern struct main_config_t mainconfig;

int read_mainconfig(int reload);
int free_mainconfig(void);
CONF_SECTION *read_radius_conf_file(void); /* for radwho and friends. */
#endif /*RADIUSD_H*/
