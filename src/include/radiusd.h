#ifndef RADIUSD_H
#define RADIUSD_H
/*
 * radiusd.h	Structures, prototypes and global variables
 *		for the FreeRADIUS server.
 *
 * Version:	$Id$
 *
 */

#include <freeradius-devel/ident.h>
RCSIDH(radiusd_h, "$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/radpaths.h>
#include <freeradius-devel/conf.h>
#include <freeradius-devel/conffile.h>
#include <freeradius-devel/event.h>

typedef struct auth_req REQUEST;

#include <freeradius-devel/realms.h>

#ifdef HAVE_PTHREAD_H
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

/*
 *	See util.c
 */
typedef struct request_data_t request_data_t;

/*
 *	For listening on multiple IP's and ports.
 */
typedef struct rad_listen_t rad_listen_t;

#define REQUEST_DATA_REGEX (0xadbeef00)
#define REQUEST_MAX_REGEX (8)

struct auth_req {
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

	request_data_t		*data;
	char			secret[32];
	child_pid_t    		child_pid;
	time_t			timestamp;
	int			number; /* internal server number */

	rad_listen_t		*listener;
	rad_listen_t		*proxy_listener;

	int                     simul_max;
	int                     simul_count;
	int                     simul_mpp; /* WEIRD: 1 is false, 2 is true */

	int			options; /* miscellanous options */
	const char		*module; /* for debugging unresponsive children */
	const char		*component; /* ditto */

	struct timeval		received;
	struct timeval		when; 		/* to wake up */
	int			delay;

	int			master_state;
	int			child_state;

	struct timeval		next_when;
	lrad_event_callback_t	next_callback;

	int			in_request_hash;
	int			in_proxy_hash;

	home_server	       	*home_server;
	home_pool_t		*home_pool; /* for dynamic failover */

	struct timeval		proxy_when;

	int			num_proxied_requests;
	int			num_proxied_responses;

};				/* REQUEST typedef */

#define RAD_REQUEST_OPTION_NONE            (0)

#define REQUEST_ACTIVE 		(1)
#define REQUEST_STOP_PROCESSING (2)

#define REQUEST_QUEUED		(1)
#define REQUEST_RUNNING		(2)
#define REQUEST_PROXIED		(3)
#define REQUEST_REJECT_DELAY	(4)
#define REQUEST_CLEANUP_DELAY	(5)
#define REQUEST_DONE		(6)

/*
 *  Function handler for requests.
 */
typedef		int (*RAD_REQUEST_FUNP)(REQUEST *);
typedef struct rad_snmp_client_entry_t rad_snmp_client_entry_t;

typedef struct radclient {
	lrad_ipaddr_t		ipaddr;
	int			prefix;
	char			*longname;
	char			*secret;
	char			*shortname;
	char			*nastype;
	char			*login;
	char			*password;
	int			number;	/* internal use only */
#ifdef WITH_SNMP
	rad_snmp_client_entry_t *auth, *acct;
#endif
} RADCLIENT;

typedef struct radclient_list RADCLIENT_LIST;

typedef struct pair_list {
	char			*name;
	VALUE_PAIR		*check;
	VALUE_PAIR		*reply;
	int			lineno;
	int			order;
	struct pair_list	*next;
	struct pair_list	*lastdefault;
} PAIR_LIST;


/*
 *	Types of listeners.
 *
 *	FIXME: Separate ports for proxy auth/acct?
 */
typedef enum RAD_LISTEN_TYPE {
	RAD_LISTEN_NONE = 0,
	RAD_LISTEN_AUTH,
	RAD_LISTEN_ACCT,
	RAD_LISTEN_PROXY,
	RAD_LISTEN_DETAIL,
	RAD_LISTEN_SNMP,
	RAD_LISTEN_MAX
} RAD_LISTEN_TYPE;

typedef int (*rad_listen_recv_t)(rad_listen_t *, RAD_REQUEST_FUNP *, REQUEST **);
typedef int (*rad_listen_send_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_print_t)(rad_listen_t *, char *, size_t);
typedef int (*rad_listen_encode_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_decode_t)(rad_listen_t *, REQUEST *);

struct rad_listen_t {
	struct rad_listen_t *next; /* should be rbtree stuff */

	/*
	 *	For normal sockets.
	 */
	RAD_LISTEN_TYPE	type;
	int		fd;
	const char	*identity;

	rad_listen_recv_t recv;
	rad_listen_send_t send;
	rad_listen_encode_t encode;
	rad_listen_decode_t decode;
	rad_listen_print_t print;

	void		*data;
};


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
	time_t		config_dead_time;
	lrad_ipaddr_t	myip;	/* from the command-line only */
	int		port;	/* from the command-line only */
	int		log_auth;
	int		log_auth_badpass;
	int		log_auth_goodpass;
#ifdef WITH_SNMP
	int		do_snmp;
#endif
	int		allow_core_dumps;
	int		debug_level;
	int		proxy_requests;
	int		wake_all_if_all_dead;
	int		proxy_synchronous;
	int		proxy_dead_time;
	int		proxy_retry_count;
	int		proxy_retry_delay;
	int		proxy_fallback;
	const char      *proxy_fail_type;
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
	const char	*uid_name;
	const char	*gid_name;
	rad_listen_t	*listen;
	int		syslog_facility;
	int		radlog_fd;
	radlog_dest_t	radlog_dest;
	CONF_SECTION	*config;
	RADCLIENT_LIST	*clients;
	const char	*radiusd_conf;
} MAIN_CONFIG_T;

#define DEBUG	if(debug_flag)log_debug
#define DEBUG2  if (debug_flag > 1)log_debug
#define DEBUG3  if (debug_flag > 2)log_debug

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
extern const char	*radius_dir;
extern const char	*radius_libdir;
extern uint32_t		expiration_seconds;
extern int		log_stripped_names;
extern int		log_auth_detail;
extern const char      *radiusd_version;

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
#ifndef _LIBRADIUS
void		debug_pair(FILE *, VALUE_PAIR *);
#endif
int		log_err (char *);

/* util.c */
void (*reset_signal(int signo, void (*func)(int)))(int);
void		request_free(REQUEST **request);
int		rad_mkdir(char *directory, int mode);
int		rad_checkfilename(const char *filename);
void		*rad_malloc(size_t size); /* calls exit(1) on error! */
REQUEST		*request_alloc(void);
REQUEST		*request_alloc_fake(REQUEST *oldreq);
int		request_data_add(REQUEST *request,
				 void *unique_ptr, int unique_int,
				 void *opaque, void (*free_opaque)(void *));
void		*request_data_get(REQUEST *request,
				  void *unique_ptr, int unique_int);
void		*request_data_reference(REQUEST *request,
				  void *unique_ptr, int unique_int);
int		rad_copy_string(char *dst, const char *src);
int		rad_copy_variable(char *dst, const char *from);

/* request_process.c */
int rad_respond(REQUEST *request, RAD_REQUEST_FUNP fun);
void		request_reject(REQUEST *request, request_fail_t reason);

/* client.c */
RADCLIENT_LIST	*clients_init(void);
void		clients_free(RADCLIENT_LIST *clients);
RADCLIENT_LIST	*clients_parse_section(const char *filename,
				       CONF_SECTION *section);
void		client_free(RADCLIENT *client);
int		client_add(RADCLIENT_LIST *clients, RADCLIENT *client);
RADCLIENT	*client_find(const RADCLIENT_LIST *clients,
			     const lrad_ipaddr_t *ipaddr);
const char	*client_name(const RADCLIENT_LIST *clients,
			     const lrad_ipaddr_t *ipaddr);
RADCLIENT	*client_findbynumber(const RADCLIENT_LIST *clients,
				     int number);
RADCLIENT	*client_find_old(const lrad_ipaddr_t *ipaddr);
const char	*client_name_old(const lrad_ipaddr_t *ipaddr);

/* files.c */
int		pairlist_read(const char *file, PAIR_LIST **list, int complain);
void		pairlist_free(PAIR_LIST **);
int		read_config_files(void);

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
int		rad_postauth(REQUEST *);

/* exec.c */
int		radius_exec_program(const char *,  REQUEST *, int,
				    char *user_msg, int msg_len,
				    VALUE_PAIR *input_pairs,
				    VALUE_PAIR **output_pairs,
					int shell_escape);

/* timestr.c */
int		timestr_match(char *, time_t);

/* valuepair.c */
int		paircompare_register(int attr, int otherattr,
				     RAD_COMPARE_FUNC func,
				     void *instance);
void		paircompare_unregister(int attr, RAD_COMPARE_FUNC func);
int		paircompare(REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check,
			    VALUE_PAIR **reply);
void		pairxlatmove(REQUEST *, VALUE_PAIR **to, VALUE_PAIR **from);
int radius_compare_vps(REQUEST *request, VALUE_PAIR *check, VALUE_PAIR *vp);
int radius_callback_compare(REQUEST *req, VALUE_PAIR *request,
			    VALUE_PAIR *check, VALUE_PAIR *check_pairs,
			    VALUE_PAIR **reply_pairs);

/* xlat.c */
typedef int (*RADIUS_ESCAPE_STRING)(char *out, int outlen, const char *in);

int            radius_xlat(char * out, int outlen, const char *fmt,
			   REQUEST * request, RADIUS_ESCAPE_STRING func);
typedef int (*RAD_XLAT_FUNC)(void *instance, REQUEST *, char *, char *, size_t, RADIUS_ESCAPE_STRING func);
int		xlat_register(const char *module, RAD_XLAT_FUNC func, void *instance);
void		xlat_unregister(const char *module, RAD_XLAT_FUNC func);


/* threads.c */
extern		int thread_pool_init(int spawn_flag);
extern		int thread_pool_clean(time_t now);
extern		int thread_pool_addrequest(REQUEST *, RAD_REQUEST_FUNP);
extern		pid_t rad_fork(void);
extern		pid_t rad_waitpid(pid_t pid, int *status);
extern          int total_active_threads(void);

#ifndef HAVE_PTHREAD_H
#define rad_fork(n) fork()
#define rad_waitpid(a,b) waitpid(a,b, 0)
#endif

/* mainconfig.c */
/* Define a global config structure */
extern struct main_config_t mainconfig;

int read_mainconfig(int reload);
int free_mainconfig(void);

/* listen.c */
void listen_free(rad_listen_t **head);
int listen_init(const char *filename, rad_listen_t **head);
rad_listen_t *proxy_new_listener(void);
RADCLIENT *client_listener_find(const rad_listen_t *listener,
				const lrad_ipaddr_t *ipaddr);

/* event.c */
int radius_event_init(int spawn_flag);
void radius_event_free(void);
int radius_event_process(struct timeval **pptv);
void radius_handle_request(REQUEST *request, RAD_REQUEST_FUNP fun);
int received_request(rad_listen_t *listener,
		     RADIUS_PACKET *packet, REQUEST **prequest,
		     const RADCLIENT *client);
REQUEST *received_proxy_response(RADIUS_PACKET *packet);

#endif /*RADIUSD_H*/
