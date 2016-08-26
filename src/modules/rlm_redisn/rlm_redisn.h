/***************************************************************************
*  rlm_redisn.h                    rlm_redisn - FreeRADIUS Redis Module    *
*                                                                          *
*      Header for Redis module file                                        *
*                                                                          *
*                                     Manuel Guesdon <guesdon@oxymium.net> *
*     code taken from rlm_sql (Mike Machado <mike@innercite.com>)          *
***************************************************************************/
#ifndef _RLM_REDISN_H
#define _RLM_REDISN_H

#include <freeradius-devel/ident.h>
RCSIDH(rlm_redisn_h, "$Id$")

#ifdef HAVE_PTHREAD_H
#include        <pthread.h>
#endif

#include	<freeradius-devel/modpriv.h>
#include <hiredis/hiredis.h>

typedef struct redisn_config {

	/* individual driver config */
	void	*localcfg;

} REDISN_CONFIG;


#define CHECKRAD1		"/usr/sbin/checkrad"
#define CHECKRAD2		"/usr/local/sbin/checkrad"

/* Hack for funky ascend ports on MAX 4048 (and probably others)
   The "NAS-Port-Id" value is "xyyzz" where "x" = 1 for digital, 2 for analog;
   "yy" = line number (1 for first PRI/T1/E1, 2 for second, so on);
   "zz" = channel number (on the PRI or Channelized T1/E1).
    This should work with normal terminal servers, unless you have a TS with
        more than 9999 ports ;^).
    The "ASCEND_CHANNELS_PER_LINE" is the number of channels for each line into
        the unit.  For my US/PRI that's 23.  A US/T1 would be 24, and a
        European E1 would be 30 (I think ... never had one ;^).
    This will NOT change the "NAS-Port-Id" reported in the detail log.  This
        is simply to fix the dynamic IP assignments a la Cistron.
    WARNING: This hack works for me, but I only have one PRI!!!  I've not
        tested it on 2 or more (or with models other than the Max 4048)
    Use at your own risk!
  -- dgreer@austintx.com
*/

#define ASCEND_PORT_HACK
#define ASCEND_CHANNELS_PER_LINE        23
#define CISCO_ACCOUNTING_HACK

/* REDISN defines */
#define MAX_QUERY_LEN			4096
#define REDISN_LOCK_LEN			MAX_QUERY_LEN
#define	REDISNTRACEFILE			RADLOG_DIR "/trace.redis"

/* REDISN Errors */
#define REDISN_DOWN			1 /* for re-connect */

#define MAX_COMMUNITY_LEN		50
#define MAX_REDISN_SOCKS			256
#define MAX_TABLE_LEN			20
#define MAX_AUTH_QUERY_LEN		256
#define AUTH_STRING_LEN			128

#define REDISSOCK_LOCKED		0
#define REDISSOCK_UNLOCKED		1

#define PW_ITEM_CHECK			0
#define PW_ITEM_REPLY			1

typedef char** REDIS_ROW;

typedef struct redisn_socket {
	int     id;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t mutex;
#endif
	struct redisn_socket *next;
	enum { sockconnected, sockunconnected } state;

  	int 		server_index;
	redisContext	*conn;
        redisReply      *reply;
        REDIS_ROW       row;
        size_t          cur_row;
        int             num_fields;

	time_t  connected;
	int	queries;
} REDISSOCK;

typedef struct rlm_redisn_t REDIS_INST;

typedef struct rlm_redisn_t {
	REDISSOCK		*redisnpool;
	REDISSOCK		*last_used;
  int next_use_server;

	char   *redisn_servers;
   	int servers_count;
  	char **server_names;
	int*   server_ports;
	char** server_passwords;
	int*   server_dbs;
	time_t* server_connect_afters;
  	char *vp_separator;
	char   *redisn_file;	/* for redisnite */
	char   *query_user;
	char   *default_profile;
	char   *nas_query;
	char   *authorize_check_query;
	char   *authorize_reply_query;
	char   *authorize_group_check_query;
	char   *authorize_group_reply_query;
	char   *accounting_on_query;
  char **accounting_on_queries;
	char   *accounting_off_query;
  char **accounting_off_queries;
	char   *accounting_update_query;
  char **accounting_update_queries;
	char   *accounting_start_query;
  char **accounting_start_queries;
	char   *accounting_stop_query;
  char **accounting_stop_queries;
	char   *simul_count_query;
	char   *simul_verify_query;
	char   *groupmemb_query;
	int     redisntrace;
	int	do_clients;
	int	read_groups;
	char   *tracefile;
	char   *xlat_name;
	int     deletestalesessions;
	int     num_redisn_socks;
	int     lifetime;
	int     max_queries;
	int     connect_failure_retry_delay;
	char   *postauth_query;
	char   *allowed_chars;
	int	query_timeout;

	int (*redisn_set_user)(REDIS_INST *inst, REQUEST *request, char *redisnusername, const char *username);
	REDISSOCK *(*redisn_get_socket)(REDIS_INST * inst);
	int (*redisn_release_socket)(REDIS_INST * inst, REDISSOCK * redisnsocket);
	size_t (*redisn_escape_func)(REQUEST *,char *out, size_t outlen, const char *in, void *arg);
	int (*redisn_query)(REDIS_INST *inst, REDISSOCK *redisnsocket, char *query);
  	int (*redisn_fetch_row)(REDIS_INST *inst, REDISSOCK *redisnsocket);
        int (*redisn_finish_query)(REDIS_INST *inst, REDISSOCK *redisnsocket);

} rlm_redisn_t;

typedef struct redisn_grouplist {
	char			groupname[MAX_STRING_LEN];
	struct redisn_grouplist	*next;
} REDISN_GROUPLIST;


int     redisn_init_socketpool(REDIS_INST * inst);
void    redisn_poolfree(REDIS_INST * inst);
int     redisn_close_socket(REDIS_INST *inst, REDISSOCK * redisnsocket);
REDISSOCK *redisn_get_socket(REDIS_INST * inst);
int     redisn_release_socket(REDIS_INST * inst, REDISSOCK * redisnsocket);
int     redisn_userparse(REDIS_INST * inst, VALUE_PAIR ** first_pair, REDIS_ROW row);
int     redisn_read_realms(REDISSOCK * redisnsocket);
int     redisn_getvpdata(REDIS_INST * inst, REDISSOCK * redisnsocket, VALUE_PAIR **pair, char *query);
int     redisn_read_naslist(REDISSOCK * redisnsocket);
int     redisn_read_clients(REDISSOCK * redisnsocket);
int     redisn_dict_init(REDISSOCK * redisnsocket);
void    query_log(REQUEST *request, REDIS_INST * inst, char *querystr);
int	rlm_redisn_query(REDIS_INST *inst, REDISSOCK *redisnsocket, char *query);
int	rlm_redisn_finish_query(REDIS_INST *inst, REDISSOCK *redisnsocket);
int	rlm_redisn_fetch_row(REDIS_INST *inst, REDISSOCK *redisnsocket);
int	redisn_set_user(REDIS_INST *inst, REQUEST *request, char *redisnusername, const char *username);
int     redisn_split_string(char*** result,char* string,char separator,int null_terminate_list);
#endif
