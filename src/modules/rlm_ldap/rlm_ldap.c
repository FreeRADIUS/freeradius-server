/*
 * rlm_ldap.c	LDAP authorization and authentication module.
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
 *   Copyright 2004,2006 The FreeRADIUS Server Project.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>

#include	<pwd.h>
#include	<ctype.h>

#include	<lber.h>
#include        <ldap.h>

#ifndef HAVE_PTHREAD_H
/*
 *      This is a lot simpler than putting ifdef's around
 *      every use of the pthread functions.
 */
#define pthread_mutex_lock(a)
#define pthread_mutex_trylock(a) (0)
#define pthread_mutex_unlock(a)
#define pthread_mutex_init(a,b)
#define pthread_mutex_destroy(a)
#else
#include	<pthread.h>
#endif


#define MAX_FILTER_STR_LEN	1024
#define TIMELIMIT 5

/*
 * These are used in case ldap_search returns LDAP_SERVER_DOWN
 * In that case we do conn->failed_conns++ and then check it:
 * If conn->failed_conns <= MAX_FAILED_CONNS_START then we try
 * to reconnect
 * conn->failed_conns is also checked on entrance in perform_search:
 * If conn->failed_conns > MAX_FAILED_CONNS_START then we don't
 * try to do anything and we just do conn->failed_conns++ and
 * return RLM_MODULE_FAIL
 * if conn->failed_conns >= MAX_FAILED_CONNS_END then we give it
 * another chance and we set it to MAX_FAILED_CONNS_RESTART and
 * try to reconnect.
 *
 *
 * We are assuming that the majority of the LDAP_SERVER_DOWN cases
 * will either be an ldap connection timeout or a temporary ldap
 * server problem.
 * As a result we make a few attempts to reconnect hoping that the problem
 * will soon go away. If it does not go away then we just return
 * RLM_MODULE_FAIL on entrance in perform_search until conn->failed_conns
 * gets to MAX_FAILED_CONNS_END. After that we give it one more chance by
 * going back to MAX_FAILED_CONNS_RESTART
 *
 */

#define MAX_FAILED_CONNS_END		20
#define MAX_FAILED_CONNS_RESTART	4
#define MAX_FAILED_CONNS_START		5

#ifdef NOVELL_UNIVERSAL_PASSWORD

/* Universal Password Length */
#define UNIVERSAL_PASS_LEN 256

int nmasldap_get_password(
	LDAP	 *ld,
	char     *objectDN,
	size_t   *pwdSize,	/* in bytes */
	char     *pwd );

#endif

#ifdef NOVELL

#define REQUEST_ACCEPTED   0
#define REQUEST_CHALLENGED 1
#define REQUEST_REJECTED   2
#define MAX_CHALLENGE_LEN  128

int radLdapXtnNMASAuth( LDAP *, char *, char *, char *, char *, size_t *, char *, int * );

#endif

/* linked list of mappings between RADIUS attributes and LDAP attributes */
struct TLDAP_RADIUS {
	char*                 attr;
	char*                 radius_attr;
	FR_TOKEN	      operator;
	struct TLDAP_RADIUS*  next;
};
typedef struct TLDAP_RADIUS TLDAP_RADIUS;

typedef struct ldap_conn {
	LDAP		*ld;
	char		bound;
	char		locked;
	int		failed_conns;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t	mutex;
#endif
} LDAP_CONN;

typedef struct {
	CONF_SECTION   *cs;
	char           *server;
	int             port;
	int             timelimit;
	int  		net_timeout;
	int		timeout;
	int             debug;
	int             tls_mode;
	int		start_tls;
	int		num_conns;
	int		do_comp;
	int		do_xlat;
	int		default_allow;
	int		failed_conns;
	int		is_url;
	int		chase_referrals;
	int		rebind;
	char           *login;
	char           *password;
	char           *filter;
	char           *base_filter;
	char           *basedn;
	char           *default_profile;
	char           *profile_attr;
	char           *access_attr;
	char           *passwd_attr;
	char           *dictionary_mapping;
	char	       *groupname_attr;
	char	       *groupmemb_filt;
	char           *groupmemb_attr;
	char		**atts;
	TLDAP_RADIUS   *check_item_map;
	TLDAP_RADIUS   *reply_item_map;
	LDAP_CONN	*conns;
#ifdef NOVELL
	LDAP_CONN *apc_conns;
#endif
	int             ldap_debug; /* Debug flag for LDAP SDK */
	char		*xlat_name; /* name used to xlat */
	char		*auth_type;
	char		*tls_cacertfile;
	char		*tls_cacertdir;
	char		*tls_certfile;
	char		*tls_keyfile;
	char		*tls_randfile;
	char		*tls_require_cert;
#ifdef NOVELL
	int		 edir_account_policy_check;
#endif
	int		 set_auth_type;

	/*
	 *	For keep-alives.
	 */
#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	int		keepalive_idle;
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	int		keepalive_probes;
#endif
#ifdef LDAP_OPT_ERROR_NUMBER
	int		keepalive_interval;
#endif

}  ldap_instance;

/* The default setting for TLS Certificate Verification */
#define TLS_DEFAULT_VERIFY "allow"

#if defined(LDAP_OPT_X_KEEPALIVE_IDLE) || defined(LDAP_OPT_X_KEEPALIVE_PROBES) || defined (LDAP_OPT_ERROR_NUMBER)
static CONF_PARSER keepalive_config[] = {
#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	{"idle", PW_TYPE_INTEGER, offsetof(ldap_instance,keepalive_idle), NULL, "60"},
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	{"probes", PW_TYPE_INTEGER, offsetof(ldap_instance,keepalive_probes), NULL, "3"},
#endif
#ifdef LDAP_OPT_ERROR_NUMBER
	{"interval", PW_TYPE_INTEGER, offsetof(ldap_instance,keepalive_interval), NULL, "30"},
#endif

	{ NULL, -1, 0, NULL, NULL }
};
#endif				/* KEEPALIVE */

static CONF_PARSER tls_config[] = {
	{"start_tls", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,start_tls), NULL, "no"},
	{"cacertfile", PW_TYPE_FILENAME,
	 offsetof(ldap_instance,tls_cacertfile), NULL, NULL},
	{"cacertdir", PW_TYPE_FILENAME,
	 offsetof(ldap_instance,tls_cacertdir), NULL, NULL},
	{"certfile", PW_TYPE_FILENAME,
	 offsetof(ldap_instance,tls_certfile), NULL, NULL},
	{"keyfile", PW_TYPE_FILENAME,
	 offsetof(ldap_instance,tls_keyfile), NULL, NULL},
	{"randfile", PW_TYPE_STRING_PTR, /* OK if it changes on HUP */
	 offsetof(ldap_instance,tls_randfile), NULL, NULL},
	{"require_cert", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,tls_require_cert), NULL, TLS_DEFAULT_VERIFY},
	{ NULL, -1, 0, NULL, NULL }
};

static const CONF_PARSER module_config[] = {
	{"server", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,server), NULL, "localhost"},
	{"port", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,port), NULL, "389"},
	{"password", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,password), NULL, ""},
	{"identity", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,login), NULL, ""},

	/*
	 *	Timeouts & stuff.
	 */
	/* wait forever on network activity */
	{"net_timeout", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,net_timeout), NULL, "10"},
	/* wait forever for search results */
	{"timeout", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,timeout), NULL, "20"},
	/* allow server unlimited time for search (server-side limit) */
	{"timelimit", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,timelimit), NULL, "20"},

	/*
	 *	TLS configuration  The first few are here for backwards
	 *	compatibility.  The last is the new subsection.
	 */
	{"tls_mode", PW_TYPE_BOOLEAN | PW_TYPE_DEPRECATED,
	 offsetof(ldap_instance,tls_mode), NULL, "no"},

	{"start_tls", PW_TYPE_BOOLEAN | PW_TYPE_DEPRECATED,
	 offsetof(ldap_instance,start_tls), NULL, "no"},
	{"tls_cacertfile", PW_TYPE_FILENAME | PW_TYPE_DEPRECATED,
	 offsetof(ldap_instance,tls_cacertfile), NULL, NULL},
	{"tls_cacertdir", PW_TYPE_FILENAME | PW_TYPE_DEPRECATED,
	 offsetof(ldap_instance,tls_cacertdir), NULL, NULL},
	{"tls_certfile", PW_TYPE_FILENAME | PW_TYPE_DEPRECATED,
	 offsetof(ldap_instance,tls_certfile), NULL, NULL},
	{"tls_keyfile", PW_TYPE_FILENAME | PW_TYPE_DEPRECATED,
	 offsetof(ldap_instance,tls_keyfile), NULL, NULL},
	{"tls_randfile", PW_TYPE_STRING_PTR | PW_TYPE_DEPRECATED, /* OK if it changes on HUP */
	 offsetof(ldap_instance,tls_randfile), NULL, NULL},
	{"tls_require_cert", PW_TYPE_STRING_PTR | PW_TYPE_DEPRECATED,
	 offsetof(ldap_instance,tls_require_cert), NULL, TLS_DEFAULT_VERIFY},
	{ "tls", PW_TYPE_SUBSECTION, 0, NULL, (const void *) tls_config },

	/*
	 *	DN's and filters.
	 */
	{"basedn", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,basedn), NULL, "o=notexist"},
	{"filter", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,filter), NULL, "(uid=%u)"},
	{"base_filter", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,base_filter), NULL, "(objectclass=radiusprofile)"},
	{"default_profile", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,default_profile), NULL, NULL},
	{"profile_attribute", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,profile_attr), NULL, NULL},

	/*
	 *	Getting passwords from the database
	 */
	{"password_attribute", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,passwd_attr), NULL, NULL},

	/*
	 *	Access limitations
	 */
	/* LDAP attribute name that controls remote access */
	{"access_attr", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,access_attr), NULL, NULL},
	{"access_attr_used_for_allow", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,default_allow), NULL, "yes"},
	{"chase_referrals", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,chase_referrals), NULL, NULL},
	{"rebind", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,rebind), NULL, NULL},

	/*
	 *	Group checks.  These could probably be done
	 *	via dynamic xlat's.
	 */
	{"groupname_attribute", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,groupname_attr), NULL, "cn"},
	{"groupmembership_filter", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,groupmemb_filt), NULL, "(|(&(objectClass=GroupOfNames)(member=%{Ldap-UserDn}))(&(objectClass=GroupOfUniqueNames)(uniquemember=%{Ldap-UserDn})))"},
	{"groupmembership_attribute", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,groupmemb_attr), NULL, NULL},

	/* file with mapping between LDAP and RADIUS attributes */
	{"dictionary_mapping", PW_TYPE_FILENAME,
	 offsetof(ldap_instance,dictionary_mapping), NULL, "${confdir}/ldap.attrmap"},

	/*
	 *	Debugging flags to the server
	 */
	{"ldap_debug", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,ldap_debug), NULL, "0x0000"},
	{"ldap_connections_number", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,num_conns), NULL, "5"},
	{"compare_check_items", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,do_comp), NULL, "no"},
	{"do_xlat", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,do_xlat), NULL, "yes"},

#ifdef NOVELL
	/*
	 *	Novell magic.
	 */
	{"edir_account_policy_check", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,edir_account_policy_check), NULL, "yes"},
#endif

	{"set_auth_type", PW_TYPE_BOOLEAN, offsetof(ldap_instance,set_auth_type), NULL, "yes"},

#if defined(LDAP_OPT_X_KEEPALIVE_IDLE) || defined(LDAP_OPT_X_KEEPALIVE_PROBES) || defined (LDAP_OPT_ERROR_NUMBER)
	{ "keepalive", PW_TYPE_SUBSECTION, 0, NULL, (const void *) keepalive_config },
#endif

	{NULL, -1, 0, NULL, NULL}
};

#define ld_valid                ld_options.ldo_valid
#define LDAP_VALID_SESSION      0x2
#define LDAP_VALID(ld)  ( (ld)->ld_valid == LDAP_VALID_SESSION )

#ifdef FIELDCPY
static void     fieldcpy(char *, char **);
#endif
static VALUE_PAIR *ldap_pairget(LDAP *, LDAPMessage *, TLDAP_RADIUS *,VALUE_PAIR **,int, ldap_instance *);
static int ldap_groupcmp(void *, REQUEST *, VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR **);
static size_t ldap_xlat(void *, REQUEST *, char *, char *, size_t, RADIUS_ESCAPE_STRING);
static LDAP    *ldap_connect(void *instance, const char *, const char *, int, int *, char **);
static int     read_mappings(ldap_instance* inst);

static inline int ldap_get_conn(LDAP_CONN *conns,LDAP_CONN **ret,
				ldap_instance *inst)
{
	register int i = 0;

	for(i=0;i<inst->num_conns;i++){
		DEBUG("  [%s] ldap_get_conn: Checking Id: %d",
		      inst->xlat_name, i);
		if ((pthread_mutex_trylock(&conns[i].mutex) == 0)) {
			if (conns[i].locked == 1) {
				/* connection is already being used */
				pthread_mutex_unlock(&(conns[i].mutex));
				continue;
			}
			/* found an unused connection */
			*ret = &conns[i];
			conns[i].locked = 1;
			DEBUG("  [%s] ldap_get_conn: Got Id: %d",
			      inst->xlat_name, i);
			return i;
		}
	}

	return -1;
}

static inline void ldap_release_conn(int i, ldap_instance *inst)
				     
{
	LDAP_CONN *conns = inst->conns;

	DEBUG("  [%s] ldap_release_conn: Release Id: %d", inst->xlat_name, i);
	conns[i].locked = 0;
	pthread_mutex_unlock(&(conns[i].mutex));
}

#ifdef NOVELL
static inline void ldap_release_apc_conn(int i, ldap_instance *inst)
				     
{
	LDAP_CONN *conns = inst->apc_conns;

	DEBUG("  [%s] ldap_release_conn: Release Id: %d", inst->xlat_name, i);
	conns[i].locked = 0;
	pthread_mutex_unlock(&(conns[i].mutex));
}
#endif

/*************************************************************************
 *
 *	Function: rlm_ldap_instantiate
 *
 *	Purpose: Uses section of radiusd config file passed as parameter
 *		 to create an instance of the module.
 *
 *************************************************************************/
static int
ldap_instantiate(CONF_SECTION * conf, void **instance)
{
	ldap_instance  *inst;
	int i = 0;
	int atts_num = 0;
	int reply_map_num = 0;
	int check_map_num = 0;
	int att_map[3] = {0,0,0};
	TLDAP_RADIUS *pair;
	ATTR_FLAGS flags;
	const char *xlat_name;

	inst = rad_malloc(sizeof *inst);
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));
	inst->chase_referrals = 2; /* use OpenLDAP defaults */
	inst->rebind = 2;
	inst->cs = conf;

	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	if (inst->server == NULL) {
		radlog(L_ERR, "rlm_ldap: missing 'server' directive.");
		free(inst);	/* FIXME: detach */
		return -1;
	}
	inst->is_url = 0;
	if (ldap_is_ldap_url(inst->server)){
#ifdef HAVE_LDAP_INITIALIZE
		inst->is_url = 1;
		inst->port = 0;
#else
		radlog(L_ERR, "rlm_ldap: 'server' directive is in URL form but ldap_initialize() is not available.");
		free(inst);	/* FIXME: detach */
		return -1;
#endif
	}

	/* workaround for servers which support LDAPS but not START TLS */
	if(inst->port == LDAPS_PORT || inst->tls_mode)
		inst->tls_mode = LDAP_OPT_X_TLS_HARD;
	else
		inst->tls_mode = 0;
	inst->reply_item_map = NULL;
	inst->check_item_map = NULL;
	inst->conns = NULL;
	inst->failed_conns = 0;

#if LDAP_SET_REBIND_PROC_ARGS != 3
	/*
	 *	The 2-argument rebind doesn't take an instance
	 *	variable.  Our rebind function needs the instance
	 *	variable for the username, password, etc.
	 */
	if (inst->rebind == 1) {
		radlog(L_ERR, "rlm_ldap: Cannot use 'rebind' directive as this version of libldap does not support the API that we need.");
		free(inst);
		return -1;
	}
#endif

	DEBUG("rlm_ldap: Registering ldap_groupcmp for Ldap-Group");
	paircompare_register(PW_LDAP_GROUP, PW_USER_NAME, ldap_groupcmp, inst);
	memset(&flags, 0, sizeof(flags));

	xlat_name = cf_section_name2(conf);
	if (xlat_name != NULL){
		char *group_name;
		DICT_ATTR *dattr;

		/*
		 * Allocate room for <instance>-Ldap-Group
		 */
		group_name = rad_malloc((strlen(xlat_name) + 1 + 11) * sizeof(char));
		sprintf(group_name,"%s-Ldap-Group",xlat_name);
		DEBUG("rlm_ldap: Creating new attribute %s",group_name);
		dict_addattr(group_name, -1, 0, PW_TYPE_STRING, flags);
		dattr = dict_attrbyname(group_name);
		if (dattr == NULL){
			radlog(L_ERR, "rlm_ldap: Failed to create attribute %s",group_name);
			free(group_name);
			free(inst);	/* FIXME: detach */
			return -1;
		}
		DEBUG("rlm_ldap: Registering ldap_groupcmp for %s",group_name);
		paircompare_register(dattr->attr, PW_USER_NAME, ldap_groupcmp, inst);
		free(group_name);
	}
	else {
		xlat_name = cf_section_name1(conf);
		rad_assert(xlat_name != NULL); /* or all hell breaks loose */
	}
	inst->xlat_name = strdup(xlat_name);
	DEBUG("rlm_ldap: Registering ldap_xlat with xlat_name %s",xlat_name);
	xlat_register(xlat_name,ldap_xlat,inst);

	/*
	 *	Over-ride set_auth_type if there's no Auth-Type of our name.
	 *	This automagically catches the case where LDAP is listed
	 *	in "authorize", but not "authenticate".
	 */
	if (inst->set_auth_type) {
	  DICT_VALUE *dv = dict_valbyname(PW_AUTH_TYPE, 0, xlat_name);

		/*
		 *	No section of *my* name, but maybe there's an
		 *	LDAP section...
		 */
		if (!dv) dv = dict_valbyname(PW_AUTH_TYPE, 0, "LDAP");
		if (!dv) {
			DEBUG2("rlm_ldap: Over-riding set_auth_type, as there is no module %s listed in the \"authenticate\" section.", xlat_name);
			inst->set_auth_type = 0;
		} else {
			inst->auth_type = dv->name; /* doesn't change on HUP */
		}
	} /* else no need to look up the value */

#ifdef NOVELL
	/*
	 *	(LDAP_Instance, V1) attribute-value pair in the config
	 *	items list means that the 'authorize' method of the
	 *	instance 'V1' of the LDAP module has processed this
	 *	request.
	 */
	dict_addattr("LDAP-Instance", -1, 0, PW_TYPE_STRING, flags);

	/*
	 *	('eDir-APC', '1') in config items list
	 *	Do not perform eDirectory account policy check (APC)
	 *
	 *	('eDir-APC', '2') in config items list
	 *	Perform eDirectory APC
	 *
	 *	('eDir-APC', '3') in config items list
	 *	eDirectory APC has been completed
	 */
	dict_addattr("eDir-APC", -1, 0, PW_TYPE_STRING, flags);
	/*
	 *	eDir-Auth-Option allows for a different NMAS Authentication method to be used instead of password
	 */
	dict_addattr("eDir-Auth-Option", -1, 0, PW_TYPE_STRING, flags);
#endif

	if (inst->num_conns <= 0){
		radlog(L_ERR, "rlm_ldap: Invalid ldap connections number passed.");
		free(inst);	/* FIXME: detach */
		return -1;
	}
	inst->conns = malloc(sizeof(*(inst->conns))*inst->num_conns);
	if (inst->conns == NULL){
		radlog(L_ERR, "rlm_ldap: Could not allocate memory. Aborting.");
		free(inst);	/* FIXME: detach */
		return -1;
	}
	for(i = 0; i < inst->num_conns; i++){
		inst->conns[i].bound = 0;
		inst->conns[i].locked = 0;
		inst->conns[i].failed_conns = 0;
		inst->conns[i].ld = NULL;
		pthread_mutex_init(&inst->conns[i].mutex, NULL);
	}

#ifdef NOVELL
	/*
	 *	'inst->apc_conns' is a separate connection pool to be
	 *	used for performing eDirectory account policy check in
	 *	the 'postauth' method. This avoids changing the
	 *	(RADIUS server) credentials associated with the
	 *	'inst->conns' connection pool.
	 */
	inst->apc_conns = malloc(sizeof(*(inst->apc_conns))*inst->num_conns);
	if (inst->apc_conns == NULL){
		radlog(L_ERR, "rlm_ldap: Could not allocate memory. Aborting.");
		free(inst);	/* FIXME: detach */
		return -1;
	}
	for(i = 0; i < inst->num_conns; i++){
		inst->apc_conns[i].bound = 0;
		inst->apc_conns[i].locked = 0;
		inst->apc_conns[i].failed_conns = 0;
		inst->apc_conns[i].ld = NULL;
		pthread_mutex_init(&inst->apc_conns[i].mutex, NULL);
	}
#endif

	if (read_mappings(inst) != 0) {
		radlog(L_ERR, "rlm_ldap: Reading dictionary mappings from file %s failed",
		       inst->dictionary_mapping);
		free(inst);	/* FIXME: detach */
		return -1;
	}
	if ((inst->check_item_map == NULL) &&
	    (inst->reply_item_map == NULL)) {
		radlog(L_ERR, "rlm_ldap: dictionary mappings file %s did not contain any mappings",
			inst->dictionary_mapping);
		free(inst);	/* FIXME: detach */
		return -1;
	}

	pair = inst->check_item_map;
	while(pair != NULL){
		atts_num++;
		pair = pair->next;
	}
	check_map_num = (atts_num - 1);
	pair = inst->reply_item_map;
	while(pair != NULL){
		atts_num++;
		pair = pair->next;
	}
	reply_map_num = (atts_num - 1);
	if (inst->profile_attr)
		atts_num++;
	if (inst->passwd_attr)
		atts_num++;
	if (inst->access_attr)
		atts_num++;
#ifdef NOVELL
		atts_num++;	/* eDirectory Authentication Option attribute */
#endif
	inst->atts = (char **)malloc(sizeof(char *)*(atts_num + 1));
	if (inst->atts == NULL){
		radlog(L_ERR, "rlm_ldap: Could not allocate memory. Aborting.");
		free(inst);	/* FIXME: detach */
		return -1;
	}
	pair = inst->check_item_map;
	if (pair == NULL)
		pair = inst->reply_item_map;
#ifdef NOVELL
	for(i=0;i<atts_num - 1;i++){
#else
 	for(i=0;i<atts_num;i++){
#endif
		if (i <= check_map_num ){
			inst->atts[i] = pair->attr;
			if (i == check_map_num)
				pair = inst->reply_item_map;
			else
				pair = pair->next;
		}
		else if (i <= reply_map_num){
			inst->atts[i] = pair->attr;
			pair = pair->next;
		}
		else{
			if (inst->profile_attr && !att_map[0]){
				inst->atts[i] = inst->profile_attr;
				att_map[0] = 1;
			}
			else if (inst->passwd_attr && !att_map[1]){
				inst->atts[i] = inst->passwd_attr;
				att_map[1] = 1;
			}
			else if (inst->access_attr && !att_map[2]){
				inst->atts[i] = inst->access_attr;
				att_map[2] = 1;
			}
		}
	}
#ifdef NOVELL
	{
		static char ts[] = "sasdefaultloginsequence";
		inst->atts[atts_num - 1] = ts;
	}
#endif
	inst->atts[atts_num] = NULL;

	DEBUG("conns: %p",inst->conns);

	*instance = inst;


	return 0;
}


/*
 *	read_mappings(...) reads a ldap<->radius mappings file to
 *	inst->reply_item_map and inst->check_item_map
 */
#define MAX_LINE_LEN 160
#define GENERIC_ATTRIBUTE_ID "$GENERIC$"

static int
read_mappings(ldap_instance* inst)
{
	FILE* mapfile;
	char *filename;

	/*
	 *	All buffers are of MAX_LINE_LEN so we can use sscanf
	 *	without being afraid of buffer overflows
	 */
	char buf[MAX_LINE_LEN], itemType[MAX_LINE_LEN];
	char radiusAttribute[MAX_LINE_LEN], ldapAttribute[MAX_LINE_LEN];
	int linenumber;
	FR_TOKEN operator;
	char opstring[MAX_LINE_LEN];

	/* open the mappings file for reading */

	filename = inst->dictionary_mapping;
	DEBUG("rlm_ldap: reading ldap<->radius mappings from file %s", filename);
	mapfile = fopen(filename, "r");

	if (mapfile == NULL) {
		radlog(L_ERR, "rlm_ldap: Opening file %s failed: %s",
		       filename, strerror(errno));
		return -1; /* error */
	}

	/*
	 *	read file line by line. Note that if line length
	 *	exceeds MAX_LINE_LEN, line numbers will be mixed up
	 */
	linenumber = 0;

	while (fgets(buf, sizeof buf, mapfile)!=NULL) {
		char* ptr;
		int token_count;
		TLDAP_RADIUS* pair;

		linenumber++;

		/* strip comments */
		ptr = strchr(buf, '#');
		if (ptr) *ptr = 0;

		/* empty line */
		if (buf[0] == 0) continue;

		/* extract tokens from the string */
		token_count = sscanf(buf, "%s %s %s %s",
				     itemType, radiusAttribute,
				     ldapAttribute, opstring);

		if (token_count <= 0) /* no tokens */
			continue;

		if ((token_count < 3) || (token_count > 4)) {
			radlog(L_ERR, "rlm_ldap: Skipping %s line %i: %s",
			       filename, linenumber, buf);
			radlog(L_ERR, "rlm_ldap: Expected 3 to 4 tokens "
			       "(Item type, RADIUS Attribute and LDAP Attribute) but found only %i", token_count);
			continue;
		}

		if (token_count == 3) {
			operator = T_OP_INVALID; /* use defaults */
		} else {
			ptr = opstring;
			operator = gettoken((void*)&ptr, buf, sizeof(buf));
			if ((operator < T_OP_ADD) || (operator > T_OP_CMP_EQ)) {
				radlog(L_ERR, "rlm_ldap: file %s: skipping line %i: unknown or invalid operator %s",
				       filename, linenumber, opstring);
				continue;
			}
		}

		/* create new TLDAP_RADIUS list node */
		pair = rad_malloc(sizeof(*pair));

		pair->attr = strdup(ldapAttribute);
		pair->radius_attr = strdup(radiusAttribute);
		pair->operator = operator;

		if ( (pair->attr == NULL) || (pair->radius_attr == NULL) ) {
			radlog(L_ERR, "rlm_ldap: Out of memory");
			if (pair->attr) free(pair->attr);
			if (pair->radius_attr) free(pair->radius_attr);
			free(pair);
			fclose(mapfile);
			return -1;
		}

		/* push node to correct list */
		if (strcasecmp(itemType, "checkItem") == 0) {
			pair->next = inst->check_item_map;
			inst->check_item_map = pair;
		} else if (strcasecmp(itemType, "replyItem") == 0) {
			pair->next = inst->reply_item_map;
			inst->reply_item_map = pair;
		} else {
			radlog(L_ERR, "rlm_ldap: file %s: skipping line %i: unknown itemType %s",
			       filename, linenumber, itemType);
			free(pair->attr);
			free(pair->radius_attr);
			free(pair);
			continue;
		}

		DEBUG("rlm_ldap: LDAP %s mapped to RADIUS %s",
		      pair->attr, pair->radius_attr);
	}

	fclose(mapfile);

	return 0; /* success */
}

static int perform_search(void *instance, LDAP_CONN *conn,
			  char *search_basedn, int scope, char *filter,
			  char **attrs, LDAPMessage ** result)
{
	int             res = RLM_MODULE_OK;
	int		ldap_errno = 0;
	ldap_instance  *inst = instance;
	int		search_retry = 0;
	struct timeval  tv;

	*result = NULL;

	if (!conn){
		radlog(L_ERR, "  [%s] NULL connection handle passed",
			inst->xlat_name);
		return RLM_MODULE_FAIL;
	}
	if (conn->failed_conns > MAX_FAILED_CONNS_START){
		conn->failed_conns++;
		if (conn->failed_conns >= MAX_FAILED_CONNS_END){
			conn->failed_conns = MAX_FAILED_CONNS_RESTART;
			conn->bound = 0;
		}
	}
retry:
	if (!conn->bound || conn->ld == NULL) {
		DEBUG2("  [%s] attempting LDAP reconnection", inst->xlat_name);
		if (conn->ld){
			DEBUG2("  [%s] closing existing LDAP connection",
				inst->xlat_name);
			ldap_unbind_s(conn->ld);
		}
		if ((conn->ld = ldap_connect(instance, inst->login,
					     inst->password, 0, &res, NULL)) == NULL) {
			radlog(L_ERR, "  [%s] (re)connection attempt failed",
				inst->xlat_name);
			if (search_retry == 0)
				conn->failed_conns++;
			return (RLM_MODULE_FAIL);
		}
		conn->bound = 1;
		conn->failed_conns = 0;
	}

	tv.tv_sec = inst->timeout;
	tv.tv_usec = 0;
	DEBUG2("  [%s] performing search in %s, with filter %s", inst->xlat_name, 
	       search_basedn ? search_basedn : "(null)" , filter);
	switch (ldap_search_st(conn->ld, search_basedn, scope, filter,
			       attrs, 0, &tv, result)) {
	case LDAP_SUCCESS:
	case LDAP_NO_SUCH_OBJECT:
		break;
	case LDAP_SERVER_DOWN:
		radlog(L_ERR, "  [%s] ldap_search() failed: LDAP connection lost.", inst->xlat_name);
		conn->failed_conns++;
		if (search_retry == 0){
			if (conn->failed_conns <= MAX_FAILED_CONNS_START){
				radlog(L_INFO, "  [%s] Attempting reconnect", inst->xlat_name);
				search_retry = 1;
				conn->bound = 0;
				ldap_msgfree(*result);
				goto retry;
			}
		}
		ldap_msgfree(*result);
		return RLM_MODULE_FAIL;
	case LDAP_INSUFFICIENT_ACCESS:
		radlog(L_ERR, "  [%s] ldap_search() failed: Insufficient access. Check the identity and password configuration directives.", inst->xlat_name);
		ldap_msgfree(*result);
		return RLM_MODULE_FAIL;
	case LDAP_TIMEOUT:
		exec_trigger(NULL, inst->cs, "modules.ldap.timeout", TRUE);
		radlog(L_ERR, "  [%s] ldap_search() failed: Timed out while waiting for server to respond. Please increase the timeout.", inst->xlat_name);
		ldap_msgfree(*result);
		return RLM_MODULE_FAIL;
	case LDAP_FILTER_ERROR:
		radlog(L_ERR, "  [%s] ldap_search() failed: Bad search filter: %s", inst->xlat_name,filter);
		ldap_msgfree(*result);
		return RLM_MODULE_FAIL;
	case LDAP_TIMELIMIT_EXCEEDED:
		exec_trigger(NULL, inst->cs, "modules.ldap.timeout", TRUE);

	case LDAP_BUSY:
	case LDAP_UNAVAILABLE:
		/* We don't need to reconnect in these cases so we don't set conn->bound */
		ldap_get_option(conn->ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "  [%s] ldap_search() failed: %s", inst->xlat_name,
		       ldap_err2string(ldap_errno));
		ldap_msgfree(*result);
		return (RLM_MODULE_FAIL);
	default:
		ldap_get_option(conn->ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "  [%s] ldap_search() failed: %s", inst->xlat_name,
		       ldap_err2string(ldap_errno));
		conn->bound = 0;
		ldap_msgfree(*result);
		return (RLM_MODULE_FAIL);
	}

	ldap_errno = ldap_count_entries(conn->ld, *result);
	if (ldap_errno != 1) {
		if (ldap_errno == 0) {
			DEBUG("  [%s] object not found", inst->xlat_name);
		} else {
			DEBUG("  [%s] got ambiguous search result (%d results)", inst->xlat_name, ldap_errno);
		}
		res = RLM_MODULE_NOTFOUND;
		ldap_msgfree(*result);
	}
	return res;
}


/*
 *	Translate the LDAP queries.
 */
static size_t ldap_escape_func(char *out, size_t outlen, const char *in)
{
	size_t len = 0;

	while (in[0]) {
		/*
		 *	Encode unsafe characters.
		 */
		if (((len == 0) &&
		    ((in[0] == ' ') || (in[0] == '#'))) ||
		    (strchr(",+\"\\<>;*=()", *in))) {
			static const char hex[] = "0123456789abcdef";

			/*
			 *	Only 3 or less bytes available.
			 */
			if (outlen <= 3) {
				break;
			}

			*(out++) = '\\';
			*(out++) = hex[((*in) >> 4) & 0x0f];
			*(out++) = hex[(*in) & 0x0f];
			outlen -= 3;
			len += 3;
			in++;
			continue;
		}

		/*
		 *	Only one byte left.
		 */
		if (outlen <= 1) {
			break;
		}

		/*
		 *	Allowed character.
		 */
		*(out++) = *(in++);
		outlen--;
		len++;
	}
	*out = '\0';
	return len;
}

/*
 *	ldap_groupcmp(). Implement the Ldap-Group == "group" filter
 */
static int ldap_groupcmp(void *instance, REQUEST *req,
			 UNUSED VALUE_PAIR *request, VALUE_PAIR *check,
			 UNUSED VALUE_PAIR *check_pairs,
			 UNUSED VALUE_PAIR **reply_pairs)
{
        char            filter[MAX_FILTER_STR_LEN];
        char            gr_filter[MAX_FILTER_STR_LEN];
        int             res;
        LDAPMessage     *result = NULL;
        LDAPMessage     *msg = NULL;
        char            basedn[MAX_FILTER_STR_LEN];
	static char	firstattr[] = "dn";
	char		*attrs[] = {firstattr,NULL};
	char		**vals;
        ldap_instance   *inst = instance;
	char		*group_attrs[] = {inst->groupmemb_attr,NULL};
	LDAP_CONN	*conn;
	int		conn_id = -1;
	VALUE_PAIR	*vp_user_dn;
	VALUE_PAIR      **request_pairs;

	request_pairs = &req->config_items;

	DEBUG("  [%s] Entering ldap_groupcmp()", inst->xlat_name);

	if (check->vp_strvalue == NULL || check->length == 0){
                DEBUG("rlm_ldap::ldap_groupcmp: Illegal group name");
                return 1;
        }

        if (req == NULL){
                DEBUG("rlm_ldap::ldap_groupcmp: NULL request");
                return 1;
        }

        if (!radius_xlat(basedn, sizeof(basedn), inst->basedn, req, ldap_escape_func)) {
                DEBUG("rlm_ldap::ldap_groupcmp: unable to create basedn.");
                return 1;
        }

        while((vp_user_dn = pairfind(*request_pairs, PW_LDAP_USERDN, 0)) == NULL){
                char            *user_dn = NULL;

                if (!radius_xlat(filter, sizeof(filter), inst->filter,
					req, ldap_escape_func)){
                        DEBUG("rlm_ldap::ldap_groupcmp: unable to create filter");
                        return 1;
                }
		if ((conn_id = ldap_get_conn(inst->conns,&conn,inst)) == -1){
			radlog(L_ERR, "  [%s] All ldap connections are in use", inst->xlat_name);
			return 1;
		}
                if ((res = perform_search(inst, conn, basedn, LDAP_SCOPE_SUBTREE,
					filter, attrs, &result)) != RLM_MODULE_OK){
                        DEBUG("rlm_ldap::ldap_groupcmp: search failed");
			ldap_release_conn(conn_id,inst);
                        return 1;
                }
                if ((msg = ldap_first_entry(conn->ld, result)) == NULL) {
                        DEBUG("rlm_ldap::ldap_groupcmp: ldap_first_entry() failed");
			ldap_release_conn(conn_id,inst);
                        ldap_msgfree(result);
                        return 1;
                }
                if ((user_dn = ldap_get_dn(conn->ld, msg)) == NULL) {
                        DEBUG("rlm_ldap:ldap_groupcmp:: ldap_get_dn() failed");
			ldap_release_conn(conn_id,inst);
                        ldap_msgfree(result);
                        return 1;
                }
		ldap_release_conn(conn_id,inst);

                /*
		 *	Adding new attribute containing DN for LDAP
		 *	object associated with given username
		 */
                pairadd(request_pairs, pairmake("Ldap-UserDn", user_dn,
						T_OP_EQ));
                ldap_memfree(user_dn);
                ldap_msgfree(result);
        }

        if(!radius_xlat(gr_filter, sizeof(gr_filter),
			inst->groupmemb_filt, req, ldap_escape_func)) {
                DEBUG("rlm_ldap::ldap_groupcmp: unable to create filter.");
                return 1;
        }

	if (strchr((char *)check->vp_strvalue,',') != NULL) {
		/* This looks like a DN */
		strlcpy(filter, gr_filter, sizeof(filter));
		strlcpy(basedn, check->vp_strvalue, sizeof(basedn));
	} else
		snprintf(filter,sizeof(filter), "(&(%s=%s)%s)",
			 inst->groupname_attr,
			 (char *)check->vp_strvalue,gr_filter);

	if ((conn_id = ldap_get_conn(inst->conns,&conn,inst)) == -1) {
		radlog(L_ERR, "  [%s] All ldap connections are in use", inst->xlat_name);
		return 1;
	}

	if ((res = perform_search(inst, conn, basedn, LDAP_SCOPE_SUBTREE,
				filter, attrs, &result)) == RLM_MODULE_OK) {
		DEBUG("rlm_ldap::ldap_groupcmp: User found in group %s",
				(char *)check->vp_strvalue);
		ldap_msgfree(result);
		ldap_release_conn(conn_id,inst);
        	return 0;
	}

	ldap_release_conn(conn_id,inst);

	if (res != RLM_MODULE_NOTFOUND ) {
		DEBUG("rlm_ldap::ldap_groupcmp: Search returned error");
		return 1;
	}

	if (inst->groupmemb_attr == NULL){
		/*
		 *	Search returned NOTFOUND and searching for
		 *	membership using user object attributes is not
		 *	specified in config file
		 */
		DEBUG("rlm_ldap::ldap_groupcmp: Group %s not found or user is not a member.",(char *)check->vp_strvalue);
		return 1;
	}

	snprintf(filter,sizeof(filter), "(objectclass=*)");
	if ((conn_id = ldap_get_conn(inst->conns,&conn,inst)) == -1){
		radlog(L_ERR, "  [%s] Add ldap connections are in use", inst->xlat_name);
		return 1;
	}
	if ((res = perform_search(inst, conn, vp_user_dn->vp_strvalue,
				  LDAP_SCOPE_BASE, filter, group_attrs,
				  &result)) != RLM_MODULE_OK) {
		DEBUG("rlm_ldap::ldap_groupcmp: Search returned error");
		ldap_release_conn(conn_id, inst);
		return 1;
	}

	if ((msg = ldap_first_entry(conn->ld, result)) == NULL) {
		DEBUG("rlm_ldap::ldap_groupcmp: ldap_first_entry() failed");
		ldap_release_conn(conn_id,inst);
		ldap_msgfree(result);
		return 1;
	}
	if ((vals = ldap_get_values(conn->ld, msg,
				    inst->groupmemb_attr)) != NULL) {
		int i = 0;
		char found = 0;

		for (;i < ldap_count_values(vals);i++){
			if (strchr(vals[i],',') != NULL){
				/* This looks like a DN */
				LDAPMessage *gr_result = NULL;
				snprintf(filter,sizeof(filter), "(%s=%s)",
					inst->groupname_attr,
					(char *)check->vp_strvalue);
				if ((res = perform_search(inst, conn, vals[i],
						LDAP_SCOPE_BASE, filter,
						attrs, &gr_result)) != RLM_MODULE_OK){
					if (res != RLM_MODULE_NOTFOUND) {
						DEBUG("rlm_ldap::ldap_groupcmp: Search returned error");
						ldap_value_free(vals);
						ldap_msgfree(result);
						ldap_release_conn(conn_id,inst);
						return 1;
					}
				} else {
					ldap_msgfree(gr_result);
					found = 1;
					break;
				}
			} else {
				if (strcmp(vals[i],(char *)check->vp_strvalue) == 0){
					found = 1;
					break;
				}
			}
		}
		ldap_value_free(vals);
		ldap_msgfree(result);
		if (found == 0){
			DEBUG("rlm_ldap::groupcmp: Group %s not found or user not a member",
				(char *)check->vp_strvalue);
			ldap_release_conn(conn_id,inst);
			return 1;
		}
	} else {
			DEBUG("rlm_ldap::ldap_groupcmp: ldap_get_values() failed");
			ldap_msgfree(result);
			ldap_release_conn(conn_id,inst);
			return 1;
	}

	DEBUG("rlm_ldap::ldap_groupcmp: User found in group %s",(char *)check->vp_strvalue);
	ldap_release_conn(conn_id,inst);

        return 0;
}

/*
 * ldap_xlat()
 * Do an xlat on an LDAP URL
 */
static size_t ldap_xlat(void *instance, REQUEST *request, char *fmt,
		     char *out, size_t freespace, RADIUS_ESCAPE_STRING func)
{
	char url[MAX_FILTER_STR_LEN];
	int res;
	size_t ret = 0;
	ldap_instance *inst = instance;
	LDAPURLDesc *ldap_url;
	LDAPMessage *result = NULL;
	LDAPMessage *msg = NULL;
	char **vals;
	int conn_id = -1;
	LDAP_CONN *conn;

	DEBUG("  [%s] - ldap_xlat", inst->xlat_name);
	if (!radius_xlat(url, sizeof(url), fmt, request, func)) {
		radlog (L_ERR, "  [%s] Unable to create LDAP URL.\n", inst->xlat_name);
		return 0;
	}
	if (!ldap_is_ldap_url(url)){
		radlog (L_ERR, "  [%s] String passed does not look like an LDAP URL.\n", inst->xlat_name);
		return 0;
	}
	if (ldap_url_parse(url,&ldap_url)){
		radlog (L_ERR, "  [%s] LDAP URL parse failed.\n", inst->xlat_name);
		return 0;
	}
	if (ldap_url->lud_attrs == NULL || ldap_url->lud_attrs[0] == NULL ||
	    ( ldap_url->lud_attrs[1] != NULL ||
	      ( !*ldap_url->lud_attrs[0] ||
		! strcmp(ldap_url->lud_attrs[0],"*") ) ) ){
		radlog (L_ERR, "  [%s] Invalid Attribute(s) request.\n", inst->xlat_name);
		ldap_free_urldesc(ldap_url);
		return 0;
	}
	if (ldap_url->lud_host){
		if (strncmp(inst->server,ldap_url->lud_host,
			    strlen(inst->server)) != 0 ||
		    ldap_url->lud_port != inst->port) {
			DEBUG("  [%s] Requested server/port is not known to this module instance.", inst->xlat_name);
			ldap_free_urldesc(ldap_url);
			return 0;
		}
	}
	if ((conn_id = ldap_get_conn(inst->conns,&conn,inst)) == -1){
		radlog(L_ERR, "  [%s] All ldap connections are in use", inst->xlat_name);
		ldap_free_urldesc(ldap_url);
		return 0;
	}
	if ((res = perform_search(inst, conn, ldap_url->lud_dn, ldap_url->lud_scope, ldap_url->lud_filter, ldap_url->lud_attrs, &result)) != RLM_MODULE_OK){
		if (res == RLM_MODULE_NOTFOUND){
			DEBUG("  [%s] Search returned not found", inst->xlat_name);
			ldap_free_urldesc(ldap_url);
			ldap_release_conn(conn_id,inst);
			return 0;
		}
		DEBUG("  [%s] Search returned error", inst->xlat_name);
		ldap_free_urldesc(ldap_url);
		ldap_release_conn(conn_id,inst);
		return 0;
	}
	if ((msg = ldap_first_entry(conn->ld, result)) == NULL){
		DEBUG("  [%s] ldap_first_entry() failed", inst->xlat_name);
		ldap_msgfree(result);
		ldap_free_urldesc(ldap_url);
		ldap_release_conn(conn_id,inst);
		return 0;
	}
	if ((vals = ldap_get_values(conn->ld, msg, ldap_url->lud_attrs[0])) != NULL) {
		ret = strlen(vals[0]);
		if (ret >= freespace){
			DEBUG("  [%s] Insufficient string space", inst->xlat_name);
			ldap_free_urldesc(ldap_url);
			ldap_value_free(vals);
			ldap_msgfree(result);
			ldap_release_conn(conn_id,inst);
			return 0;
		}
		DEBUG("  [%s] Adding attribute %s, value: %s", inst->xlat_name,ldap_url->lud_attrs[0],vals[0]);
		strlcpy(out,vals[0],freespace);
		ldap_value_free(vals);
	}
	else
		ret = 0;

	ldap_msgfree(result);
	ldap_free_urldesc(ldap_url);
	ldap_release_conn(conn_id,inst);

	DEBUG("  [%s] - ldap_xlat end", inst->xlat_name);

	return ret;
}


/*
 *	For auto-header discovery.
 */
static const FR_NAME_NUMBER header_names[] = {
	{ "{clear}",	PW_CLEARTEXT_PASSWORD },
	{ "{cleartext}", PW_CLEARTEXT_PASSWORD },
	{ "{md5}",	PW_MD5_PASSWORD },
	{ "{BASE64_MD5}",	PW_MD5_PASSWORD },
	{ "{smd5}",	PW_SMD5_PASSWORD },
	{ "{crypt}",	PW_CRYPT_PASSWORD },
	{ "{sha}",	PW_SHA_PASSWORD },
	{ "{ssha}",	PW_SSHA_PASSWORD },
	{ "{nt}",	PW_NT_PASSWORD },
	{ "{ns-mta-md5}", PW_NS_MTA_MD5_PASSWORD },
	{ NULL, 0 }
};


/******************************************************************************
 *
 *      Function: rlm_ldap_authorize
 *
 *      Purpose: Check if user is authorized for remote access
 *
 ******************************************************************************/
static int ldap_authorize(void *instance, REQUEST * request)
{
	LDAPMessage	*result = NULL;
	LDAPMessage	*msg = NULL;
	LDAPMessage	*def_msg = NULL;
	LDAPMessage	*def_attr_msg = NULL;
	LDAPMessage	*def_result = NULL;
	LDAPMessage	*def_attr_result = NULL;
	ldap_instance	*inst = instance;
	char		*user_dn = NULL;
	char		filter[MAX_FILTER_STR_LEN];
	char		basedn[MAX_FILTER_STR_LEN];
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	int		res;
	VALUE_PAIR	**check_pairs, **reply_pairs;
	char		**vals;
	VALUE_PAIR      *module_fmsg_vp;
	VALUE_PAIR	*user_profile;
	char            module_fmsg[MAX_STRING_LEN];
	LDAP_CONN	*conn;
	int		conn_id = -1;
	int		added_known_password = 0;

	if (!request->username){
		RDEBUG2("Attribute \"User-Name\" is required for authorization.\n");
		return RLM_MODULE_NOOP;
	}

	check_pairs = &request->config_items;
	reply_pairs = &request->reply->vps;

	/*
	 * Check for valid input, zero length names not permitted
	 */
	if (request->username->vp_strvalue == 0) {
		DEBUG2("zero length username not permitted\n");
		return RLM_MODULE_INVALID;
	}
	RDEBUG("performing user authorization for %s",
	       request->username->vp_strvalue);

	if (!radius_xlat(filter, sizeof(filter), inst->filter,
			 request, ldap_escape_func)) {
		radlog(L_ERR, "  [%s] unable to create filter.\n", inst->xlat_name);
		return RLM_MODULE_INVALID;
	}

	if (!radius_xlat(basedn, sizeof(basedn), inst->basedn,
			 request, ldap_escape_func)) {
		radlog(L_ERR, "  [%s] unable to create basedn.\n", inst->xlat_name);
		return RLM_MODULE_INVALID;
	}

	if ((conn_id = ldap_get_conn(inst->conns,&conn,inst)) == -1){
		radlog(L_ERR, "  [%s] All ldap connections are in use", inst->xlat_name);
		return RLM_MODULE_FAIL;
	}
	if ((res = perform_search(instance, conn, basedn, LDAP_SCOPE_SUBTREE, filter, inst->atts, &result)) != RLM_MODULE_OK) {
		RDEBUG("search failed");
		if (res == RLM_MODULE_NOTFOUND){
			snprintf(module_fmsg,sizeof(module_fmsg),"  [%s] User not found", inst->xlat_name);
			module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
		}
		ldap_release_conn(conn_id,inst);
		return (res);
	}
	if ((msg = ldap_first_entry(conn->ld, result)) == NULL) {
		RDEBUG("ldap_first_entry() failed");
		ldap_msgfree(result);
		ldap_release_conn(conn_id,inst);
		return RLM_MODULE_FAIL;
	}
	if ((user_dn = ldap_get_dn(conn->ld, msg)) == NULL) {
		RDEBUG("ldap_get_dn() failed");
		ldap_msgfree(result);
		ldap_release_conn(conn_id,inst);
		return RLM_MODULE_FAIL;
	}
	/*
	 * Adding new attribute containing DN for LDAP object associated with
	 * given username
	 */
	pairadd(check_pairs, pairmake("Ldap-UserDn", user_dn, T_OP_EQ));
	ldap_memfree(user_dn);


	/* Remote access is controled by attribute of the user object */
	if (inst->access_attr) {
		if ((vals = ldap_get_values(conn->ld, msg, inst->access_attr)) != NULL) {
			if (inst->default_allow){
				RDEBUG("checking if remote access for %s is allowed by %s", request->username->vp_strvalue, inst->access_attr);
				if (!strncmp(vals[0], "FALSE", 5)) {
					RDEBUG("dialup access disabled");
					snprintf(module_fmsg,sizeof(module_fmsg),"  [%s] Access Attribute denies access", inst->xlat_name);
					module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
					pairadd(&request->packet->vps, module_fmsg_vp);
					ldap_msgfree(result);
					ldap_value_free(vals);
					ldap_release_conn(conn_id,inst);
					return RLM_MODULE_USERLOCK;
				}
				ldap_value_free(vals);
			}
			else{
				RDEBUG("%s attribute exists - access denied by default", inst->access_attr);
				snprintf(module_fmsg,sizeof(module_fmsg),"  [%s] Access Attribute denies access", inst->xlat_name);
				module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
				pairadd(&request->packet->vps, module_fmsg_vp);
				ldap_msgfree(result);
				ldap_value_free(vals);
				ldap_release_conn(conn_id,inst);
				return RLM_MODULE_USERLOCK;
			}
		} else {
			if (inst->default_allow){
				RDEBUG("no %s attribute - access denied by default", inst->access_attr);
				snprintf(module_fmsg,sizeof(module_fmsg),"  [%s] Access Attribute denies access", inst->xlat_name);
				module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
				pairadd(&request->packet->vps, module_fmsg_vp);
				ldap_msgfree(result);
				ldap_release_conn(conn_id,inst);
				return RLM_MODULE_USERLOCK;
			}
		}
	}

	/*
	 * Check for the default profile entry. If it exists then add the
	 * attributes it contains in the check and reply pairs
	 */

	user_profile = pairfind(request->config_items, PW_USER_PROFILE, 0);
	if (inst->default_profile || user_profile){
		char *profile = inst->default_profile;

		strlcpy(filter,inst->base_filter,sizeof(filter));
		if (user_profile)
			profile = user_profile->vp_strvalue;
		if (profile && *profile){
			if ((res = perform_search(instance, conn,
				profile, LDAP_SCOPE_BASE,
				filter, inst->atts, &def_result)) == RLM_MODULE_OK){
				if ((def_msg = ldap_first_entry(conn->ld,def_result))){
					if ((check_tmp = ldap_pairget(conn->ld,def_msg,inst->check_item_map,check_pairs,1, inst))) {
						if (inst->do_xlat){
							pairxlatmove(request, check_pairs, &check_tmp);
							pairfree(&check_tmp);
						}
						else
							pairadd(check_pairs,check_tmp);
					}
					if ((reply_tmp = ldap_pairget(conn->ld,def_msg,inst->reply_item_map,reply_pairs,0, inst))) {
						if (inst->do_xlat){
							pairxlatmove(request, reply_pairs, &reply_tmp);
							pairfree(&reply_tmp);
						}
						else
							pairadd(reply_pairs,reply_tmp);
					}
				}
				ldap_msgfree(def_result);
			} else
				RDEBUG("default_profile/user-profile search failed");
		}
	}

	/*
	 * Check for the profile attribute. If it exists, we assume that it
	 * contains the DN of an entry containg a profile for the user. That
	 * way we can have different general profiles for various user groups
	 * (students,faculty,staff etc)
	 */

	if (inst->profile_attr){
		if ((vals = ldap_get_values(conn->ld, msg, inst->profile_attr)) != NULL) {
			unsigned int i=0;
			strlcpy(filter,inst->base_filter,sizeof(filter));
			while(vals[i] && *vals[i]){
				if ((res = perform_search(instance, conn,
					vals[i], LDAP_SCOPE_BASE,
					filter, inst->atts, &def_attr_result)) == RLM_MODULE_OK){
					if ((def_attr_msg = ldap_first_entry(conn->ld,def_attr_result))){
						if ((check_tmp = ldap_pairget(conn->ld,def_attr_msg,inst->check_item_map,check_pairs,1, inst))) {
							if (inst->do_xlat){
								pairxlatmove(request, check_pairs, &check_tmp);
								pairfree(&check_tmp);
							}
							else
								pairadd(check_pairs,check_tmp);
						}
						if ((reply_tmp = ldap_pairget(conn->ld,def_attr_msg,inst->reply_item_map,reply_pairs,0, inst))) {
							if (inst->do_xlat){
								pairxlatmove(request, reply_pairs, &reply_tmp);
								pairfree(&reply_tmp);
							}
							else
								pairadd(reply_pairs,reply_tmp);
						}
					}
					ldap_msgfree(def_attr_result);
				} else
					RDEBUG("profile_attribute search failed");
				i++;
			}
			ldap_value_free(vals);
		}
	}
	if (inst->passwd_attr && *inst->passwd_attr) {
#ifdef NOVELL_UNIVERSAL_PASSWORD
		if (strcasecmp(inst->passwd_attr,"nspmPassword") != 0) {
#endif
			VALUE_PAIR *passwd_item;
			char **passwd_vals;
			char *value = NULL;
			int i;

			/*
			 *	Read the password from the DB, and
			 *	add it to the request.
			 */
			passwd_vals = ldap_get_values(conn->ld,msg,
						      inst->passwd_attr);

			/*
			 *	Loop over what we received, and parse it.
			 */
			if (passwd_vals) for (i = 0;
					      passwd_vals[i] != NULL;
					      i++) {
				int attr = PW_USER_PASSWORD;

				if (!*passwd_vals[i])
					continue;

				value = passwd_vals[i];
				if (!value) continue;

				passwd_item = radius_paircreate(request,
								&request->config_items,
								attr, 0,
								PW_TYPE_STRING);
				strlcpy(passwd_item->vp_strvalue, value,
					sizeof(passwd_item->vp_strvalue));
				passwd_item->length = strlen(passwd_item->vp_strvalue);
				RDEBUG("Added %s = %s in check items",
				      passwd_item->name,
				      passwd_item->vp_strvalue);
				added_known_password = 1;
			}
			ldap_value_free(passwd_vals);
#ifdef NOVELL_UNIVERSAL_PASSWORD
  		}
		else{
		/*
	 	* Read Universal Password from eDirectory
	 	*/
			VALUE_PAIR	*passwd_item;
			VALUE_PAIR	*vp_user_dn;
			char		*universal_password = NULL;
			size_t		universal_password_len = UNIVERSAL_PASS_LEN;
			char		*passwd_val = NULL;

			res = 0;

			if ((passwd_item = pairfind(request->config_items, PW_CLEARTEXT_PASSWORD, 0)) == NULL){

				universal_password = rad_malloc(universal_password_len);
				memset(universal_password, 0, universal_password_len);

				vp_user_dn = pairfind(request->config_items,PW_LDAP_USERDN, 0);
				res = nmasldap_get_password(conn->ld,vp_user_dn->vp_strvalue,&universal_password_len,universal_password);

				if (res == 0){
					passwd_val = universal_password;
					if (passwd_val){
						passwd_item = radius_paircreate(request, &request->config_items, PW_CLEARTEXT_PASSWORD, 0, PW_TYPE_STRING);
						strlcpy(passwd_item->vp_strvalue,passwd_val,sizeof(passwd_item->vp_strvalue));
						passwd_item->length = strlen(passwd_item->vp_strvalue);
						added_known_password = 1;

#ifdef NOVELL
						{
							DICT_ATTR *dattr;
							VALUE_PAIR	*vp_inst, *vp_apc;
							int inst_attr, apc_attr;

							dattr = dict_attrbyname("LDAP-Instance");
							inst_attr = dattr->attr;
							dattr = dict_attrbyname("eDir-APC");
							apc_attr = dattr->attr;

							vp_inst = pairfind(request->config_items, inst_attr, 0);
							if(vp_inst == NULL){
								/*
								 * The authorize method of no other LDAP module instance has
								 * processed this request.
								 */
								vp_inst = radius_paircreate(request, &request->config_items, inst_attr, 0, PW_TYPE_STRING);
								strlcpy(vp_inst->vp_strvalue, inst->xlat_name, sizeof(vp_inst->vp_strvalue));
								vp_inst->length = strlen(vp_inst->vp_strvalue);

								/*
								 * Inform the authenticate / post-auth method about the presence
								 * of UP in the config items list and whether eDirectory account
								 * policy check is to be performed or not.
								 */
								vp_apc = radius_paircreate(request, &request->config_items, apc_attr, 0, PW_TYPE_STRING);
								if(!inst->edir_account_policy_check){
									/* Do nothing */
									strcpy(vp_apc->vp_strvalue, "1");
								}else{
									/* Perform eDirectory account-policy check */
									strcpy(vp_apc->vp_strvalue, "2");
								}
								vp_apc->length = 1;
							}
						}
#endif

						RDEBUG("Added the eDirectory password %s in check items as %s",passwd_item->vp_strvalue,passwd_item->name);
					}
				}
				else {
					RDEBUG("Error reading Universal Password.Return Code = %d",res);
				}

				memset(universal_password, 0, universal_password_len);
				free(universal_password);
			}
		}
#endif
	}

#ifdef NOVELL
	{
		VALUE_PAIR      *vp_auth_opt;
		DICT_ATTR       *dattr;
		char            **auth_option;
		int             auth_opt_attr;

		dattr = dict_attrbyname("eDir-Auth-Option");
		auth_opt_attr = dattr->attr;
		if(pairfind(*check_pairs, auth_opt_attr, 0) == NULL){
			if ((auth_option = ldap_get_values(conn->ld, msg, "sasDefaultLoginSequence")) != NULL) {
				if ((vp_auth_opt = paircreate(auth_opt_attr, 0, PW_TYPE_STRING)) == NULL){
					radlog(L_ERR, "  [%s] Could not allocate memory. Aborting.", inst->xlat_name);
					ldap_msgfree(result);
					ldap_release_conn(conn_id, inst);
				}
				strcpy(vp_auth_opt->vp_strvalue, auth_option[0]);
				vp_auth_opt->length = strlen(auth_option[0]);
				pairadd(&request->config_items, vp_auth_opt);
			}else{
				RDEBUG("No default NMAS login sequence");
			}
		}
	}
#endif

	RDEBUG("looking for check items in directory...");

	if ((check_tmp = ldap_pairget(conn->ld, msg, inst->check_item_map,check_pairs,1, inst)) != NULL) {
		if (inst->do_xlat){
			pairxlatmove(request, check_pairs, &check_tmp);
			pairfree(&check_tmp);
		}
		else
			pairadd(check_pairs,check_tmp);
	}


	RDEBUG("looking for reply items in directory...");


	if ((reply_tmp = ldap_pairget(conn->ld, msg, inst->reply_item_map,reply_pairs,0, inst)) != NULL) {
		if (inst->do_xlat){
			pairxlatmove(request, reply_pairs, &reply_tmp);
			pairfree(&reply_tmp);
		}
		else
			pairadd(reply_pairs,reply_tmp);
	}

       if (inst->do_comp && paircompare(request,request->packet->vps,*check_pairs,reply_pairs) != 0){
#ifdef NOVELL
		/* Don't perform eDirectory APC if RADIUS authorize fails */
		int apc_attr;
		VALUE_PAIR *vp_apc;
		DICT_ATTR *dattr;

		dattr = dict_attrbyname("eDir-APC");
		apc_attr = dattr->attr;

		vp_apc = pairfind(request->config_items, apc_attr, 0);
		if(vp_apc)
			vp_apc->vp_strvalue[0] = '1';
#endif

		RDEBUG("Pairs do not match. Rejecting user.");
		snprintf(module_fmsg,sizeof(module_fmsg),"  [%s] Pairs do not match", inst->xlat_name);
		module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
		pairadd(&request->packet->vps, module_fmsg_vp);
		ldap_msgfree(result);
		ldap_release_conn(conn_id,inst);

		return RLM_MODULE_REJECT;
	}
       
       /*
	*	More warning messages for people who can't be bothered
	*	to read the documentation.
	*/
       if (debug_flag > 1) {
	       if (!pairfind(request->config_items, PW_CLEARTEXT_PASSWORD, 0) &&
		   !pairfind(request->config_items, PW_NT_PASSWORD, 0) &&
		   !pairfind(request->config_items, PW_USER_PASSWORD, 0) &&
		   !pairfind(request->config_items, PW_PASSWORD_WITH_HEADER, 0) &&
		   !pairfind(request->config_items, PW_CRYPT_PASSWORD, 0)) {
		       DEBUG("WARNING: No \"known good\" password was found in LDAP.  Are you sure that the user is configured correctly?");
	       }
       }

	/*
 	 * Module should default to LDAP authentication if no Auth-Type
	 * specified.  Note that we do this ONLY if configured, AND we
	 * set the Auth-Type to our module name, which allows multiple
	 * ldap instances to work.
	 */
	if (inst->set_auth_type &&
	    (pairfind(*check_pairs, PW_AUTH_TYPE, 0) == NULL) &&
	    request->password &&
	    (request->password->attribute == PW_USER_PASSWORD) &&
	    !added_known_password) {
		pairadd(check_pairs, pairmake("Auth-Type", inst->auth_type, T_OP_EQ));
		RDEBUG("Setting Auth-Type = %s", inst->auth_type);
	}

	RDEBUG("user %s authorized to use remote access",
	      request->username->vp_strvalue);
	ldap_msgfree(result);
	ldap_release_conn(conn_id,inst);

	return RLM_MODULE_OK;
}

/*****************************************************************************
 *
 *	Function: rlm_ldap_authenticate
 *
 *	Purpose: Check the user's password against ldap database
 *
 *****************************************************************************/
static int ldap_authenticate(void *instance, REQUEST * request)
{
	LDAP           *ld_user;
	LDAPMessage    *result, *msg;
	ldap_instance  *inst = instance;
	static char	firstattr[] = "uid";
	char           *user_dn, *attrs[] = {firstattr, NULL};
	char		filter[MAX_FILTER_STR_LEN];
	char		basedn[MAX_FILTER_STR_LEN];
	int		res;
	VALUE_PAIR     *vp_user_dn;
	VALUE_PAIR      *module_fmsg_vp;
	char            module_fmsg[MAX_STRING_LEN];
	LDAP_CONN	*conn;
	int		conn_id = -1;
#ifdef NOVELL
	char		*err = NULL;
#endif

	/*
	 * Ensure that we're being passed a plain-text password, and not
	 * anything else.
	 */

	if (!request->username) {
		radlog(L_AUTH, "  [%s] Attribute \"User-Name\" is required for authentication.\n", inst->xlat_name);
		return RLM_MODULE_INVALID;
	}

	if (!request->password){
		radlog(L_AUTH, "  [%s] Attribute \"User-Password\" is required for authentication.", inst->xlat_name);
		DEBUG2("  You seem to have set \"Auth-Type := LDAP\" somewhere.");
		DEBUG2("  THAT CONFIGURATION IS WRONG.  DELETE IT.");
		DEBUG2("  YOU ARE PREVENTING THE SERVER FROM WORKING PROPERLY.");
		return RLM_MODULE_INVALID;
	}

	if(request->password->attribute != PW_USER_PASSWORD) {
		radlog(L_AUTH, "  [%s] Attribute \"User-Password\" is required for authentication. Cannot use \"%s\".", inst->xlat_name, request->password->name);
		return RLM_MODULE_INVALID;
	}

	if (request->password->length == 0) {
		snprintf(module_fmsg,sizeof(module_fmsg),"  [%s] empty password supplied", inst->xlat_name);
		module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
		pairadd(&request->packet->vps, module_fmsg_vp);
		return RLM_MODULE_INVALID;
	}

	/*
	 * Check that we don't have any failed connections. If we do there's no real need
	 * of runing. Also give it another chance if we have a lot of failed connections.
	 */
	if (inst->failed_conns > MAX_FAILED_CONNS_END)
		inst->failed_conns = 0;
	if (inst->failed_conns > MAX_FAILED_CONNS_START){
		inst->failed_conns++;
		return RLM_MODULE_FAIL;
	}


	RDEBUG("login attempt by \"%s\" with password \"%s\"",
	       request->username->vp_strvalue, request->password->vp_strvalue);

	while ((vp_user_dn = pairfind(request->config_items,
				      PW_LDAP_USERDN, 0)) == NULL) {
		if (!radius_xlat(filter, sizeof(filter), inst->filter,
				request, ldap_escape_func)) {
			radlog(L_ERR, "  [%s] unable to create filter.\n", inst->xlat_name);
			return RLM_MODULE_INVALID;
		}

		if (!radius_xlat(basedn, sizeof(basedn), inst->basedn,
		 		request, ldap_escape_func)) {
			radlog(L_ERR, "  [%s] unable to create basedn.\n", inst->xlat_name);
			return RLM_MODULE_INVALID;
		}

		if ((conn_id = ldap_get_conn(inst->conns,&conn,inst)) == -1){
			radlog(L_ERR, "  [%s] All ldap connections are in use", inst->xlat_name);
			return RLM_MODULE_FAIL;
		}
		if ((res = perform_search(instance, conn, basedn, LDAP_SCOPE_SUBTREE, filter, attrs, &result)) != RLM_MODULE_OK) {
			if (res == RLM_MODULE_NOTFOUND){
				snprintf(module_fmsg,sizeof(module_fmsg),"  [%s] User not found", inst->xlat_name);
				module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
				pairadd(&request->packet->vps, module_fmsg_vp);
			}
			ldap_release_conn(conn_id,inst);
			return (res);
		}
		if ((msg = ldap_first_entry(conn->ld, result)) == NULL) {
			ldap_msgfree(result);
			ldap_release_conn(conn_id,inst);
			return RLM_MODULE_FAIL;
		}
		if ((user_dn = ldap_get_dn(conn->ld, msg)) == NULL) {
			RDEBUG("ldap_get_dn() failed");
			ldap_msgfree(result);
			ldap_release_conn(conn_id,inst);
			return RLM_MODULE_FAIL;
		}
		ldap_release_conn(conn_id,inst);
		pairadd(&request->config_items, pairmake("Ldap-UserDn", user_dn, T_OP_EQ));
		ldap_memfree(user_dn);
		ldap_msgfree(result);
	}

	user_dn = vp_user_dn->vp_strvalue;

	RDEBUG("user DN: %s", user_dn);

#ifndef NOVELL
	ld_user = ldap_connect(instance, user_dn, request->password->vp_strvalue,
			       1, &res, NULL);
#else
	/* Don't perform eDirectory APC again after attempting to bind here. */
	{
		int apc_attr;
		DICT_ATTR *dattr;
		VALUE_PAIR *vp_apc;
		VALUE_PAIR      *vp_auth_opt, *vp_state;
		int auth_opt_attr;
		char seq[256];
		char host_ipaddr[32];
		LDAP_CONN       *conn1;
		int auth_state = -1;
		char            *challenge = NULL;
		size_t          challenge_len = MAX_CHALLENGE_LEN;
		char            *state = NULL;

		dattr = dict_attrbyname("eDir-APC");
		apc_attr = dattr->attr;
		vp_apc = pairfind(request->config_items, apc_attr, 0);
		if(vp_apc && vp_apc->vp_strvalue[0] == '2')
			vp_apc->vp_strvalue[0] = '3';

		res = 0;

		dattr = dict_attrbyname("eDir-Auth-Option");
		auth_opt_attr = dattr->attr;

		vp_auth_opt = pairfind(request->config_items, auth_opt_attr, 0);

		if(vp_auth_opt )
		{
			RDEBUG("ldap auth option = %s", vp_auth_opt->vp_strvalue);
			strncpy(seq, vp_auth_opt->vp_strvalue, vp_auth_opt->length);
			seq[vp_auth_opt->length] = '\0';
			if( strcasecmp(seq, "<No Default>") ){

				/* Get the client IP address to check for packet validity */
				inet_ntop(AF_INET, &request->packet->src_ipaddr, host_ipaddr, sizeof(host_ipaddr));

				/* challenge variable is used to receive the challenge from the
				 * Token method (if any) and also to send the state attribute
				 * in case the request packet is a reply to a challenge
				 */
				challenge = rad_malloc(MAX_CHALLENGE_LEN);

				/*  If state attribute present in request it is a reply to challenge. */
				if((vp_state = pairfind(request->packet->vps, PW_STATE, 0))!= NULL ){
					RDEBUG("Response to Access-Challenge");
					strncpy(challenge, vp_state->vp_strvalue, sizeof(challenge));
					challenge_len = vp_state->length;
					challenge[challenge_len] = 0;
					auth_state = -2;
				}

				if ((conn_id = ldap_get_conn(inst->conns, &conn1, inst)) == -1){
					radlog(L_ERR, "  [%s] All ldap connections are in use", inst->xlat_name);
					res =  RLM_MODULE_FAIL;
				}

				if(!conn1){
					radlog(L_ERR, "  [%s] NULL connection handle passed", inst->xlat_name);
					return RLM_MODULE_FAIL;
				}

				if (conn1->failed_conns > MAX_FAILED_CONNS_START){
					conn1->failed_conns++;
					if (conn1->failed_conns >= MAX_FAILED_CONNS_END){
						conn1->failed_conns = MAX_FAILED_CONNS_RESTART;
						conn1->bound = 0;
					}
				}
retry:
				if (!conn1->bound || conn1->ld == NULL) {
					DEBUG2("  [%s] attempting LDAP reconnection", inst->xlat_name);
					if (conn1->ld){
						DEBUG2("  [%s] closing existing LDAP connection", inst->xlat_name);
						ldap_unbind_s(conn1->ld);
					}
					if ((conn1->ld = ldap_connect(instance, inst->login,inst->password, 0, &res, NULL)) == NULL) {
						radlog(L_ERR, "  [%s] (re)connection attempt failed", inst->xlat_name);
						conn1->failed_conns++;
						return (RLM_MODULE_FAIL);
					}
					conn1->bound = 1;
					conn1->failed_conns = 0;
				}
				RDEBUG("Performing NMAS Authentication for user: %s, seq: %s \n", user_dn,seq);

				res = radLdapXtnNMASAuth(conn1->ld, user_dn, request->password->vp_strvalue, seq, host_ipaddr, &challenge_len, challenge, &auth_state );

				switch(res){
					case LDAP_SUCCESS:
						ldap_release_conn(conn_id,inst);
						if ( auth_state == -1)
							res = RLM_MODULE_FAIL;
						if ( auth_state != REQUEST_CHALLENGED){
							if (auth_state == REQUEST_ACCEPTED){
								RDEBUG("user %s authenticated succesfully",request->username->vp_strvalue);
								res = RLM_MODULE_OK;
							}else if(auth_state == REQUEST_REJECTED){
								RDEBUG("user %s authentication failed",request->username->vp_strvalue);
								res = RLM_MODULE_REJECT;
							}
						}else{
							/* Request challenged. Generate Reply-Message attribute with challenge data */
							pairadd(&request->reply->vps,pairmake("Reply-Message", challenge, T_OP_EQ));
							/* Generate state attribute */
							state = rad_malloc(MAX_CHALLENGE_LEN);
							(void) sprintf(state, "%s%s", challenge, challenge);
							vp_state = paircreate(PW_STATE, 0, PW_TYPE_OCTETS);
							memcpy(vp_state->vp_strvalue, state, strlen(state));
							vp_state->length = strlen(state);
							pairadd(&request->reply->vps, vp_state);
							free(state);
							/* Mark the packet as a Acceess-Challenge Packet */
							request->reply->code = PW_ACCESS_CHALLENGE;
							RDEBUG("Sending Access-Challenge.");
							res = RLM_MODULE_HANDLED;
						}
						if(challenge)
							free(challenge);
						return res;
					case LDAP_SERVER_DOWN:
						radlog(L_ERR, "  [%s] nmas authentication failed: LDAP connection lost.", inst->xlat_name);                                                conn->failed_conns++;
						if (conn->failed_conns <= MAX_FAILED_CONNS_START){
							radlog(L_INFO, "  [%s] Attempting reconnect", inst->xlat_name);
							conn->bound = 0;
							goto retry;
						}
						if(challenge)
							free(challenge);
						return RLM_MODULE_FAIL;
					default:
						ldap_release_conn(conn_id,inst);
						if(challenge)
							free(challenge);
						return RLM_MODULE_FAIL;
				}
			}
		}
 	}

	ld_user = ldap_connect(instance, user_dn, request->password->vp_strvalue,
			1, &res, &err);

	if(err != NULL){
		/* 'err' contains the LDAP connection error description */
		RDEBUG("%s", err);
		pairadd(&request->reply->vps, pairmake("Reply-Message", err, T_OP_EQ));
		ldap_memfree((void *)err);
	}
#endif

	if (ld_user == NULL){
		if (res == RLM_MODULE_REJECT){
			inst->failed_conns = 0;
			snprintf(module_fmsg,sizeof(module_fmsg),"  [%s] Bind as user failed", inst->xlat_name);
			module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
		}
		if (res == RLM_MODULE_FAIL){
			RDEBUG("ldap_connect() failed");
			inst->failed_conns++;
		}
		return (res);
	}

	RDEBUG("user %s authenticated succesfully",
	      request->username->vp_strvalue);
	ldap_unbind_s(ld_user);
	inst->failed_conns = 0;

	return RLM_MODULE_OK;
}

#ifdef NOVELL
/*****************************************************************************
 *
 *	Function: rlm_ldap_postauth
 *
 *	Purpose: Perform eDirectory account policy check and failed-login reporting
 *	to eDirectory.
 *
 *****************************************************************************/
static int ldap_postauth(void *instance, REQUEST * request)
{
	int res = RLM_MODULE_FAIL;
	int inst_attr, apc_attr;
	char password[UNIVERSAL_PASS_LEN];
	ldap_instance  *inst = instance;
	LDAP_CONN	*conn;
	VALUE_PAIR *vp_inst, *vp_apc;
	DICT_ATTR *dattr;

	dattr = dict_attrbyname("LDAP-Instance");
	inst_attr = dattr->attr;
	dattr = dict_attrbyname("eDir-APC");
	apc_attr = dattr->attr;

	vp_inst = pairfind(request->config_items, inst_attr, 0);

	/*
	 * Check if the password in the config items list is the user's UP which has
	 * been read in the authorize method of this instance of the LDAP module.
	 */
	if((vp_inst == NULL) || strcmp(vp_inst->vp_strvalue, inst->xlat_name))
		return RLM_MODULE_NOOP;

	vp_apc = pairfind(request->config_items, apc_attr, 0);

	switch(vp_apc->vp_strvalue[0]){
		case '1':
			/* Account policy check not enabled */
		case '3':
			/* Account policy check has been completed */
			res = RLM_MODULE_NOOP;
			break;
		case '2':
			{
				int err, conn_id = -1;
				char *error_msg = NULL;
				VALUE_PAIR *vp_fdn, *vp_pwd;
				DICT_ATTR *da;

				if (request->reply->code == PW_AUTHENTICATION_REJECT) {
				  /* Bind to eDirectory as the RADIUS user with a wrong password. */
				  vp_pwd = pairfind(request->config_items, PW_CLEARTEXT_PASSWORD, 0);
				  if (vp_pwd && *vp_pwd->vp_strvalue) {
				  	  strcpy(password, vp_pwd->vp_strvalue);
					  if (password[0] != 'a') {
						  password[0] = 'a';
					  } else {
						  password[0] = 'b';
					  }
				  } else {
					  strcpy(password, "dummy_password");
				  }
				  res = RLM_MODULE_REJECT;
				} else {
					/* Bind to eDirectory as the RADIUS user using the user's UP */
					vp_pwd = pairfind(request->config_items, PW_CLEARTEXT_PASSWORD, 0);
					if (vp_pwd == NULL) {
						RDEBUG("User's Universal Password not in config items list.");
						return RLM_MODULE_FAIL;
					}
					strcpy(password, vp_pwd->vp_strvalue);
				}

				if ((da = dict_attrbyname("Ldap-UserDn")) == NULL) {
					RDEBUG("Attribute for user FDN not found in dictionary. Unable to proceed");
					return RLM_MODULE_FAIL;
				}

				vp_fdn = pairfind(request->config_items, da->attr, 0);
				if (vp_fdn == NULL) {
					RDEBUG("User's FQDN not in config items list.");
					return RLM_MODULE_FAIL;
				}

				if ((conn_id = ldap_get_conn(inst->apc_conns, &conn, inst)) == -1){
					radlog(L_ERR, "  [%s] All ldap connections are in use", inst->xlat_name);
					return RLM_MODULE_FAIL;
				}

				/*
				 *	If there is an existing LDAP
				 *	connection to the directory,
				 *	bind over it. Otherwise,
				 *	establish a new connection.
				 */
			postauth_reconnect:
				if (!conn->bound || conn->ld == NULL) {
					DEBUG2("  [%s] attempting LDAP reconnection", inst->xlat_name);
					if (conn->ld){
						DEBUG2("  [%s] closing existing LDAP connection", inst->xlat_name);
						ldap_unbind_s(conn->ld);
					}
					if ((conn->ld = ldap_connect(instance, (char *)vp_fdn->vp_strvalue, password, 0, &res, &error_msg)) == NULL) {
						radlog(L_ERR, "  [%s] eDirectory account policy check failed.", inst->xlat_name);

						if (error_msg != NULL) {
							RDEBUG("%s", error_msg);
							pairadd(&request->reply->vps, pairmake("Reply-Message", error_msg, T_OP_EQ));
							ldap_memfree((void *)error_msg);
						}

						vp_apc->vp_strvalue[0] = '3';
						ldap_release_apc_conn(conn_id, inst);
						return RLM_MODULE_REJECT;
					}
					conn->bound = 1;
				} else if((err = ldap_simple_bind_s(conn->ld, (char *)vp_fdn->vp_strvalue, password)) != LDAP_SUCCESS) {
					if (err == LDAP_SERVER_DOWN) {
						conn->bound = 0;
						goto postauth_reconnect;
					}
					RDEBUG("eDirectory account policy check failed.");
					ldap_get_option(conn->ld, LDAP_OPT_ERROR_STRING, &error_msg);
					if (error_msg != NULL) {
						RDEBUG("%s", error_msg);
						pairadd(&request->reply->vps, pairmake("Reply-Message", error_msg, T_OP_EQ));
						ldap_memfree((void *)error_msg);
					}
					vp_apc->vp_strvalue[0] = '3';
					ldap_release_apc_conn(conn_id, inst);
					return RLM_MODULE_REJECT;
				}
				vp_apc->vp_strvalue[0] = '3';
				ldap_release_apc_conn(conn_id, inst);
				return RLM_MODULE_OK;
			}
	}
	return res;
}
#endif

#if LDAP_SET_REBIND_PROC_ARGS == 3
static int ldap_rebind(LDAP *ld, LDAP_CONST char *url,
		       UNUSED ber_tag_t request, UNUSED ber_int_t msgid,
		       void *params )
{
	ldap_instance	*inst = params;

	DEBUG("  [%s] rebind to URL %s", inst->xlat_name,url);
	return ldap_bind_s(ld, inst->login, inst->password, LDAP_AUTH_SIMPLE);
}
#endif

static LDAP *ldap_connect(void *instance, const char *dn, const char *password,
			  int auth, int *result, char **err)
{
	ldap_instance  *inst = instance;
	LDAP           *ld = NULL;
	int             msgid, rc, ldap_version;
	int		ldap_errno = 0;
	LDAPMessage    *res;
	struct timeval tv;

	if (inst->is_url){
#ifdef HAVE_LDAP_INITIALIZE
		DEBUG("  [%s] (re)connect to %s, authentication %d", inst->xlat_name, inst->server, auth);
		if (ldap_initialize(&ld, inst->server) != LDAP_SUCCESS) {
			exec_trigger(NULL, inst->cs, "modules.ldap.fail", FALSE);
			radlog(L_ERR, "  [%s] ldap_initialize() failed", inst->xlat_name);
			*result = RLM_MODULE_FAIL;
			return (NULL);
		}
#endif
	} else {
		DEBUG("  [%s] (re)connect to %s:%d, authentication %d", inst->xlat_name, inst->server, inst->port, auth);
		if ((ld = ldap_init(inst->server, inst->port)) == NULL) {
			exec_trigger(NULL, inst->cs, "modules.ldap.fail", FALSE);
			radlog(L_ERR, "  [%s] ldap_init() failed", inst->xlat_name);
			*result = RLM_MODULE_FAIL;
			return (NULL);
		}
	}

	tv.tv_sec = inst->net_timeout;
	tv.tv_usec = 0;
	if (ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT,
			    (void *) &tv) != LDAP_OPT_SUCCESS) {
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "  [%s] Could not set LDAP_OPT_NETWORK_TIMEOUT %d: %s", inst->xlat_name, inst->net_timeout, ldap_err2string(ldap_errno));
	}

	/*
	 *	Leave "chase_referrals" unset to use the OpenLDAP
	 *	default.
	 */
	if (inst->chase_referrals != 2) {
		if (inst->chase_referrals) {
			rc=ldap_set_option(ld, LDAP_OPT_REFERRALS,
					   LDAP_OPT_ON);
			
#if LDAP_SET_REBIND_PROC_ARGS == 3
			if (inst->rebind == 1) {
				ldap_set_rebind_proc(ld, ldap_rebind,
						     inst);
			}
#endif
		} else {
			rc=ldap_set_option(ld, LDAP_OPT_REFERRALS,
					   LDAP_OPT_OFF);
		}
		if (rc != LDAP_OPT_SUCCESS) {
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
			radlog(L_ERR, "  [%s] Could not set LDAP_OPT_REFERRALS=%d  %s", inst->xlat_name, inst->chase_referrals, ldap_err2string(ldap_errno));
		}
	}

	if (ldap_set_option(ld, LDAP_OPT_TIMELIMIT,
			    (void *) &(inst->timelimit)) != LDAP_OPT_SUCCESS) {
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "  [%s] Could not set LDAP_OPT_TIMELIMIT %d: %s", inst->xlat_name, inst->timelimit, ldap_err2string(ldap_errno));
	}

	if (inst->ldap_debug && ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &(inst->ldap_debug)) != LDAP_OPT_SUCCESS) {
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "  [%s] Could not set LDAP_OPT_DEBUG_LEVEL %d: %s", inst->xlat_name, inst->ldap_debug, ldap_err2string(ldap_errno));
	}

	ldap_version = LDAP_VERSION3;
	if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
			    &ldap_version) != LDAP_OPT_SUCCESS) {
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "  [%s] Could not set LDAP version to V3: %s", inst->xlat_name, ldap_err2string(ldap_errno));
	}

#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	if (ldap_set_option(ld, LDAP_OPT_X_KEEPALIVE_IDLE,
			    (void *) &(inst->keepalive_idle)) != LDAP_OPT_SUCCESS) {
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "  [%s] Could not set LDAP_OPT_X_KEEPALIVE_IDLE %d: %s", inst->xlat_name, inst->keepalive_idle, ldap_err2string(ldap_errno));
	}
#endif

#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	if (ldap_set_option(ld, LDAP_OPT_X_KEEPALIVE_PROBES,
			    (void *) &(inst->keepalive_probes)) != LDAP_OPT_SUCCESS) {
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "  [%s] Could not set LDAP_OPT_X_KEEPALIVE_PROBES %d: %s", inst->xlat_name, inst->keepalive_probes, ldap_err2string(ldap_errno));
	}
#endif

#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	if (ldap_set_option(ld, LDAP_OPT_X_KEEPALIVE_INTERVAL,
			    (void *) &(inst->keepalive_interval)) != LDAP_OPT_SUCCESS) {
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "  [%s] Could not set LDAP_OPT_X_KEEPALIVE_INTERVAL %d: %s", inst->xlat_name, inst->keepalive_interval, ldap_err2string(ldap_errno));
	}
#endif

#ifdef HAVE_LDAP_START_TLS
        if (inst->tls_mode) {
		DEBUG("  [%s] setting TLS mode to %d", inst->xlat_name, inst->tls_mode);
        	if (ldap_set_option(ld, LDAP_OPT_X_TLS,
				    (void *) &(inst->tls_mode)) != LDAP_OPT_SUCCESS) {
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
 			radlog(L_ERR, "  [%s] could not set LDAP_OPT_X_TLS option %s:", inst->xlat_name, ldap_err2string(ldap_errno));
		}
	}

	if (inst->tls_cacertfile != NULL) {
		DEBUG("  [%s] setting TLS CACert File to %s", inst->xlat_name, inst->tls_cacertfile);

		if ( ldap_set_option( NULL, LDAP_OPT_X_TLS_CACERTFILE,
				      (void *) inst->tls_cacertfile )
		     != LDAP_OPT_SUCCESS) {
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
			radlog(L_ERR, "  [%s] could not set "
			       "LDAP_OPT_X_TLS_CACERTFILE option to %s: %s",
			       inst->xlat_name, 
			       inst->tls_cacertfile,
			       ldap_err2string(ldap_errno));
		}
	}

	if (inst->tls_cacertdir != NULL) {
		DEBUG("  [%s] setting TLS CACert Directory to %s", inst->xlat_name, inst->tls_cacertdir);

		if ( ldap_set_option( NULL, LDAP_OPT_X_TLS_CACERTDIR,
				      (void *) inst->tls_cacertdir )
		     != LDAP_OPT_SUCCESS) {
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
			radlog(L_ERR, "  [%s] could not set "
			       "LDAP_OPT_X_TLS_CACERTDIR option to %s: %s",
			       inst->xlat_name, 
			       inst->tls_cacertdir,
			       ldap_err2string(ldap_errno));
		}
	}

	if (strcmp(TLS_DEFAULT_VERIFY, inst->tls_require_cert ) != 0 ) {
		DEBUG("  [%s] setting TLS Require Cert to %s", inst->xlat_name,
		      inst->tls_require_cert);
	}


#ifdef HAVE_LDAP_INT_TLS_CONFIG
	if (ldap_int_tls_config(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
				(inst->tls_require_cert)) != LDAP_OPT_SUCCESS) {
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "  [%s] could not set ", 
		       "LDAP_OPT_X_TLS_REQUIRE_CERT option to %s: %s",
		       inst->xlat_name, 
		       inst->tls_require_cert,
		       ldap_err2string(ldap_errno));
	}
#endif

	if (inst->tls_certfile != NULL) {
		DEBUG("  [%s] setting TLS Cert File to %s", inst->xlat_name, inst->tls_certfile);

		if (ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE,
				    (void *) inst->tls_certfile)
		    != LDAP_OPT_SUCCESS) {
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
			radlog(L_ERR, "  [%s] could not set "
			       "LDAP_OPT_X_TLS_CERTFILE option to %s: %s",
			       inst->xlat_name, 
			       inst->tls_certfile,
			       ldap_err2string(ldap_errno));
		}
	}

	if (inst->tls_keyfile != NULL) {
		DEBUG("  [%s] setting TLS Key File to %s", inst->xlat_name,
		      inst->tls_keyfile);

		if ( ldap_set_option( NULL, LDAP_OPT_X_TLS_KEYFILE,
				      (void *) inst->tls_keyfile )
		     != LDAP_OPT_SUCCESS) {
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
			radlog(L_ERR, "  [%s] could not set "
			       "LDAP_OPT_X_TLS_KEYFILE option to %s: %s",
			       inst->xlat_name, 
			       inst->tls_keyfile, ldap_err2string(ldap_errno));
		}
	}

	if (inst->tls_randfile != NULL) {
		DEBUG("  [%s] setting TLS Key File to %s", inst->xlat_name,
		      inst->tls_randfile);

		if (ldap_set_option(NULL, LDAP_OPT_X_TLS_RANDOM_FILE,
				    (void *) inst->tls_randfile)
		    != LDAP_OPT_SUCCESS) {
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
			radlog(L_ERR, "  [%s] could not set "
			       "LDAP_OPT_X_TLS_RANDOM_FILE option to %s: %s",
			       inst->xlat_name,
			       inst->tls_randfile, ldap_err2string(ldap_errno));
		}
	}

	if (inst->start_tls) {
		DEBUG("  [%s] starting TLS", inst->xlat_name);
		rc = ldap_start_tls_s(ld, NULL, NULL);
		if (rc != LDAP_SUCCESS) {
			DEBUG("  [%s] ldap_start_tls_s()", inst->xlat_name);
			ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER,
					&ldap_errno);
			radlog(L_ERR, "  [%s] could not start TLS %s", inst->xlat_name,
			       ldap_err2string(ldap_errno));
			*result = RLM_MODULE_FAIL;
			ldap_unbind_s(ld);
			exec_trigger(NULL, inst->cs, "modules.ldap.fail", FALSE);
			return (NULL);
		}
	}
#endif /* HAVE_LDAP_START_TLS */

	if (inst->is_url){
		DEBUG("  [%s] bind as %s/%s to %s", inst->xlat_name,
		      dn, password, inst->server);
	} else {
		DEBUG("  [%s] bind as %s/%s to %s:%d", inst->xlat_name,
		      dn, password, inst->server, inst->port);
	}

	msgid = ldap_bind(ld, dn, password,LDAP_AUTH_SIMPLE);
	if (msgid == -1) {
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		if(err != NULL){
			ldap_get_option(ld, LDAP_OPT_ERROR_STRING, err);
		}
		if (inst->is_url) {
			radlog(L_ERR, "  [%s] %s bind to %s failed: %s", inst->xlat_name,
			 	dn, inst->server, ldap_err2string(ldap_errno));
		} else {
			radlog(L_ERR, "  [%s] %s bind to %s:%d failed: %s", inst->xlat_name,
			 	dn, inst->server, inst->port,
			 	ldap_err2string(ldap_errno));
		}
		*result = RLM_MODULE_FAIL;
		ldap_unbind_s(ld);
		return (NULL);
	}
	DEBUG("  [%s] waiting for bind result ...", inst->xlat_name);

	tv.tv_sec = inst->timeout;
	tv.tv_usec = 0;
	rc = ldap_result(ld, msgid, 1, &tv, &res);

	if (rc < 1) {
		DEBUG("  [%s] ldap_result()", inst->xlat_name);
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		if(err != NULL){
			ldap_get_option(ld, LDAP_OPT_ERROR_STRING, err);
		}
		if (inst->is_url) {
			radlog(L_ERR, "  [%s] %s bind to %s failed: %s", inst->xlat_name,
				dn, inst->server, (rc == 0) ? "timeout" : ldap_err2string(ldap_errno));
		} else {
			radlog(L_ERR, "  [%s] %s bind to %s:%d failed: %s", inst->xlat_name,
			       dn, inst->server, inst->port,
				(rc == 0) ? "timeout" : ldap_err2string(ldap_errno));
		}
		*result = RLM_MODULE_FAIL;
		ldap_unbind_s(ld);
		return (NULL);
	}

	ldap_errno = ldap_result2error(ld, res, 1);
	switch (ldap_errno) {
	case LDAP_SUCCESS:
		DEBUG("  [%s] Bind was successful", inst->xlat_name);
		*result = RLM_MODULE_OK;
		break;

	case LDAP_INVALID_CREDENTIALS:
		if (auth){
			DEBUG("  [%s] Bind failed with invalid credentials", inst->xlat_name);
			*result = RLM_MODULE_REJECT;
		} else {
			radlog(L_ERR, "  [%s] LDAP login failed: check identity, password settings in ldap section of radiusd.conf", inst->xlat_name);
			*result = RLM_MODULE_FAIL;
		}
		if(err != NULL){
			ldap_get_option(ld, LDAP_OPT_ERROR_STRING, err);
		}
		break;

	case LDAP_CONSTRAINT_VIOLATION:
		DEBUG("rlm_ldap: Bind failed with constraint violation");
		*result = RLM_MODULE_REJECT;
		if(err != NULL){
			ldap_get_option(ld, LDAP_OPT_ERROR_STRING, err);
		}
		break;

	default:
		if (inst->is_url) {
			radlog(L_ERR,"  [%s] %s bind to %s failed %s", inst->xlat_name,
				dn, inst->server, ldap_err2string(ldap_errno));
		} else {
			radlog(L_ERR,"  [%s] %s bind to %s:%d failed %s", inst->xlat_name,
				dn, inst->server, inst->port,
				ldap_err2string(ldap_errno));
		}
		*result = RLM_MODULE_FAIL;
		if(err != NULL){
			ldap_get_option(ld, LDAP_OPT_ERROR_STRING, err);
		}
	}

	if (*result != RLM_MODULE_OK) {
		ldap_unbind_s(ld);
		ld = NULL;
	}
	return ld;
}

/*****************************************************************************
 *
 *	Detach from the LDAP server and cleanup internal state.
 *
 *****************************************************************************/
static int
ldap_detach(void *instance)
{
	ldap_instance  *inst = instance;
	TLDAP_RADIUS *pair, *nextpair;

	if (inst->conns) {
		int i;

		for (i = 0;i < inst->num_conns; i++) {
			if (inst->conns[i].locked) return -1;

			if (inst->conns[i].ld){
				ldap_unbind_s(inst->conns[i].ld);
			}
			pthread_mutex_destroy(&inst->conns[i].mutex);
		}
		free(inst->conns);
	}

#ifdef NOVELL
	if (inst->apc_conns){
		int i;

		for (i = 0; i < inst->num_conns; i++) {
			if (inst->apc_conns[i].locked) return -1;

			if (inst->apc_conns[i].ld){
				ldap_unbind_s(inst->apc_conns[i].ld);
			}
			pthread_mutex_destroy(&inst->apc_conns[i].mutex);
		}
		free(inst->apc_conns);
	}
#endif

	pair = inst->check_item_map;

	while (pair != NULL) {
		nextpair = pair->next;
		free(pair->attr);
		free(pair->radius_attr);
		free(pair);
		pair = nextpair;
	}

	pair = inst->reply_item_map;

	while (pair != NULL) {
		nextpair = pair->next;
		free(pair->attr);
		free(pair->radius_attr);
		free(pair);
		pair = nextpair;
	}

	if (inst->atts)
		free(inst->atts);

	paircompare_unregister(PW_LDAP_GROUP, ldap_groupcmp);
	xlat_unregister(inst->xlat_name,ldap_xlat, instance);
	free(inst->xlat_name);

	free(inst);

	return 0;
}


#ifdef FIELDCPY
static void
fieldcpy(char *string, char **uptr)
{
	char           *ptr;

	ptr = *uptr;
	while (*ptr == ' ' || *ptr == '\t') {
		ptr++;
	}
	if (*ptr == '"') {
		ptr++;
		while (*ptr != '"' && *ptr != '\0' && *ptr != '\n') {
			*string++ = *ptr++;
		}
		*string = '\0';
		if (*ptr == '"') {
			ptr++;
		}
		*uptr = ptr;
		return;
	}
	while (*ptr != ' ' && *ptr != '\t' && *ptr != '\0' && *ptr != '\n' &&
	       *ptr != '=' && *ptr != ',') {
		*string++ = *ptr++;
	}
	*string = '\0';
	*uptr = ptr;
	return;
}
#endif

/*
 *	Copied from src/lib/token.c
 */
static const FR_NAME_NUMBER tokens[] = {
	{ "=~", T_OP_REG_EQ,	}, /* order is important! */
	{ "!~", T_OP_REG_NE,	},
	{ "{",	T_LCBRACE,	},
	{ "}",	T_RCBRACE,	},
	{ "(",	T_LBRACE,	},
	{ ")",	T_RBRACE,	},
	{ ",",	T_COMMA,	},
	{ "+=",	T_OP_ADD,	},
	{ "-=",	T_OP_SUB,	},
	{ ":=",	T_OP_SET,	},
	{ "=*", T_OP_CMP_TRUE,  },
	{ "!*", T_OP_CMP_FALSE, },
	{ "==",	T_OP_CMP_EQ,	},
	{ "=",	T_OP_EQ,	},
	{ "!=",	T_OP_NE,	},
	{ ">=",	T_OP_GE,	},
	{ ">",	T_OP_GT,	},
	{ "<=",	T_OP_LE,	},
	{ "<",	T_OP_LT,	},
	{ NULL, 0}
};

/*****************************************************************************
 *	Get RADIUS attributes from LDAP object
 *	( according to draft-adoba-radius-05.txt
 *	  <http://www.ietf.org/internet-drafts/draft-adoba-radius-05.txt> )
 *
 *****************************************************************************/
static VALUE_PAIR *ldap_pairget(LDAP *ld, LDAPMessage *entry,
				TLDAP_RADIUS *item_map,
				VALUE_PAIR **pairs, int is_check,
				ldap_instance *inst)
{
	char          **vals;
	int             vals_count;
	int             vals_idx;
	const char      *ptr;
	const char     *value;
	TLDAP_RADIUS   *element;
	FR_TOKEN      token, operator;
	int             is_generic_attribute;
	char		buf[MAX_STRING_LEN];
	VALUE_PAIR     *pairlist = NULL;
	VALUE_PAIR     *newpair = NULL;
	char		do_xlat = FALSE;
	char		print_buffer[2048];

	/*
	 *	check if there is a mapping from this LDAP attribute
	 *	to a RADIUS attribute
	 */
	for (element = item_map; element != NULL; element = element->next) {
		/*
		 *	No mapping, skip it.
		 */
		if ((vals = ldap_get_values(ld,entry,element->attr)) == NULL)
			continue;

		/*
		 *	Check whether this is a one-to-one-mapped ldap
		 *	attribute or a generic attribute and set flag
		 *	accordingly.
		 */
		if (strcasecmp(element->radius_attr, GENERIC_ATTRIBUTE_ID)==0)
			is_generic_attribute = 1;
		else
			is_generic_attribute = 0;

		/*
		 *	Find out how many values there are for the
		 *	attribute and extract all of them.
		 */
		vals_count = ldap_count_values(vals);

		for (vals_idx = 0; vals_idx < vals_count; vals_idx++) {
			value = vals[vals_idx];

			if (is_generic_attribute) {
				/*
				 *	This is a generic attribute.
				 */
				FR_TOKEN dummy; /* makes pairread happy */

				/* not sure if using pairread here is ok ... */
				if ( (newpair = pairread(&value, &dummy)) != NULL) {
					DEBUG("  [%s] extracted attribute %s from generic item %s", inst->xlat_name,
					      newpair->name, vals[vals_idx]);
					pairadd(&pairlist, newpair);
				} else {
					radlog(L_ERR, "  [%s] parsing %s failed: %s", inst->xlat_name,
					       element->attr, vals[vals_idx]);
				}
			} else {
				/*
				 *	This is a one-to-one-mapped attribute
				 */
				ptr = value;
				operator = gettoken(&ptr, buf, sizeof(buf));
				if (operator < T_EQSTART || operator > T_EQEND) {
					/* no leading operator found */
					if (element->operator != T_OP_INVALID)
						operator = element->operator;
					else if (is_check)
						operator = T_OP_CMP_EQ;
					else
						operator = T_OP_EQ;
				} else {
					/* the value is after the operator */
					value = ptr;
				}

				/*
				 *	Do xlat if the *entire* string
				 *	is quoted.
				 */
				if ((value[0] == '\'' || value[0] == '"' ||
				     value[0] == '`') &&
				    (value[0] == value[strlen(value)-1])) {
					ptr = value;
					token = gettoken(&ptr, buf, sizeof(buf));
					switch (token) {
					/* take the unquoted string */
					case T_SINGLE_QUOTED_STRING:
					case T_DOUBLE_QUOTED_STRING:
						value = buf;
						break;

					/* the value will be xlat'ed later */
					case T_BACK_QUOTED_STRING:
						value = buf;
						do_xlat = TRUE;
						break;

					/* keep the original string */
					default:
						break;
					}
				}
				if (value[0] == '\0') {
					DEBUG("  [%s] Attribute %s has no value", inst->xlat_name, element->attr);
					continue;
				}

				/*
				 *	Create the pair.
				 */
				if (do_xlat) {
					newpair = pairmake_xlat(element->radius_attr,
								value,
								operator);
				} else {
					newpair = pairmake(element->radius_attr,
							   value,
							   operator);
				}
				if (newpair == NULL) {
					radlog(L_ERR, "  [%s] Failed to create the pair: %s", inst->xlat_name, fr_strerror());
					continue;
				}

				vp_prints(print_buffer, sizeof(print_buffer),
					  newpair);
				DEBUG("  [%s] %s -> %s", inst->xlat_name,
				      element->attr, print_buffer);


				/*
				 *	Add the pair into the packet.
				 */
				if (!vals_idx){
				  pairdelete(pairs, newpair->attribute, newpair->vendor);
				}
				pairadd(&pairlist, newpair);
			}
		}
		ldap_value_free(vals);
	}

	return (pairlist);
}

/* globally exported name */
module_t rlm_ldap = {
	RLM_MODULE_INIT,
	"LDAP",
	RLM_TYPE_THREAD_SAFE,	/* type: reserved 	 */
	ldap_instantiate,	/* instantiation 	 */
	ldap_detach,		/* detach 		 */
	{
		ldap_authenticate,	/* authentication 	 */
		ldap_authorize,		/* authorization 	 */
		NULL,			/* preaccounting 	 */
		NULL,			/* accounting 		 */
		NULL,			/* checksimul 		 */
		NULL,			/* pre-proxy 		 */
		NULL,			/* post-proxy 		 */
#ifdef NOVELL
		ldap_postauth		/* post-auth 		 */
#else
		NULL
#endif
	},
};
