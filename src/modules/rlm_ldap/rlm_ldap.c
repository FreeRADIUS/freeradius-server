/*
 * rlm_ldap.c LDAP authorization and authentication module.
 * 
 * 
 * This module is based on LDAP patch to Cistron radiusd by James Golovich 
 * <james@wwnet.net>, which in turn was based mostly on a Mysql+Cistron patch 
 * from <oyarzun@wilmington.net>
 * 
 * 17 Jan 2000,	Adrian Pavlykevych <pam@polynet.lviv.ua>
 *	- OpenLDAP SDK porting, basic TLS support, LDAP authorization,
 *	  fault tolerance with multiple LDAP server support 
 * 24 May 2000,	Adrian Pavlykevych <pam@polynet.lviv.ua> 
 *	- Converting to new configuration file format, futher improvements
 *	  in fault tolerance, threaded operation
 * 12 Dec 2000,	Adrian Pavlykevych <pam@polynet.lviv.ua> 
 *	- Added preliminary support for multiple instances
 * 	- moved all instance configuration into dynamicly allocated structure
 *	- Removed connection maintenance thread and all attempts for multihreading
 *	  the module itself. OpenLDAP SDK is not thread safe when used with shared
 *	  LDAP connection.
 *	- Added configuration option for defining LDAP attribute of user object,
 *	  which controls remote access.
 * 16 Feb 2001, Hannu Laurila <hannu.laurila@japo.fi>
 * 	- LDAP<->RADIUS attribute mappings are now read from a file
 *  	- Support for generic RADIUS check and reply attribute.
 * Jun 2001, Kostas Kalevras <kkalev@noc.ntua.gr>
 *	- Fix: check and reply attributes from LDAP _replace_ existing ones
 *	- Added "default_profile" directive, which points to radiusProfile 
 *	  object, which contains default values for RADIUS users
 *	- Added "profile_attribute" directive, which specifies user object 
 *	  attribute pointing to radiusProfile object.
 * Nov 2001, Kostas Kalevras <kkalev@noc.ntua.gr>
 *	- Added support for adding the user password to the check. Based on
 *	  the password_header directive rlm_ldap will strip the
 *	  password header if needed. This will make support for CHAP much easier.
 *	- Added module messages when we reject a user.
 *	- Added ldap_groupcmp to allow searching for user group membership.
 *	- Added ldap_xlat to allow ldap urls in xlat strings. Something like:
 *	  %{ldap:ldap:///dc=company,dc=com?cn?sub?uid=user}
 * Nov 2001, Gordon Tetlow <gordont@gnf.org>
 *	- Do an xlat on the access_group attribute.
 * Dec 2001, Kostas Kalevras <kkalev@noc.ntua.gr>
 *	- Added ldap caching for the default/regular profiles and group entries.
 *	- Fixed a memory leak in ldap_xlat.
 *	- Removed dict_attrbyname from ldap_pairget. They are not needed.
 *	- Moved the radius_xlat's for filter and basedn in ldap_authenticate() to
 *	  the right place.
 *	- Made the module thread safe. We create a connection pool and each thread
 *	  will call ldap_get_conn to lock one of the ldap connections and release with
 *	  a call to ldap_release_conn when it has finished.
 *	- Request only the user attributes that interest us (radius attributes,regular
 *	  profile,user password and access attribute).
 */
static const char rcsid[] = "$Id$";

#include "autoconf.h"

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>
#include	<string.h>

#include	<lber.h>
#include        <ldap.h>

#include	<errno.h>
#include	<unistd.h>
#include	<pthread.h>

#include        "libradius.h"
#include	"radiusd.h"
#include	"conffile.h"
#include	"modules.h"
#include	"rad_assert.h"


#define MAX_AUTH_QUERY_LEN      256
#define TIMELIMIT 5

/* linked list of mappings between RADIUS attributes and LDAP attributes */
struct TLDAP_RADIUS {
	char*                 attr;
	char*                 radius_attr;
	struct TLDAP_RADIUS*  next;
};
typedef struct TLDAP_RADIUS TLDAP_RADIUS;

typedef struct ldap_conn {
	LDAP		*ld;
	char		bound;
	pthread_mutex_t	mutex;
} LDAP_CONN;

#define MAX_SERVER_LINE 1024

typedef struct {
	char           *server;
	int             port;
	int             timelimit;
	struct timeval  net_timeout;
	struct timeval  timeout;
	int             debug;
	int             tls_mode;
	int		start_tls;
	int		num_conns;
	int		cache_timeout;
	int		cache_size;
	char           *login;
	char           *password;
	char           *filter;
	char           *basedn;
	char           *default_profile;
	char           *profile_attr;
	char           *access_group;
	char           *access_attr;
	char           *passwd_hdr;
	char           *passwd_attr;
	char           *dictionary_mapping;
	char	       *groupname_attr;
	char	       *groupmemb_filt;
	char		**atts;
	TLDAP_RADIUS   *check_item_map;
	TLDAP_RADIUS   *reply_item_map;
	LDAP_CONN	*conns;
	int             ldap_debug; /* Debug flag for LDAP SDK */
	char		*xlat_name; /* name used to xlat */
}               ldap_instance;

static CONF_PARSER module_config[] = {
	{"server", PW_TYPE_STRING_PTR, offsetof(ldap_instance,server), NULL, NULL},
	{"port", PW_TYPE_INTEGER, offsetof(ldap_instance,port), NULL, "389"},
	/* wait forever on network activity */
	{"net_timeout", PW_TYPE_INTEGER, offsetof(ldap_instance,net_timeout.tv_sec), NULL, "10"},
	/* wait forever for search results */
	{"timeout", PW_TYPE_INTEGER, offsetof(ldap_instance,timeout.tv_sec), NULL, "20"},
	/* allow server unlimited time for search (server-side limit) */
	{"timelimit", PW_TYPE_INTEGER, offsetof(ldap_instance,timelimit), NULL, "20"},
	{"ldap_cache_timeout", PW_TYPE_INTEGER, offsetof(ldap_instance,cache_timeout), NULL, "0"},
	{"ldap_cache_size", PW_TYPE_INTEGER, offsetof(ldap_instance,cache_size), NULL, "0"},
	{"identity", PW_TYPE_STRING_PTR, offsetof(ldap_instance,login), NULL, ""},
	{"start_tls", PW_TYPE_BOOLEAN, offsetof(ldap_instance,start_tls), NULL, "no"},
	{"password", PW_TYPE_STRING_PTR, offsetof(ldap_instance,password), NULL, ""},
	{"basedn", PW_TYPE_STRING_PTR, offsetof(ldap_instance,basedn), NULL, NULL},
	{"filter", PW_TYPE_STRING_PTR, offsetof(ldap_instance,filter), NULL, "(uid=%u)"},
	{"default_profile", PW_TYPE_STRING_PTR, offsetof(ldap_instance,default_profile), NULL, NULL},
	{"profile_attribute", PW_TYPE_STRING_PTR, offsetof(ldap_instance,profile_attr), NULL, NULL},
	{"access_group", PW_TYPE_STRING_PTR, offsetof(ldap_instance,access_group), NULL, NULL},
	{"password_header", PW_TYPE_STRING_PTR, offsetof(ldap_instance,passwd_hdr), NULL, NULL},
	{"password_attribute", PW_TYPE_STRING_PTR, offsetof(ldap_instance,passwd_attr), NULL, NULL},
	/* LDAP attribute name that controls remote access */
	{"access_attr", PW_TYPE_STRING_PTR, offsetof(ldap_instance,access_attr), NULL, NULL},
	/* file with mapping between LDAP and RADIUS attributes */
	{"groupname_attribute", PW_TYPE_STRING_PTR, offsetof(ldap_instance,groupname_attr), NULL, "cn"},
	{"groupmembership_filter", PW_TYPE_STRING_PTR, offsetof(ldap_instance,groupmemb_filt), NULL, "(|(&(objectClass=GroupOfNames)(member=%{Ldap-UserDn}))(&(objectClass=GroupOfUniqueNames)(uniquemember=%{Ldap-UserDn})))"},
	{"dictionary_mapping", PW_TYPE_STRING_PTR, offsetof(ldap_instance,dictionary_mapping), NULL, "${confdir}/ldap.attrmap"},
	{"ldap_debug", PW_TYPE_INTEGER, offsetof(ldap_instance,ldap_debug), NULL, "0x0000"},
	{"ldap_connections_number", PW_TYPE_INTEGER, offsetof(ldap_instance,num_conns), NULL, "5"},

	{NULL, -1, 0, NULL, NULL}
};

#define ld_valid                ld_options.ldo_valid
#define LDAP_VALID_SESSION      0x2
#define LDAP_VALID(ld)  ( (ld)->ld_valid == LDAP_VALID_SESSION )

#ifdef FIELDCPY
static void     fieldcpy(char *, char **);
#endif
static VALUE_PAIR *ldap_pairget(LDAP *, LDAPMessage *, TLDAP_RADIUS *,VALUE_PAIR **);
static int ldap_groupcmp(void *, REQUEST *, VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR *, VALUE_PAIR **);
static int ldap_xlat(void *,REQUEST *, char *, char *,int, RADIUS_ESCAPE_STRING);
static LDAP    *ldap_connect(void *instance, const char *, const char *, int, int *);
static int     read_mappings(ldap_instance* inst);

static inline int ldap_get_conn(LDAP_CONN *conns,LDAP_CONN **ret,void *instance)
{
	ldap_instance *inst = instance;
	register int i = 0;

	for(;i<inst->num_conns;i++){
		if (pthread_mutex_trylock(&(conns[i].mutex)) == 0){
			*ret = &conns[i];
			DEBUG("ldap_get_conn: Got Id: %d",i);
			return i;
		}
	}

	return -1;
}
	
static inline void ldap_release_conn(int i, LDAP_CONN *conns)
{
	DEBUG("ldap_release_conn: Release Id: %d",i);
	pthread_mutex_unlock(&(conns[i].mutex));
}

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
	char *xlat_name;

	inst = rad_malloc(sizeof *inst);

	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	if (inst->server == NULL) {
		radlog(L_ERR, "rlm_ldap: missing 'server' directive.");
		free(inst);
		return -1;
	}
 
	inst->timeout.tv_usec = 0;
	inst->net_timeout.tv_usec = 0;
	inst->tls_mode = LDAP_OPT_X_TLS_TRY;
	inst->reply_item_map = NULL;
	inst->check_item_map = NULL;
	inst->conns = NULL;

	paircompare_register(PW_GROUP, PW_USER_NAME, ldap_groupcmp, inst);
#ifdef PW_GROUP_NAME /* compat */
	paircompare_register(PW_GROUP_NAME, PW_USER_NAME, ldap_groupcmp, inst);
#endif
	DEBUG("conns: %p",inst->conns);

	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL) {
		xlat_name = cf_section_name1(conf);
		rad_assert(xlat_name != NULL); /* or all hell breaks loose */
	}
	inst->xlat_name = strdup(xlat_name);
	xlat_register(xlat_name,ldap_xlat,inst);

	if (inst->num_conns <= 0){
		radlog(L_ERR, "rlm_ldap: Invalid ldap connections number passed.");
		free(inst);
		return -1;
	}
	inst->conns = (LDAP_CONN *)malloc(sizeof(LDAP_CONN)*inst->num_conns);
	if (inst->conns == NULL){
		radlog(L_ERR, "rlm_ldap: Could not allocate memory. Aborting.");
		free(inst);
		return -1;
	}
	for(;i<inst->num_conns;i++){
		inst->conns[i].bound = 0;
		inst->conns[i].ld = NULL;
		pthread_mutex_init(&inst->conns[i].mutex, NULL);
	}	

	if (read_mappings(inst) != 0) {
		radlog(L_ERR, "rlm_ldap: Reading dictionary mappings from file %s failed",
		       inst->dictionary_mapping);
		radlog(L_ERR, "rlm_ldap: Proceeding with no mappings");
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
	inst->atts = (char **)malloc(sizeof(char *)*(atts_num + 1));
	if (inst->atts == NULL){
		radlog(L_ERR, "rlm_ldap: Could not allocate memory. Aborting.");
		free(inst);
		return -1;
	}
	pair = inst->check_item_map;
	for(i=0;i<atts_num;i++){
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
	inst->atts[atts_num] = NULL;		

	DEBUG("conns: %p",inst->conns);

	*instance = inst;


	return 0;
}


/*
 * read_mappings(...) reads a ldap<->radius mappings file to inst->reply_item_map and inst->check_item_map
 */

#define MAX_LINE_LEN 160
#define GENERIC_ATTRIBUTE_ID "$GENERIC$"

static int
read_mappings(ldap_instance* inst)
{
	FILE* mapfile;
	char *filename;
	/* all buffers are of MAX_LINE_LEN so we can use sscanf without being afraid of buffer overflows */
	char buf[MAX_LINE_LEN], itemType[MAX_LINE_LEN], radiusAttribute[MAX_LINE_LEN], ldapAttribute[MAX_LINE_LEN];
	int linenumber;

	/* open the mappings file for reading */

	filename = inst->dictionary_mapping;
	DEBUG("rlm_ldap: reading ldap<->radius mappings from file %s", filename);
	mapfile = fopen(filename, "r");

	if (mapfile == NULL) {
		radlog(L_ERR, "rlm_ldap: Opening file %s failed", filename);
		return -1; /* error */
	}

	/* read file line by line. Note that if line length exceed MAX_LINE_LEN, line numbers will be mixed up */

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
		token_count = sscanf(buf, "%s %s %s", itemType, radiusAttribute, ldapAttribute);

		if (token_count <= 0) /* no tokens */			
			continue;

		if (token_count != 3) {
			radlog(L_ERR, "rlm_ldap: Skipping %s line %i: %s", filename, linenumber, buf);
			radlog(L_ERR, "rlm_ldap: Expected 3 tokens "
			       "(Item type, RADIUS Attribute and LDAP Attribute) but found only %i", token_count);
			continue;
		}

		/* create new TLDAP_RADIUS list node */
		pair = rad_malloc(sizeof(TLDAP_RADIUS));

		pair->attr = strdup(ldapAttribute);
		pair->radius_attr = strdup(radiusAttribute);

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

static int 
perform_search(void *instance, LDAP_CONN *conn, char *search_basedn, int scope, char *filter, 
		char **attrs, LDAPMessage ** result)
{
	int             res = RLM_MODULE_OK;
	int		ldap_errno = 0;
	ldap_instance  *inst = instance;

	*result = NULL;

	if (!conn){
		radlog(L_ERR, "rlm_ldap: NULL connection handle passed");
		return RLM_MODULE_FAIL;
	}
	if (!conn->bound) {
		DEBUG2("rlm_ldap: attempting LDAP reconnection");
		if (conn->ld){
			DEBUG2("rlm_ldap: closing existing LDAP connection");
			if (inst->cache_timeout >0)
				ldap_destroy_cache(conn->ld);
			ldap_unbind_s(conn->ld);
		}
		if ((conn->ld = ldap_connect(instance, inst->login, inst->password, 0, &res)) == NULL) {
			radlog(L_ERR, "rlm_ldap: (re)connection attempt failed");
			return (RLM_MODULE_FAIL);
		}
		conn->bound = 1;
	}
	DEBUG2("rlm_ldap: performing search in %s, with filter %s", search_basedn ? search_basedn : "(null)" , filter);
	switch (ldap_search_st(conn->ld, search_basedn, scope, filter, attrs, 0, &(inst->timeout), result)) {
	case LDAP_SUCCESS:
		break;

	default:
		ldap_get_option(conn->ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "rlm_ldap: ldap_search() failed: %s", ldap_err2string(ldap_errno));
		conn->bound = 0;
		ldap_msgfree(*result);	
		return (RLM_MODULE_FAIL);
	}

	if ((ldap_count_entries(conn->ld, *result)) != 1) {
		DEBUG("rlm_ldap: object not found or got ambiguous search result");
		res = RLM_MODULE_NOTFOUND;
		ldap_msgfree(*result);	
	}
	return res;
}


/*
 * ldap_groupcmp(). Implement the Group == "group" filter
 */

static int ldap_groupcmp(void *instance, REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check,
                VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
        char            filter[MAX_AUTH_QUERY_LEN];
        char            *group_dn;
        int             res;
        LDAPMessage     *result = NULL;
        LDAPMessage     *msg = NULL;
        char            basedn[1024];
	char		*attrs[] = {"dn",NULL};
        ldap_instance   *inst = instance;
	LDAP_CONN	*conn;
	int		conn_id = -1;

        check_pairs = check_pairs;
        reply_pairs = reply_pairs;

	DEBUG("rlm_ldap: Entering ldap_groupcmp()");

        if (check->strvalue == NULL || check->length == 0){
                DEBUG("rlm_ldap::ldap_groupcmp: Illegal group name");
                return 1;
        }

        if (req == NULL){
                DEBUG("rlm_ldap::ldap_groupcmp: NULL request");
                return 1;
        }

        if (!radius_xlat(basedn, sizeof(basedn), inst->basedn, req, NULL)) {
                DEBUG("rlm_ldap::ldap_groupcmp: unable to create basedn.");
                return 1;
        }

        if ((pairfind(req->packet->vps, LDAP_USERDN)) == NULL){
                char            *user_dn = NULL;

                if (!radius_xlat(filter, MAX_AUTH_QUERY_LEN, inst->filter, req, NULL)) {
                        DEBUG("rlm_ldap::ldap_groupcmp: unable to create filter");
                        return 1;
                }
		if ((conn_id = ldap_get_conn(inst->conns,&conn,inst)) == -1){
			radlog(L_ERR, "rlm_ldap: All ldap connections are in use");
			return 1;
		}
                if ((res = perform_search(inst, conn, basedn, LDAP_SCOPE_SUBTREE, filter, attrs, &result)) != RLM_MODULE_OK) {
                        DEBUG("rlm_ldap::ldap_groupcmp: search failed");
			ldap_release_conn(conn_id,inst->conns);
                        return 1;
                }
                if ((msg = ldap_first_entry(conn->ld, result)) == NULL) {
                        DEBUG("rlm_ldap::ldap_groupcmp: ldap_first_entry() failed");
			ldap_release_conn(conn_id,inst->conns);
                        ldap_msgfree(result);
                        return 1;
                }
                if ((user_dn = ldap_get_dn(conn->ld, msg)) == NULL) {
                        DEBUG("rlm_ldap:ldap_groupcmp:: ldap_get_dn() failed");
			ldap_release_conn(conn_id,inst->conns);
                        ldap_msgfree(result);
                        return 1;
                }
                /*
                * Adding new attribute containing DN for LDAP object associated with
                * given username
                */
                pairadd(&req->packet->vps, pairmake("Ldap-UserDn", user_dn, T_OP_EQ));
                ldap_memfree(user_dn);
                ldap_msgfree(result);
        }

        snprintf(filter,MAX_AUTH_QUERY_LEN - 1, "(%s=%s)",inst->groupname_attr,(char *)check->strvalue);

	if (conn_id == -1 && (conn_id = ldap_get_conn(inst->conns,&conn,inst)) == -1){
		radlog(L_ERR, "rlm_ldap: All ldap connections are in use");
		return 1;
	}

	if (inst->cache_timeout >0)
		ldap_enable_cache(conn->ld, inst->cache_timeout, inst->cache_size);

        if ((res = perform_search(inst, conn, basedn, LDAP_SCOPE_SUBTREE, filter, attrs, &result)) != RLM_MODULE_OK){
		if (inst->cache_timeout >0)
			ldap_disable_cache(conn->ld);
                if (res == RLM_MODULE_NOTFOUND){
                        DEBUG("rlm_ldap::ldap_groupcmp: Group %s not found", (char *)check->strvalue);
			ldap_release_conn(conn_id,inst->conns);
                        return 1;
                }
                DEBUG("rlm_ldap::ldap_groupcmp: Search returned error");
		ldap_release_conn(conn_id,inst->conns);
                return 1;
        }
        if ((msg = ldap_first_entry(conn->ld, result)) == NULL){
                DEBUG("rlm_ldap::ldap_groupcmp: ldap_first_entry() failed");
		if (inst->cache_timeout >0)
			ldap_disable_cache(conn->ld);
		ldap_release_conn(conn_id,inst->conns);
                ldap_msgfree(result);
                return 1;
        }
        if ((group_dn = ldap_get_dn(conn->ld, msg)) == NULL){
                DEBUG("rlm_ldap:ldap_groupcmp:: ldap_get_dn() failed");
		if (inst->cache_timeout >0)
			ldap_disable_cache(conn->ld);
		ldap_release_conn(conn_id,inst->conns);
                ldap_msgfree(result);
                return 1;
        }
	ldap_msgfree(result);


        if(!radius_xlat(filter, MAX_AUTH_QUERY_LEN, inst->groupmemb_filt, req, NULL)){
                DEBUG("rlm_ldap::ldap_groupcmp: unable to create filter.");
		if (inst->cache_timeout >0)
			ldap_disable_cache(conn->ld);
		ldap_release_conn(conn_id,inst->conns);
		ldap_memfree(group_dn);
                return 1;
        }

        if ((res = perform_search(inst, conn, group_dn, LDAP_SCOPE_BASE, filter, attrs, &result)) != RLM_MODULE_OK){
		if (inst->cache_timeout >0)
			ldap_disable_cache(conn->ld);
		ldap_release_conn(conn_id,inst->conns);
                if (res == RLM_MODULE_NOTFOUND){
			DEBUG("rlm_ldap::ldap_groupcmp: User not found in group %s",group_dn);
			ldap_memfree(group_dn);
			return -1;
                }
                DEBUG("rlm_ldap::ldap_groupcmp: Search returned error");
		ldap_memfree(group_dn);
                return 1;
        }
        else{
                DEBUG("rlm_ldap::ldap_groupcmp: User found in group %s",group_dn);
		if (inst->cache_timeout >0)
			ldap_disable_cache(conn->ld);
		ldap_memfree(group_dn);
                ldap_msgfree(result);
        }
	ldap_release_conn(conn_id,inst->conns);

        return 0;

}

/*
 * ldap_xlat()
 * Do an xlat on an LDAP URL
 */

static int ldap_xlat(void *instance, REQUEST *request, char *fmt, char *out, int freespace,
				RADIUS_ESCAPE_STRING func)
{
	char url[MAX_STRING_LEN];
	int res;
	int ret = 0;
	ldap_instance *inst = instance;
	LDAPURLDesc *ldap_url;
	LDAPMessage *result = NULL;
	LDAPMessage *msg = NULL;
	char **vals;
	int conn_id = -1;
	LDAP_CONN *conn;

	DEBUG("rlm_ldap: - ldap_xlat");
	if (!radius_xlat(url, sizeof(url), fmt, request, func)) {
		radlog (L_ERR, "rlm_ldap: Unable to create LDAP URL.\n");
		return 0;
	}
	if (!ldap_is_ldap_url(url)){
		radlog (L_ERR, "rlm_ldap: String passed does not look like an LDAP URL.\n");
		return 0;
	}
	if (ldap_url_parse(url,&ldap_url)){
		radlog (L_ERR, "rlm_ldap: LDAP URL parse failed.\n");
		return 0;
	}
	if (ldap_url->lud_attrs == NULL || ldap_url->lud_attrs[0] == NULL || \
		( ldap_url->lud_attrs[1] != NULL || ( ! strlen(ldap_url->lud_attrs[0]) || \
		! strcmp(ldap_url->lud_attrs[0],"*") ) ) ){
		radlog (L_ERR, "rlm_ldap: Invalid Attribute(s) request.\n");
		ldap_free_urldesc(ldap_url);
		return 0;
	}
	if (ldap_url->lud_host){
		if (strncmp(inst->server,ldap_url->lud_host,strlen(inst->server)) != 0 || \
				ldap_url->lud_port != inst->port){
			DEBUG("rlm_ldap: Requested server/port is not known to this module instance.");
			ldap_free_urldesc(ldap_url);
			return 0;
		}
	}
	if ((conn_id = ldap_get_conn(inst->conns,&conn,inst)) == -1){
		radlog(L_ERR, "rlm_ldap: All ldap connections are in use");
		return 1;
	}
	if ((res = perform_search(inst, conn, ldap_url->lud_dn, ldap_url->lud_scope, ldap_url->lud_filter, ldap_url->lud_attrs, &result)) != RLM_MODULE_OK){
		if (res == RLM_MODULE_NOTFOUND){
			DEBUG("rlm_ldap: Search returned not found");
			ldap_free_urldesc(ldap_url);
			ldap_release_conn(conn_id,inst->conns);
			return 0;
		}
		DEBUG("rlm_ldap: Search returned error");
		ldap_free_urldesc(ldap_url);
		ldap_release_conn(conn_id,inst->conns);
		return 0;
	}
	if ((msg = ldap_first_entry(conn->ld, result)) == NULL){
		DEBUG("rlm_ldap: ldap_first_entry() failed");
		ldap_msgfree(result);
		ldap_free_urldesc(ldap_url);
		ldap_release_conn(conn_id,inst->conns);
		return 0;
	}
	if ((vals = ldap_get_values(conn->ld, msg, ldap_url->lud_attrs[0])) != NULL) {
		ret = strlen(vals[0]);
		if (ret > freespace){
			DEBUG("rlm_ldap: Insufficient string space");
			ldap_free_urldesc(ldap_url);
			ldap_value_free(vals);
			ldap_msgfree(result);
			ldap_release_conn(conn_id,inst->conns);
			return 0;
		}
		DEBUG("rlm_ldap: Adding attribute %s, value: %s",ldap_url->lud_attrs[0],vals[0]);
		strncpy(out,vals[0],ret);
		ldap_value_free(vals);
	}
	else
		ret = 0;

	ldap_msgfree(result);
	ldap_free_urldesc(ldap_url);
	ldap_release_conn(conn_id,inst->conns);

	DEBUG("rlm_ldap: - ldap_xlat end");

	return ret;
}


/******************************************************************************
 *
 *      Function: rlm_ldap_authorize
 *
 *      Purpose: Check if user is authorized for remote access
 *
 ******************************************************************************/
static int 
ldap_authorize(void *instance, REQUEST * request)
{
	LDAPMessage	*result = NULL;
	LDAPMessage	*msg = NULL;
	LDAPMessage	*def_msg = NULL;
	LDAPMessage	*def_attr_msg = NULL;
	LDAPMessage	*gr_result = NULL;
	LDAPMessage	*def_result = NULL;
	LDAPMessage	*def_attr_result = NULL;
	ldap_instance	*inst = instance;
	char		*user_dn = NULL;
	char		filter[MAX_AUTH_QUERY_LEN];
	char		basedn[1024];
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	int		res;
	VALUE_PAIR	**check_pairs, **reply_pairs;
	char		**vals;
	VALUE_PAIR      *module_msg_vp;
	VALUE_PAIR	*user_profile;
	char            module_msg[MAX_STRING_LEN];
	LDAP_CONN	*conn;
	int		conn_id = -1;

	DEBUG("rlm_ldap: - authorize");

	if (!request->username){
		radlog(L_AUTH, "rlm_ldap: Attribute \"User-Name\" is required for authentication.\n");
		return RLM_MODULE_INVALID;
	}

	check_pairs = &request->config_items;
	reply_pairs = &request->reply->vps;

	/*
	 * Check for valid input, zero length names not permitted
	 */
	if (request->username->strvalue == 0) {
		radlog(L_ERR, "rlm_ldap: zero length username not permitted\n");
		return RLM_MODULE_INVALID;
	}
	DEBUG("rlm_ldap: performing user authorization for %s",
	       request->username->strvalue);

	if (!radius_xlat(filter, sizeof(filter), inst->filter,
			 request, NULL)) {
		radlog (L_ERR, "rlm_ldap: unable to create filter.\n");
		return RLM_MODULE_INVALID;
	}

	if (!radius_xlat(basedn, sizeof(basedn), inst->basedn,
			 request, NULL)) {
		radlog (L_ERR, "rlm_ldap: unable to create basedn.\n");
		return RLM_MODULE_INVALID;
	}

	if ((conn_id = ldap_get_conn(inst->conns,&conn,inst)) == -1){
		radlog(L_ERR, "rlm_ldap: All ldap connections are in use");
		return RLM_MODULE_FAIL;
	}
	if ((res = perform_search(instance, conn, basedn, LDAP_SCOPE_SUBTREE, filter, inst->atts, &result)) != RLM_MODULE_OK) {
		DEBUG("rlm_ldap: search failed");
		if (res == RLM_MODULE_NOTFOUND){
			snprintf(module_msg,MAX_STRING_LEN-1,"rlm_ldap: User not found");
			module_msg_vp = pairmake("Module-Message", module_msg, T_OP_EQ);
			pairadd(&request->packet->vps, module_msg_vp);
		}
		ldap_release_conn(conn_id,inst->conns);
		return (res);
	}
	if ((msg = ldap_first_entry(conn->ld, result)) == NULL) {
		DEBUG("rlm_ldap: ldap_first_entry() failed");
		ldap_msgfree(result);
		ldap_release_conn(conn_id,inst->conns);
		return RLM_MODULE_FAIL;
	}
	if ((user_dn = ldap_get_dn(conn->ld, msg)) == NULL) {
		DEBUG("rlm_ldap: ldap_get_dn() failed");
		ldap_msgfree(result);
		ldap_release_conn(conn_id,inst->conns);
		return RLM_MODULE_FAIL;
	}
	/*
	 * Adding new attribute containing DN for LDAP object associated with
	 * given username
	 */
	pairadd(&request->packet->vps, pairmake("Ldap-UserDn", user_dn, T_OP_EQ));
	ldap_memfree(user_dn);


	/* Remote access is controled by attribute of the user object */
	if (inst->access_attr) {
		if ((vals = ldap_get_values(conn->ld, msg, inst->access_attr)) != NULL) {
			DEBUG("rlm_ldap: checking if remote access for %s is allowed by %s", request->username->strvalue, inst->access_attr);
			if (!strncmp(vals[0], "FALSE", 5)) {
				DEBUG("rlm_ldap: dialup access disabled");
				snprintf(module_msg,MAX_STRING_LEN-1,"rlm_ldap: Access Attribute denies access");
				module_msg_vp = pairmake("Module-Message", module_msg, T_OP_EQ);
				pairadd(&request->packet->vps, module_msg_vp);
				ldap_msgfree(result);
				ldap_value_free(vals);
				ldap_release_conn(conn_id,inst->conns);
				return RLM_MODULE_USERLOCK;
			}
			ldap_value_free(vals);
		} else {
			DEBUG("rlm_ldap: no %s attribute - access denied by default", inst->access_attr);
			snprintf(module_msg,MAX_STRING_LEN-1,"rlm_ldap: Access Attribute denies access");
			module_msg_vp = pairmake("Module-Message", module_msg, T_OP_EQ);
			pairadd(&request->packet->vps, module_msg_vp);
			ldap_msgfree(result);
			ldap_release_conn(conn_id,inst->conns);
			return RLM_MODULE_USERLOCK;
		}
	}
	if (inst->cache_timeout >0)
		ldap_enable_cache(conn->ld, inst->cache_timeout, inst->cache_size);

	/* Remote access controled by group membership of the user object */
	if (inst->access_group != NULL) {
		static char	group[MAX_AUTH_QUERY_LEN];
		static char	*attrs[] = {"dn", NULL};

		DEBUG("rlm_ldap: checking user membership in dialup-enabling group %s", inst->access_group);
		/*
		 * uniquemember appears in Netscape Directory Server's groups
		 * since we have objectclass groupOfNames and
		 * groupOfUniqueNames
		 */
		if(!radius_xlat(group, MAX_AUTH_QUERY_LEN, inst->access_group,
				request, NULL)) 
			radlog (L_ERR, "rlm_ldap: unable to munge group.\n"); 

		if(!radius_xlat(filter, MAX_AUTH_QUERY_LEN, inst->groupmemb_filt,
			        request, NULL)) 
			radlog (L_ERR, "rlm_ldap: unable to create filter.\n"); 

		if ((res = perform_search(instance, conn, group, LDAP_SCOPE_BASE, filter, attrs, &gr_result)) != RLM_MODULE_OK) {
			if (inst->cache_timeout >0)
				ldap_disable_cache(conn->ld);
			ldap_msgfree(result);
			ldap_release_conn(conn_id,inst->conns);
			if (res == RLM_MODULE_NOTFOUND){
				snprintf(module_msg,MAX_STRING_LEN-1,"rlm_ldap: User is not an access group member");
				module_msg_vp = pairmake("Module-Message", module_msg, T_OP_EQ);
				pairadd(&request->packet->vps, module_msg_vp);
				return (RLM_MODULE_USERLOCK);
			}
			else
				return (res);
		} else 
			ldap_msgfree(gr_result);
	}

	/*
	 * Check for the default profile entry. If it exists then add the 
	 * attributes it contains in the check and reply pairs
	 */

	user_profile = pairfind(request->config_items, PW_USER_PROFILE);
	if (inst->default_profile || user_profile){
		char *profile = inst->default_profile;

		strncpy(filter,"(objectclass=radiusprofile)",MAX_AUTH_QUERY_LEN);
		if (user_profile)
			profile = user_profile->strvalue;
		if (profile && strlen(profile)){
			if ((res = perform_search(instance, conn,
				profile, LDAP_SCOPE_BASE, 
				filter, inst->atts, &def_result)) == RLM_MODULE_OK){
				if ((def_msg = ldap_first_entry(conn->ld,def_result))){
					if ((check_tmp = ldap_pairget(conn->ld,def_msg,inst->check_item_map,check_pairs)))
						pairadd(check_pairs,check_tmp);
					if ((reply_tmp = ldap_pairget(conn->ld,def_msg,inst->reply_item_map,reply_pairs)))
						pairadd(reply_pairs,reply_tmp);
				}
				ldap_msgfree(def_result);
			} else 
				DEBUG("rlm_ldap: default_profile/user-profile search failed");
		}
	}

	/*
	 * Check for the profile attribute. If it exists, we assume that it 
	 * contains the DN of an entry containg a profile for the user. That
	 * way we can have different general profiles for various user groups
	 * (students,faculty,staff etc)
	 */

	if (inst->profile_attr){
		if ((vals = ldap_get_values(conn->ld, msg, inst->profile_attr)) != NULL && strlen(vals[0])) {
			strncpy(filter,"(objectclass=radiusprofile)",MAX_AUTH_QUERY_LEN);
			if ((res = perform_search(instance, conn,
				vals[0], LDAP_SCOPE_BASE, 
				filter, inst->atts, &def_attr_result)) == RLM_MODULE_OK){
				if ((def_attr_msg = ldap_first_entry(conn->ld,def_attr_result))){
					if ((check_tmp = ldap_pairget(conn->ld,def_attr_msg,inst->check_item_map,check_pairs)))
						pairadd(check_pairs,check_tmp);
					if ((reply_tmp = ldap_pairget(conn->ld,def_attr_msg,inst->reply_item_map,reply_pairs)))
						pairadd(reply_pairs,reply_tmp);
				}
				ldap_msgfree(def_attr_result);
			} else 
				DEBUG("rlm_ldap: profile_attribute search failed");
			ldap_value_free(vals);
		}
	}
	if (inst->cache_timeout >0)
		ldap_disable_cache(conn->ld);
	if (inst->passwd_attr && strlen(inst->passwd_attr)){
		VALUE_PAIR *passwd_item;

		if ((passwd_item = pairfind(request->config_items, PW_PASSWORD)) == NULL){
			char **passwd_vals;
			char *passwd_val = NULL;
			int passwd_len;

			if ((passwd_vals = ldap_get_values(conn->ld,msg,inst->passwd_attr)) != NULL){
				unsigned int i=0;
				while(passwd_vals[i] != NULL){
					if (strlen(passwd_vals[i])){
						passwd_val = passwd_vals[i];

						if (inst->passwd_hdr && strlen(inst->passwd_hdr)){
							passwd_val = strstr(passwd_val,inst->passwd_hdr);
							if (passwd_val != NULL)
								passwd_val += strlen(inst->passwd_hdr);
							else
								DEBUG("rlm_ldap: Password header not found in password %s for user %s", passwd_vals[0],request->username->strvalue);
						}
						if (passwd_val){
							if ((passwd_item = paircreate(PW_PASSWORD,PW_TYPE_STRING)) == NULL){
								radlog(L_ERR|L_CONS, "no memory");
								ldap_value_free(passwd_vals);
								ldap_msgfree(result);
								ldap_release_conn(conn_id,inst->conns);
								return RLM_MODULE_FAIL;
							}
							passwd_len = strlen(passwd_val);
							strncpy(passwd_item->strvalue,passwd_val,MAX_STRING_LEN - 1);
							passwd_item->length = (passwd_len > (MAX_STRING_LEN - 1)) ? (MAX_STRING_LEN - 1) : passwd_len;
							pairadd(&request->config_items,passwd_item);
							DEBUG("rlm_ldap: Added password %s in check items",passwd_item->strvalue);
						}
					}
					i++;
				}
				ldap_value_free(passwd_vals);
			}
		}
	}



	DEBUG("rlm_ldap: looking for check items in directory...");

	if ((check_tmp = ldap_pairget(conn->ld, msg, inst->check_item_map,check_pairs)) != NULL)
		pairadd(check_pairs, check_tmp);


	/*
 	 * Module should default to LDAP authentication if no Auth-Type
	 * specified
	 */
	if (pairfind(*check_pairs, PW_AUTHTYPE) == NULL)
		pairadd(check_pairs, pairmake("Auth-Type", "LDAP", T_OP_EQ));


	DEBUG("rlm_ldap: looking for reply items in directory...");


	if ((reply_tmp = ldap_pairget(conn->ld, msg, inst->reply_item_map,reply_pairs)) != NULL)
		pairadd(reply_pairs, reply_tmp);


	DEBUG("rlm_ldap: user %s authorized to use remote access",
	      request->username->strvalue);
	ldap_msgfree(result);
	ldap_release_conn(conn_id,inst->conns);

	return RLM_MODULE_OK;
}

/*****************************************************************************
 *
 *	Function: rlm_ldap_authenticate
 *
 *	Purpose: Check the user's password against ldap database
 *
 *****************************************************************************/
static int 
ldap_authenticate(void *instance, REQUEST * request)
{
	LDAP           *ld_user;
	LDAPMessage    *result, *msg;
	ldap_instance  *inst = instance;
	char           *user_dn, *attrs[] = {"uid", NULL};
        char		filter[MAX_AUTH_QUERY_LEN];
	char		basedn[1024];
	int             res;
	VALUE_PAIR     *vp_user_dn;
	VALUE_PAIR      *module_msg_vp;
	char            module_msg[MAX_STRING_LEN];
	LDAP_CONN	*conn;
	int		conn_id = -1;

	DEBUG("rlm_ldap: - authenticate");
	/*
	 * Ensure that we're being passed a plain-text password, and not
	 * anything else.
	 */

	if (!request->username) {
		radlog(L_AUTH, "rlm_ldap: Attribute \"User-Name\" is required for authentication.\n");
		return RLM_MODULE_INVALID;
	}

	if (!request->password){
		radlog(L_AUTH, "rlm_ldap: Attribute \"User-Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	if(request->password->attribute != PW_PASSWORD) {
		radlog(L_AUTH, "rlm_ldap: Attribute \"User-Password\" is required for authentication. Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}

	if (request->password->length == 0) {
		radlog(L_ERR, "rlm_ldap: empty password supplied");
		return RLM_MODULE_INVALID;
	}

	DEBUG("rlm_ldap: login attempt by \"%s\" with password \"%s\"", 
	       request->username->strvalue, request->password->strvalue);

	while((vp_user_dn = pairfind(request->packet->vps, LDAP_USERDN)) == NULL) {
		if (!radius_xlat(filter, sizeof(filter), inst->filter,
				request, NULL)) {
			radlog (L_ERR, "rlm_ldap: unable to create filter.\n"); 
			return RLM_MODULE_INVALID;
		}

		if (!radius_xlat(basedn, sizeof(basedn), inst->basedn,
		 		request, NULL)) {
			radlog (L_ERR, "rlm_ldap: unable to create basedn.\n");
			return RLM_MODULE_INVALID;
		}

		if ((conn_id = ldap_get_conn(inst->conns,&conn,inst)) == -1){
			radlog(L_ERR, "rlm_ldap: All ldap connections are in use");
			return RLM_MODULE_FAIL;
		}
		if ((res = perform_search(instance, conn, basedn, LDAP_SCOPE_SUBTREE, filter, attrs, &result)) != RLM_MODULE_OK) {
			if (res == RLM_MODULE_NOTFOUND){
				snprintf(module_msg,MAX_STRING_LEN-1,"rlm_ldap: User not found");
				module_msg_vp = pairmake("Module-Message", module_msg, T_OP_EQ);
				pairadd(&request->packet->vps, module_msg_vp);
			}
			ldap_release_conn(conn_id,inst->conns);
			return (res);
		}
		if ((msg = ldap_first_entry(conn->ld, result)) == NULL) {
			ldap_msgfree(result);
			ldap_release_conn(conn_id,inst->conns);
			return RLM_MODULE_FAIL;
		}
		if ((user_dn = ldap_get_dn(conn->ld, msg)) == NULL) {
			DEBUG("rlm_ldap: ldap_get_dn() failed");
			ldap_msgfree(result);
			ldap_release_conn(conn_id,inst->conns);
			return RLM_MODULE_FAIL;
		}
		ldap_release_conn(conn_id,inst->conns);
		pairadd(&request->packet->vps, pairmake("Ldap-UserDn", user_dn, T_OP_EQ));
		ldap_memfree(user_dn);
		ldap_msgfree(result);
	}

	user_dn = vp_user_dn->strvalue;

	DEBUG("rlm_ldap: user DN: %s", user_dn);

	ld_user = ldap_connect(instance, user_dn, request->password->strvalue,
			       1, &res);
	if (ld_user == NULL){
		snprintf(module_msg,MAX_STRING_LEN-1,"rlm_ldap: Bind as user failed");
		module_msg_vp = pairmake("Module-Message", module_msg, T_OP_EQ);
		pairadd(&request->packet->vps, module_msg_vp);
		return (res);
	}

	DEBUG("rlm_ldap: user %s authenticated succesfully",
	      request->username->strvalue);
	ldap_unbind_s(ld_user);

	return RLM_MODULE_OK;
}

static LDAP    *
ldap_connect(void *instance, const char *dn, const char *password, int auth, int *result)
{
	ldap_instance  *inst = instance;
	LDAP           *ld;
	int             msgid, rc, ldap_version;
	int		ldap_errno = 0;
	LDAPMessage    *res;

	DEBUG("rlm_ldap: (re)connect to %s:%d, authentication %d", inst->server, inst->port, auth);
	if ((ld = ldap_init(inst->server, inst->port)) == NULL) {
		radlog(L_ERR, "rlm_ldap: ldap_init() failed");
		*result = RLM_MODULE_FAIL;
		return (NULL);
	}
	if (ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, (void *) &(inst->net_timeout)) != LDAP_OPT_SUCCESS) {
		radlog(L_ERR, "rlm_ldap: Could not set LDAP_OPT_NETWORK_TIMEOUT %ld.%ld", inst->net_timeout.tv_sec, inst->net_timeout.tv_usec);
	}
	if (ldap_set_option(ld, LDAP_OPT_TIMELIMIT, (void *) &(inst->timelimit)) != LDAP_OPT_SUCCESS) {
		radlog(L_ERR, "rlm_ldap: Could not set LDAP_OPT_TIMELIMIT %d", inst->timelimit);
	}
	if (inst->ldap_debug && ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &(inst->ldap_debug)) != LDAP_OPT_SUCCESS) {
		radlog(L_ERR, "rlm_ldap: Could not set LDAP_OPT_DEBUG_LEVEL %d", inst->ldap_debug);
	}
#ifdef HAVE_TLS
	if (inst->tls_mode && ldap_set_option(ld, LDAP_OPT_X_TLS, (void *) &(inst->tls_mode)) != LDAP_OPT_SUCCESS) {
		radlog(L_ERR, "rlm_ldap: Could not set LDAP_OPT_X_TLS_TRY");
	}
#endif

#ifdef HAVE_LDAP_START_TLS
	if (inst->start_tls) {
		DEBUG("rlm_ldap: try to start TLS");
		ldap_version = LDAP_VERSION3;
		if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) == LDAP_SUCCESS) {
			rc = ldap_start_tls_s(ld, NULL, NULL);
			if (rc != LDAP_SUCCESS) {
				DEBUG("rlm_ldap: ldap_start_tls_s()");
				ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
				radlog(L_ERR, "rlm_ldap: could not start TLS %s", ldap_err2string(ldap_errno));
				*result = RLM_MODULE_FAIL;
				ldap_unbind_s(ld);
				return (NULL);
			}
		}
	}
#endif /* HAVE_LDAP_START_TLS */

	DEBUG("rlm_ldap: bind as %s/%s", dn, password);
	msgid = ldap_simple_bind(ld, dn, password);
	if (msgid == -1) {
		DEBUG("rlm_ldap: ldap_simple_bind()");
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "rlm_ldap: %s bind failed: %s", dn, ldap_err2string(ldap_errno));
		*result = RLM_MODULE_FAIL;
		ldap_unbind_s(ld);
		return (NULL);
	}
	DEBUG("rlm_ldap: waiting for bind result ...");

	rc = ldap_result(ld, msgid, 1, &(inst->timeout), &res);

	if(rc < 1) {
		DEBUG("rlm_ldap: ldap_result()");
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "rlm_ldap: %s bind failed: %s", dn, (rc == 0) ? "timeout" : ldap_err2string(ldap_errno));
		*result = RLM_MODULE_FAIL;
		ldap_unbind_s(ld);
		return (NULL);
	}
	ldap_errno = ldap_result2error(ld, res, 1);
	switch (ldap_errno) {
	case LDAP_SUCCESS:
		*result = RLM_MODULE_OK;
		break;

	case LDAP_INVALID_CREDENTIALS:
		if (auth) 
			*result = RLM_MODULE_REJECT;
		else {
			radlog(L_ERR, "rlm_ldap: LDAP login failed: check login, password settings in ldap section of radiusd.conf");
			*result = RLM_MODULE_FAIL;
		}		
		break;
		
	default:
		radlog(L_ERR,"rlm_ldap: %s bind failed %s", dn, ldap_err2string(ldap_errno));
		*result = RLM_MODULE_FAIL;
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

	if (inst->server)
		free((char *) inst->server);
	if (inst->login)
		free((char *) inst->login);
	if (inst->password)
		free((char *) inst->password);
	if (inst->basedn)
		free((char *) inst->basedn);
	if (inst->access_group)
		free((char *) inst->access_group);
	if (inst->dictionary_mapping)
		free(inst->dictionary_mapping);
	if (inst->filter)
		free((char *) inst->filter);
	if (inst->passwd_hdr)
		free((char *) inst->passwd_hdr);
	if (inst->passwd_attr)
		free((char *) inst->passwd_attr);
	if (inst->groupname_attr)
		free((char *) inst->groupname_attr);
	if (inst->groupmemb_filt)
		free((char *) inst->groupmemb_filt);
	if (inst->conns){
		int i=0;

		for(;i<inst->num_conns;i++){
			if (inst->conns[i].ld){
				if (inst->cache_timeout >0)
					ldap_destroy_cache(inst->conns[i].ld);
				ldap_unbind_s(inst->conns[i].ld);
			}
			pthread_mutex_destroy(&inst->conns[i].mutex);
		}
		free(inst->conns);
	}

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

	paircompare_unregister(PW_GROUP, ldap_groupcmp);
#ifdef PW_GROUP_NAME
	paircompare_unregister(PW_GROUP_NAME, ldap_groupcmp);
#endif
	xlat_unregister(inst->xlat_name,ldap_xlat);
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
/*****************************************************************************
 *	Get RADIUS attributes from LDAP object
 *	( according to draft-adoba-radius-05.txt
 *	  <http://www.ietf.org/internet-drafts/draft-adoba-radius-05.txt> )
 *
 *****************************************************************************/

static VALUE_PAIR *
ldap_pairget(LDAP * ld, LDAPMessage * entry,
	     TLDAP_RADIUS * item_map, VALUE_PAIR **pairs)
{
	char          **vals;
	int             vals_count;
	int             vals_idx;
	char           *ptr;
	TLDAP_RADIUS   *element;
	LRAD_TOKEN      token;
	int             is_generic_attribute;
	char            value[64];
	VALUE_PAIR     *pairlist = NULL;
	VALUE_PAIR     *newpair = NULL;

	/* check if there is a mapping from this LDAP attribute to a RADIUS attribute */
	for (element = item_map; element != NULL; element = element->next) {
	if ((vals = ldap_get_values(ld,entry,element->attr)) != NULL){
			/* check whether this is a one-to-one-mapped ldap attribute or a generic
			   attribute and set flag accordingly */

			if (strcasecmp(element->radius_attr, GENERIC_ATTRIBUTE_ID)==0)
				is_generic_attribute = 1;
			else
				is_generic_attribute = 0;

			/* find out how many values there are for the attribute and extract all of them */

			vals_count = ldap_count_values(vals);

			for (vals_idx = 0; vals_idx < vals_count; vals_idx++) {
				ptr = vals[vals_idx];

				if (is_generic_attribute) {
					/* this is a generic attribute */
					int dummy; /* makes pairread happy */
					
					/* not sure if using pairread here is ok ... */
					if ( (newpair = pairread(&ptr, &dummy)) != NULL) {
						DEBUG("rlm_ldap: extracted attribute %s from generic item %s", 
						      newpair->name, vals[vals_idx]);
						if (! vals_idx){
							pairdelete(pairs,newpair->attribute);
						}
						pairadd(&pairlist, newpair);
					} else {
						radlog(L_ERR, "rlm_ldap: parsing %s failed: %s", 
						       element->attr, vals[vals_idx]);
					}
				} else {
					/* this is a one-to-one-mapped attribute */
					token = gettoken(&ptr, value, sizeof(value));
					if (token < T_EQSTART || token > T_EQEND) {
						token = T_OP_EQ;
					} else {
						gettoken(&ptr, value, sizeof(value));
					}
					if (value[0] == 0) {
						DEBUG("rlm_ldap: Attribute %s has no value", element->attr);
						break;
					}
					DEBUG("rlm_ldap: Adding %s as %s, value %s & op=%d", element->attr, element->radius_attr, value, token);
						if ((newpair = pairmake(element->radius_attr, value, token)) == NULL)
						continue;
					if (! vals_idx){
						pairdelete(pairs,newpair->attribute);
					}
					pairadd(&pairlist, newpair);
				}
			}
			ldap_value_free(vals);
		}
	}

	return (pairlist);
}

/* globally exported name */
module_t        rlm_ldap = {
	"LDAP",
	RLM_TYPE_THREAD_SAFE,	/* type: reserved 	 */
	NULL,			/* initialization 	 */
	ldap_instantiate,	/* instantiation 	 */
	{
		ldap_authenticate,	/* authentication 	 */
		ldap_authorize,		/* authorization 	 */
		NULL,			/* preaccounting 	 */
		NULL,			/* accounting 		 */
		NULL			/* checksimul 		 */
	},
	ldap_detach,		/* detach 		 */
	NULL,			/* destroy 		 */
};
