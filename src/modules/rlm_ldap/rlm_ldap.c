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

#include	"radiusd.h"
#include	"conffile.h"
#include	"modules.h"


#define MAX_AUTH_QUERY_LEN      256
#define TIMELIMIT 5

/* linked list of mappings between RADIUS attributes and LDAP attributes */
struct TLDAP_RADIUS {
	char*                 attr;
	char*                 radius_attr;
	struct TLDAP_RADIUS*  next;
};
typedef struct TLDAP_RADIUS TLDAP_RADIUS;

#define MAX_SERVER_LINE 1024
/*
 * These should really be in a module-specific data structure, which is
 * passed to the module with every request.
 */

static struct timeval *timeout = NULL;

typedef struct {
	char           *server;
	int             port;
	int             timelimit;
	struct timeval  net_timeout;
	struct timeval  timeout;
	int             debug;
	int             tls_mode;
	char           *login;
	char           *password;
	char           *filter;
	char           *basedn;
	char           *access_group;
	char           *access_attr;
	char           *dictionary_mapping;
	TLDAP_RADIUS   *check_item_map;
	TLDAP_RADIUS   *reply_item_map;
	LDAP           *ld;
	int             bound;
	int             ldap_debug; /* Debug flag for LDAP SDK */
}               ldap_instance;

static CONF_PARSER module_config[] = {
	{"server", PW_TYPE_STRING_PTR, offsetof(ldap_instance,server), NULL, NULL},
	{"port", PW_TYPE_INTEGER, offsetof(ldap_instance,port), NULL, "389"},
	/* wait forever on network activity */
	{"net_timeout", PW_TYPE_INTEGER, offsetof(ldap_instance,net_timeout.tv_sec), NULL, "-1"},
	/* wait forever for search results */
	{"timeout", PW_TYPE_INTEGER, offsetof(ldap_instance,timeout.tv_sec), NULL, "-1"},
	/* allow server unlimited time for search (server-side limit) */
	{"timelimit", PW_TYPE_INTEGER, offsetof(ldap_instance,timelimit), NULL, "-1"},

	{"identity", PW_TYPE_STRING_PTR, offsetof(ldap_instance,login), NULL, NULL},
	{"password", PW_TYPE_STRING_PTR, offsetof(ldap_instance,password), NULL, NULL},
	{"basedn", PW_TYPE_STRING_PTR, offsetof(ldap_instance,basedn), NULL, NULL},
	{"filter", PW_TYPE_STRING_PTR, offsetof(ldap_instance,filter), NULL, NULL},
	{"access_group", PW_TYPE_STRING_PTR, offsetof(ldap_instance,access_group), NULL, NULL},
	/* LDAP attribute name that controls remote access */
	{"access_attr", PW_TYPE_STRING_PTR, offsetof(ldap_instance,access_attr), NULL, NULL},
	/* file with mapping between LDAP and RADIUS attributes */
	{"dictionary_mapping", PW_TYPE_STRING_PTR, offsetof(ldap_instance,dictionary_mapping), NULL, "${confdir}/ldap.attrmap"},
	{"ldap_debug", PW_TYPE_INTEGER, offsetof(ldap_instance,ldap_debug), NULL, "0x0000"},

	{NULL, -1, 0, NULL, NULL}
};

#define ld_valid                ld_options.ldo_valid
#define LDAP_VALID_SESSION      0x2
#define LDAP_VALID(ld)  ( (ld)->ld_valid == LDAP_VALID_SESSION )

static char    *make_filter(char *, char *);
#ifdef FIELDCPY
static void     fieldcpy(char *, char **);
#endif
static VALUE_PAIR *ldap_pairget(LDAP *, LDAPMessage *, TLDAP_RADIUS *);
static LDAP    *ldap_connect(void *instance, const char *, const char *, int, int *);
static int     read_mappings(ldap_instance* inst);

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

	inst = rad_malloc(sizeof *inst);

	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}
	inst->timeout.tv_usec = 0;
	inst->net_timeout.tv_usec = 0;
	inst->tls_mode = LDAP_OPT_X_TLS_TRY;
	inst->bound = 0;
	inst->reply_item_map = NULL;
	inst->check_item_map = NULL;
	inst->ld = NULL;

	if (read_mappings(inst) != 0) {
		radlog(L_ERR, "rlm_ldap: Reading dictionary mappings from file %s failed",
		       inst->dictionary_mapping);
		radlog(L_ERR, "rlm_ldap: Proceeding with no mappings");
	}

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
perform_search(void *instance, char *search_basedn, int scope, char *filter, char **attrs, LDAPMessage ** result)
{
	int             msgid;
	int             res = RLM_MODULE_OK;
	int             rc;
	ldap_instance  *inst = instance;

	if (!inst->bound) {
		DEBUG2("rlm_ldap: attempting LDAP reconnection");
		if (inst->ld){
			DEBUG2("rlm_ldap: closing existing LDAP connection");
			ldap_unbind_s(inst->ld);
		}
		if ((inst->ld = ldap_connect(instance, inst->login, inst->password, 0, &res)) == NULL) {
			radlog(L_ERR, "rlm_ldap: (re)connection attempt failed");
			return (RLM_MODULE_FAIL);
		}
		inst->bound = 1;
	}
	DEBUG2("rlm_ldap: performing search in %s, with filter %s", search_basedn, filter);
	msgid = ldap_search(inst->ld, search_basedn, scope, filter, attrs, 0);
	if (msgid == -1) {
		radlog(L_ERR, "rlm_ldap: ldap_search() failed\n");
		inst->bound = 0;
		return (RLM_MODULE_FAIL);
	}
	rc = ldap_result(inst->ld, msgid, 1, timeout, result);

	if (rc < 1) {
		ldap_perror(inst->ld, "rlm_ldap: ldap_result()");
		radlog(L_ERR, "rlm_ldap: ldap_result() failed - %s\n", strerror(errno));
		ldap_msgfree(*result);
		inst->bound = 0;
		return (RLM_MODULE_FAIL);
	}
	switch (ldap_result2error(inst->ld, *result, 0)) {
	case LDAP_SUCCESS:
		break;

	case LDAP_TIMELIMIT_EXCEEDED:
		radlog(L_ERR, "rlm_ldap: Warning timelimit exceeded, using partial results\n");
		break;

	default:
		DEBUG("rlm_ldap: ldap_search() failed");
		ldap_msgfree(*result);
		inst->bound = 0;
		return (RLM_MODULE_FAIL);
	}

	if ((ldap_count_entries(inst->ld, *result)) != 1) {
		DEBUG("rlm_ldap: object not found or got ambiguous search result");
		res = RLM_MODULE_NOTFOUND;
	}
	return res;
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
	LDAPMessage    *result, *msg, *gr_result;
	ldap_instance  *inst = instance;
	char           *filter, *name, *user_dn;
	char           *attrs[] = {"*", NULL};
	VALUE_PAIR     *check_tmp;
	VALUE_PAIR     *reply_tmp;
	int             res;
	VALUE_PAIR    **check_pairs, **reply_pairs;
	char          **vals;

	DEBUG("rlm_ldap: - authorize");

	if(!request->username){
		radlog(L_AUTH, "rlm_ldap: Attribute \"User-Name\" is required for authentication.\n");
		return RLM_MODULE_INVALID;
	}

	check_pairs = &request->config_items;
	reply_pairs = &request->reply->vps;
	name = request->username->strvalue;

	/*
	 * Check for valid input, zero length names not permitted
	 */
	if (name[0] == 0) {
		radlog(L_ERR, "rlm_ldap: zero length username not permitted\n");
		return RLM_MODULE_INVALID;
	}
	DEBUG("rlm_ldap: performing user authorization for %s", name);

	filter = make_filter(inst->filter, name);

	if ((res = perform_search(instance, inst->basedn, LDAP_SCOPE_SUBTREE, filter, attrs, &result)) != RLM_MODULE_OK) {
		DEBUG("rlm_ldap: search failed");
		return (res);
	}
	if ((msg = ldap_first_entry(inst->ld, result)) == NULL) {
		DEBUG("rlm_ldap: ldap_first_entry() failed");
		ldap_msgfree(result);
		return RLM_MODULE_FAIL;
	}
	if ((user_dn = ldap_get_dn(inst->ld, msg)) == NULL) {
		DEBUG("rlm_ldap: ldap_get_dn() failed");
		ldap_msgfree(result);
		return RLM_MODULE_FAIL;
	}
	/* Remote access is controled by attribute of the user object */
	if (inst->access_attr) {
		if ((vals = ldap_get_values(inst->ld, msg, inst->access_attr)) != NULL) {
			DEBUG("rlm_ldap: checking if remote access for %s is allowed by %s", name, inst->access_attr);
			if (!strncmp(vals[0], "FALSE", 5)) {
				DEBUG("rlm_ldap: dialup access disabled");
				ldap_msgfree(result);
				return RLM_MODULE_USERLOCK;
			}
		} else {
			DEBUG("rlm_ldap: no %s attribute - access denied by default", inst->access_attr);
			ldap_msgfree(result);
			return RLM_MODULE_USERLOCK;
		}
	}
	/* Remote access controled by group membership of the user object */
	if (inst->access_group != NULL) {
		DEBUG("rlm_ldap: checking user membership in dialup-enabling group %s", inst->access_group);
		/*
		 * uniquemember appears in Netscape Directory Server's groups
		 * since we have objectclass groupOfNames and
		 * groupOfUniqueNames
		 */
		filter = make_filter("(| (& (objectClass=GroupOfNames) (member=%u)) (& (objectClass=GroupOfUniqueNames) (uniquemember=%u)))", user_dn);
		res = perform_search(instance, inst->access_group, LDAP_SCOPE_BASE, filter, NULL, &gr_result);
		ldap_msgfree(gr_result);


		if (res != RLM_MODULE_OK) {
			if (res == RLM_MODULE_NOTFOUND)
				return (RLM_MODULE_USERLOCK);
			else
				return (res);
		}
	}
	DEBUG("rlm_ldap: looking for check items in directory...");
	if ((check_tmp = ldap_pairget(inst->ld, msg, inst->check_item_map)) != NULL)
		pairadd(check_pairs, check_tmp);


	/*
	 * Module should default to LDAP authentication if no Auth-Type
	 * specified
	 */
	if (pairfind(*check_pairs, PW_AUTHTYPE) == NULL)
		pairadd(check_pairs, pairmake("Auth-Type", "LDAP", T_OP_CMP_EQ));

	/*
	 * Adding new attribute containing DN for LDAP object associated with
	 * given username
	 */
	pairadd(&request->packet->vps, pairmake("Ldap-UserDn", user_dn, T_OP_EQ));

	DEBUG("rlm_ldap: looking for reply items in directory...");

	if ((reply_tmp = ldap_pairget(inst->ld, msg, inst->reply_item_map)) != NULL)
		pairadd(reply_pairs, reply_tmp);

	DEBUG("rlm_ldap: user %s authorized to use remote access", name);
	ldap_msgfree(result);
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
	char           *filter, *passwd, *user_dn, *name, *attrs[] = {"uid", NULL};
	int             res;
	VALUE_PAIR     *vp_user_dn;

	DEBUG("rlm_ldap: - authenticate");
	/*
	 * Ensure that we're being passed a plain-text password, and not
	 * anything else.
	 */

	if(!request->username){
		radlog(L_AUTH, "rlm_ldap: Attribute \"User-Name\" is required for authentication.\n");
		return RLM_MODULE_INVALID;
	}

	if (!request->password){
		radlog(L_AUTH, "rlm_ldap: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	if(request->password->attribute != PW_PASSWORD) {
		radlog(L_AUTH, "rlm_ldap: Attribute \"Password\" is required for authentication. Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}

	name = request->username->strvalue;
	passwd = request->password->strvalue;

	if (strlen(passwd) == 0) {
		radlog(L_ERR, "rlm_ldap: empty password supplied");
		return RLM_MODULE_INVALID;
	}
	DEBUG("rlm_ldap: login attempt by \"%s\" with password \"%s\"", name, passwd);
	filter = make_filter(inst->filter, name);

	if ((vp_user_dn = pairfind(request->packet->vps, LDAP_USERDN)) == NULL) {
		if ((res = perform_search(instance, inst->basedn, LDAP_SCOPE_SUBTREE, filter, attrs, &result)) != RLM_MODULE_OK) {
			DEBUG("rlm_ldap: search did not return ok value");
			return (res);
		}
		if ((msg = ldap_first_entry(inst->ld, result)) == NULL) {
			ldap_msgfree(result);
			return RLM_MODULE_FAIL;
		}
		if ((user_dn = ldap_get_dn(inst->ld, msg)) == NULL) {
			DEBUG("rlm_ldap: ldap_get_dn() failed");
			ldap_msgfree(result);
			return RLM_MODULE_FAIL;
		}
		pairadd(&request->packet->vps, pairmake("Ldap-UserDn", user_dn, T_OP_EQ));
		ldap_msgfree(result);
	} else {
		user_dn = vp_user_dn->strvalue;
	}

	DEBUG("rlm_ldap: user DN: %s", user_dn);

	ld_user = ldap_connect(instance, user_dn, passwd, 1, &res);

	if (ld_user == NULL)
		return (res);

	DEBUG("rlm_ldap: user %s authenticated succesfully", name);
	ldap_unbind_s(ld_user);
	return RLM_MODULE_OK;
}

static LDAP    *
ldap_connect(void *instance, const char *dn, const char *password, int auth, int *result)
{
	ldap_instance  *inst = instance;
	LDAP           *ld;
	int             msgid, rc;
	LDAPMessage    *res;

	DEBUG("rlm_ldap: (re)connect to %s:%d, authentication %d", inst->server, inst->port, auth);
	if ((ld = ldap_init(inst->server, inst->port)) == NULL) {
		radlog(L_ERR, "rlm_ldap: ldap_init() failed");
		*result = RLM_MODULE_FAIL;
		return (NULL);
	}
	if (inst->net_timeout.tv_sec != -1 && ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, (void *) &(inst->net_timeout)) != LDAP_OPT_SUCCESS) {
		radlog(L_ERR, "rlm_ldap: Could not set LDAP_OPT_NETWORK_TIMEOUT %ld.%ld", inst->net_timeout.tv_sec, inst->net_timeout.tv_usec);
	}
	if (inst->timelimit != -1 && ldap_set_option(ld, LDAP_OPT_TIMELIMIT, (void *) &(inst->timelimit)) != LDAP_OPT_SUCCESS) {
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

	DEBUG("rlm_ldap: connect as %s/%s", dn, password);
	msgid = ldap_bind(ld, dn, password, LDAP_AUTH_SIMPLE);
	if (msgid == -1) {
		ldap_perror(ld, "rlm_ldap: ldap_connect()");
		*result = RLM_MODULE_FAIL;
		ldap_unbind_s(ld);
		return (NULL);
	}
	DEBUG("rlm_ldap: ldap_connect() waiting for bind result ...");

	if (inst->timeout.tv_sec < 0)
		rc = ldap_result(ld, msgid, 1, NULL, &res);
	else
		rc = ldap_result(ld, msgid, 1, &(inst->timeout), &res);

	if (rc < 1) {
		ldap_perror(ld, "rlm_ldap: ldap_result()");
		*result = RLM_MODULE_FAIL;
		ldap_unbind_s(ld);
		return (NULL);
	}
	DEBUG("rlm_ldap: ldap_connect() bind finished");
	switch (ldap_result2error(ld, res, 1)) {
	case LDAP_SUCCESS:
		*result = RLM_MODULE_OK;
		break;

	case LDAP_INVALID_CREDENTIALS:
		if (auth) {
			*result = RLM_MODULE_REJECT;
			break;
		}
	default:
		DEBUG("rlm_ldap: LDAP FAILURE");
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
	if (inst->ld)
		ldap_unbind_s(inst->ld);

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

	free(inst);

	return 0;
}

/*****************************************************************************
 *	Replace %<whatever> in a string.
 *
 *	%u   User name
 *
 *****************************************************************************/
static char    *
make_filter(char *str, char *name)
{
	static char     buf[MAX_AUTH_QUERY_LEN];
	int             i = 0, c;
	char           *p;

	for (p = str; *p; p++) {
		c = *p;
		if (c != '%' && c != '\\') {
			buf[i++] = *p;
			continue;
		}
		if (*++p == 0)
			break;
		if (c == '%')
			switch (*p) {
			case '%':
				buf[i++] = *p;
				break;
			case 'u':	/* User name */
				if (name != NULL)
					strcpy(buf + i, name);
				else
					strcpy(buf + i, " ");
				i += strlen(buf + i);
				break;
			default:
				buf[i++] = '%';
				buf[i++] = *p;
				break;
			}
		if (c == '\\')
			switch (*p) {
			case 'n':
				buf[i++] = '\n';
				break;
			case 'r':
				buf[i++] = '\r';
				break;
			case 't':
				buf[i++] = '\t';
				break;
			default:
				buf[i++] = '\\';
				buf[i++] = *p;
				break;
			}
	}
	if (i >= MAX_AUTH_QUERY_LEN)
		i = MAX_AUTH_QUERY_LEN - 1;
	buf[i++] = 0;
	return buf;
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
	     TLDAP_RADIUS * item_map)
{
	BerElement     *berptr;
	char           *attr;
	char          **vals;
	int             vals_count;
	int             vals_idx;
	char           *ptr;
	TLDAP_RADIUS   *element;
	int             token;
	int             is_generic_attribute;
	char            value[64];
	VALUE_PAIR     *pairlist;
	VALUE_PAIR     *newpair = NULL;
	pairlist = NULL;
	if ((attr = ldap_first_attribute(ld, entry, &berptr)) == NULL) {
		DEBUG("rlm_ldap: Object has no attributes");
		return NULL;
	}
	do {
		/* check if there is a mapping from this LDAP attribute to a RADIUS attribute */
		for (element = item_map; element != NULL; element = element->next) {
			if (!strcasecmp(attr, element->attr)) {
                                /* mapping found, get the values */
				if (((vals = ldap_get_values(ld, entry, attr)) == NULL)) {
                                        DEBUG("rlm_ldap: ldap_get_values returned NULL for attribute %s", attr);
                                        break;
                                }


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
							pairadd(&pairlist, newpair);
						} else {
							radlog(L_ERR, "rlm_ldap: parsing %s failed: %s", 
							       attr, vals[vals_idx]);
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
							DEBUG("rlm_ldap: Attribute %s has no value", attr);
							break;
						}
						DEBUG("rlm_ldap: Adding %s as %s, value %s & op=%d", attr, element->radius_attr, value, token);
						if ((newpair = pairmake(element->radius_attr, value, token)) == NULL)
							continue;
						pairadd(&pairlist, newpair);
					}
				}
                                ldap_value_free(vals);
                        }
		}
	} while ((attr = ldap_next_attribute(ld, entry, berptr)) != NULL);

	ber_free(berptr, 0);
	return (pairlist);
}

/* globally exported name */
module_t        rlm_ldap = {
	"LDAP",
	RLM_TYPE_THREAD_UNSAFE,	/* type: reserved 	 */
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
