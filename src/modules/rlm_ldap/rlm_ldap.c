/*
 * rlm_ldap.c LDAP authorization and authentication module. 
 * 
 *
 * This module is based on LDAP patch to Cistron radiusd, which in turn was
 * based mostly on a Mysql+Cistron patch from oyarzun@wilmington.net
 *
 * 	Written by Adrian Pavlykevych <pam@polynet.lviv.ua>
 */
static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include	<sys/socket.h>

#ifdef HAVE_NETINET_IN_H
#include	<netinet/in.h>
#endif

#include	<stdio.h>
#include	<stdlib.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<ctype.h>
#include	<string.h>

#include	<lber.h>
#include        <ldap.h>

#include	"radiusd.h"
#include	"conffile.h"
#include	"modules.h"

#define DIALUP_ACCESS 1
#define MAX_AUTH_QUERY_LEN      256
#define TIMELIMIT 5

typedef struct {
  char* attr;
  char* radius_attr;
} TLDAP_RADIUS;

static char	*make_filter(char *, char *);

static char		*dn_base(char *);
static VALUE_PAIR	*ldap_pairget(LDAP *, LDAPMessage *, TLDAP_RADIUS *);
static LDAP		*rlm_ldap_connect(const char *, const char *, int, int *);


#define MAX_SERVER_LINE 1024
/*
 *	These should really be in a module-specific data structure,
 *	which is passed to the module with every request.
 */
static char	*ldap_server = NULL;
static int	ldap_port = 389;
static int	ldap_timelimit = TIMELIMIT;
/* wait forever on network activity */
static struct timeval ldap_net_timeout = { -1, 0 };
/* wait forever for search results */
static struct timeval ldap_timeout = { -1, 0 };
static struct timeval *timeout = NULL;
static int	ldap_cache_size = 0; /* cache size limited only by TTL */
static int	ldap_cache_ttl = 30 ;/* cache objects TTL 30 secs */	
static int	ldap_debug = 0; /* 0x0005; */
static int	ldap_tls_mode = LDAP_OPT_X_TLS_TRY;
static char	*ldap_login    = NULL;
static char	*ldap_password = NULL;
static char	*ldap_filter   = NULL;
static char	*ldap_basedn   = NULL;
static char	*group_basedn  = NULL;
static char	*ldap_radius_group = NULL;

static LDAP	*ld = NULL;

static CONF_PARSER module_config[] = {
  { "server",		PW_TYPE_STRING_PTR, &ldap_server,	      NULL },
  { "port",		PW_TYPE_INTEGER,    &ldap_port,		      "389" },
  { "net_timeout",	PW_TYPE_INTEGER,    &ldap_net_timeout.tv_sec, "-1" },
  { "timeout",		PW_TYPE_INTEGER,    &ldap_timeout.tv_sec,     "-1" },

  { "identity",		PW_TYPE_STRING_PTR, &ldap_login,	      NULL },
  { "password",		PW_TYPE_STRING_PTR, &ldap_password,	      NULL },
  { "basedn",		PW_TYPE_STRING_PTR, &ldap_basedn,	      NULL },
  { "filter",		PW_TYPE_STRING_PTR, &ldap_filter,	      NULL },
  { "access_group",	PW_TYPE_STRING_PTR, &ldap_radius_group,	      NULL },

  { "cache_size",	PW_TYPE_INTEGER,    &ldap_cache_size,	      "0" },
  { "cache_ttl",	PW_TYPE_INTEGER,    &ldap_cache_ttl,	      "30" },
  
  { NULL, -1, NULL, NULL }
};

/* LDAP attribute name that controls remote access */
#define LDAP_RADIUSACCESS "dialupAccess"

/*
 *	Fallback to default settings if no basic attributes defined in
 *	object
 *
 *	(An ugly hack to be replaced by profiles and policies,
 *	or by new configuration file support...)
 */
#define DEFAULT_CONF

#ifdef DEFAULT_CONF
#define DEFAULT_SERVICE_TYPE "Framed-User"
#define DEFAULT_FRAMED_PROTOCOL "PPP"
#define DEFAULT_FRAMED_MTU "576"
#define DEFAULT_FRAMED_COMPRESSION "Van-Jacobson-TCP-IP"
#define DEFAULT_IDLE_TIMEOUT "240"
#define DEFAULT_SIMULTANEOUS_USE "1"
#endif

#define ld_valid                ld_options.ldo_valid
#define LDAP_VALID_SESSION      0x2
#define LDAP_VALID(ld)  ( (ld)->ld_valid == LDAP_VALID_SESSION )

/*
 *      Mappings of LDAP radius* attributes to RADIUS attributes
 *
 *	Hmm... these should really be read in from the configuration file
 */
static TLDAP_RADIUS check_item_map[] = {
        { "radiusAuthType", "Auth-Type" },
        { "npSessionsAllowed", "Simultaneous-Use" },
        {NULL, NULL}
};
static TLDAP_RADIUS reply_item_map[] = {
	{ "radiusServiceType", "Service-Type" },
	{ "radiusFramedProtocol", "Framed-Protocol" },
	{ "radiusFramedIPAddress", "Framed-IP-Address" },
	{ "radiusFramedIPNetmask", "Framed-IP-Netmask" },
	{ "radiusFramedRoute", "Framed-Route" },
	{ "radiusFramedRouting", "Framed-Routing" },
	{ "radiusFilterId", "Filter-Id" },
	{ "radiusFramedMTU", "Framed-MTU" },
	{ "radiusFramedCompression", "Framed-Compression" },
	{ "radiusLoginIPHost", "Login-IP-Host" },
	{ "radiusLoginService", "Login-Service" },
	{ "radiusLoginTCPPort", "Login-TCP-Port" },
	{ "radiusCallbackNumber", "Callback-Number" },
	{ "radiusCallbackId", "Callback-Id" },
	{ "radiusFramedRoute", "Framed-Route" },
	{ "radiusFramedIPXNetwork", "Framed-IPX-Network" },
	{ "radiusClass", "Class" },
	{ "radiusSessionTimeout", "Session-Timeout" },
	{ "radiusIdleTimeout", "Idle-Timeout" },
	{ "radiusTerminationAction", "Termination-Action" },
	{ "radiusCalledStationId", "Called-Station-Id" },
	{ "radiusCallingStationId", "Calling-Station-Id" },
	{ "radiusLoginLATService", "Login-LAT-Service" },
	{ "radiusLoginLATNode", "Login-LAT-Node" },
	{ "radiusLoginLATGroup", "Login-LAT-Group" },
	{ "radiusFramedAppleTalkLink", "Framed-AppleTalk-Link" },
	{ "radiusFramedAppleTalkNetwork", "Framed-AppleTalk-Network" },
	{ "radiusFramedAppleTalkZone", "Framed-AppleTalk-Zone" },
	{ "radiusPortLimit", "Port-Limit" },
	{ "radiusLoginLATPort", "Login-LAT-Port" },
        {NULL, NULL}
};

/*************************************************************************
 *
 *	Function: rlm_ldap_instantiate
 *
 *	Purpose: Uses section of radiusd config file passed as parameter
 *		 to create an instance ofthe module.
 *	Note: 	 Currently multiple instances are not supported, lots of
 *		 data structures restructuring should be done to support it 
 *
 *************************************************************************/
static int rlm_ldap_instantiate(CONF_SECTION *conf, void **instance)
{
	int res;
	int i;

	cf_section_parse(conf, module_config);
	
	if(ldap_radius_group != NULL)
		group_basedn = dn_base(ldap_radius_group);
	if(ldap_net_timeout.tv_sec != -1)
		timeout = &ldap_net_timeout;
	if(ldap_timeout.tv_sec != -1 )
		timeout = &ldap_timeout;
	
	if(timeout != NULL)
		DEBUG("timeout: %ld.%ld", timeout->tv_sec,timeout->tv_usec);
	
	if ((ld = rlm_ldap_connect(ldap_login, ldap_password, 0, &res)) == NULL) {
		DEBUG("rlm_ldap: Could not connect to LDAP");
		return -1;
	}

	//DEBUG("rlm_ldap: Disabling LDAP cache");
  //ldap_disable_cache(ld);
  return 0;
}


static int perform_search(char *ldap_basedn, char *filter, char **attrs, LDAPMessage **result)
{
  
	int msgid;
	int res = RLM_MODULE_OK;
	int rc;
	
	ld = rlm_ldap_connect(ldap_login, ldap_password, 0, &res);
	
	
	DEBUG("rlm_ldap: performing search with filter '%s'", filter);
	msgid = ldap_search(ld,ldap_basedn,LDAP_SCOPE_SUBTREE,filter,attrs,0);
	DEBUG("rlm_ldap: ok, search done, continuing...");
	
	if(msgid == -1) {
		radlog(L_ERR,"rlm_ldap: ldap_search() API failed\n");
		return RLM_MODULE_FAIL;
	}
	
	
	rc = ldap_result(ld, msgid, 1, timeout, result);
	
	DEBUG("rlm_ldap: ok, got a result, continuing...");
	if(rc < 1) {
		DEBUG("rlm_ldap: result is less than desirable. :\(");
		ldap_perror( ld, "rlm_ldap: ldap_result()" );
		radlog(L_ERR,"rlm_ldap: ldap_result() failed - %s\n", strerror(errno));
		return RLM_MODULE_FAIL;
	}
	
	DEBUG("rlm_ldap: result is valid");
	switch(ldap_result2error(ld, *result, 0)) {
	case LDAP_SUCCESS:
		break;
		
	case LDAP_TIMELIMIT_EXCEEDED:
		radlog(L_ERR, "rlm_ldap: Warning timelimit exceeded, using partial results\n");
		break;
		
	default:
		DEBUG("rlm_ldap: ldap_search() failed");
		ldap_msgfree(*result);
		return RLM_MODULE_FAIL;
	}
	
	if ((ldap_count_entries(ld, *result)) != 1) {
		DEBUG("rlm_ldap: user object not found or got ambiguous search result");
		ldap_msgfree(*result);
		res = RLM_MODULE_NOTFOUND;
	} else {
		DEBUG("rlm_ldap: single result returned. good.");
	}
	
	return res;
}

/******************************************************************************
 *
 *      Function: rlm_ldap_authorize
 *
 *      Purpose: Check if user is authorized for remote access 
 *
 *****************************************************************************/
static int rlm_ldap_authorize(void *instance, REQUEST *request)
{
	LDAPMessage *result, *msg, *gr_result, *gr_msg;
	char *filter, *name, *user_dn;
	const char *attrs[] 	= { "*", NULL };
	const *group_attrs[] = { "member", NULL	};
	char **vals;
	VALUE_PAIR      *check_tmp;
	VALUE_PAIR      *reply_tmp;
	int  i;
	int	 res;
	VALUE_PAIR **check_pairs, **reply_pairs;
	
	check_pairs = &request->config_items;
	reply_pairs = &request->reply->vps;
	
	DEBUG("rlm_ldap: authorize");
	name = request->username->strvalue;
	
	/*
	 *      Check for valid input, zero length names not permitted
	 */
	if (name[0] == 0) {
		radlog(L_ERR, "rlm_ldap: zero length username not permitted\n");
		return RLM_MODULE_INVALID;
	}
	
/*  Unfortunately LDAP queries are case insensitive, so in order to provide
    unique names for simultaneous logins verification, we need to lowercase
    USERNAME attribute value
*/
	for(i=0; name[i] != 0; i++) 
		name[i] = tolower(name[i]);
	
	DEBUG("rlm_ldap: performing user authorization for %s", name);
	
	filter = make_filter(ldap_filter, name);
	
	res = perform_search(ldap_basedn, filter, attrs, &result);
	
	
	if ((msg = ldap_first_entry(ld,result)) == NULL) {
		DEBUG("rlm_ldap: ldap_first_entry() failed");
		ldap_msgfree(result);
		return RLM_MODULE_FAIL;
	}
	
	if ((user_dn = ldap_get_dn(ld,msg)) == NULL) {
		DEBUG("rlm_ldap: ldap_get_dn() failed");
		ldap_msgfree(result);
		return RLM_MODULE_FAIL;
	}
	
	/*
	 *	Remote access is controlled by LDAP_RADIUSACCESS
	 *	attribute of user object
	 */
	if((vals = ldap_get_values(ld, msg, LDAP_RADIUSACCESS)) != NULL ) {
		if(!strncmp(vals[0],"FALSE",5)) {
			DEBUG("rlm_ldap: dialup access disabled");
			ldap_msgfree(result);
			return RLM_MODULE_REJECT;
		}
	} else {
		DEBUG("rlm_ldap: no %s attribute - access denied by default", LDAP_RADIUSACCESS);
		ldap_msgfree(result);
		return RLM_MODULE_REJECT;
	}
	
	/*
	 *	Remote access controlled by group membership attribute
	 *	of user object
	 */
	if(ldap_radius_group != NULL) {
		int found = 0;
		
		DEBUG("rlm_ldap: checking user membership in dialup-enabling group %s", ldap_radius_group);
		if((res = perform_search(group_basedn, ldap_radius_group, group_attrs, &gr_result)))
			return(res);
		
		if ((gr_msg = ldap_first_entry(ld, gr_result)) == NULL) {
			DEBUG("rlm_ldap: ldap_first_entry() failed");
			ldap_msgfree(result);
			return RLM_MODULE_FAIL;
		}
		
		if ((vals = ldap_get_values(ld, gr_msg, "member")) != NULL ) {
			int valno;
			for(valno = 0;
			    (vals[valno] != NULL) 
				    && !(found = !strncmp(vals[valno],user_dn,strlen(user_dn)));
			    valno++) {
			}
			ldap_value_free(vals);
		}
		
		ldap_msgfree(gr_result);
		
		if (!found) {
			DEBUG("rlm_ldap: user does not belong to dialup-enabling group");
			ldap_msgfree(result);
			return RLM_MODULE_REJECT;
		}
	}
	
	
	DEBUG("rlm_ldap: looking for check items in directory..."); 
	if ((check_tmp = ldap_pairget(ld, msg, check_item_map)) != (VALUE_PAIR *)0) {
		pairadd(check_pairs, check_tmp);
	}
	
	/*
	 *	Module should default to LDAP authentication if no
	 *	Auth-Type specified
	 *
	 *	FIXME: This should be a configuration parameter.
	 */
	if(pairfind(*check_pairs, PW_AUTHTYPE) == NULL){
		pairadd(check_pairs, pairmake("Auth-Type", "LDAP", T_OP_CMP_EQ));
	}

	/* 
	 *	Adding new attribute containing DN for LDAP object
	 *	associated with given username
	 */
	pairadd(&request->packet->vps, pairmake("Ldap-UserDn", user_dn, T_OP_EQ));
	
	DEBUG("rlm_ldap: looking for reply items in directory..."); 
	if((reply_tmp = ldap_pairget(ld,msg, reply_item_map)) != (VALUE_PAIR *)0) {
		pairadd(reply_pairs, reply_tmp);
	}
	
#ifdef DEFAULT_CONF
	if(pairfind(*reply_pairs, PW_SERVICE_TYPE) == NULL){
		pairadd(reply_pairs, pairmake("Service-Type", DEFAULT_SERVICE_TYPE, T_OP_EQ));
	}
	if(pairfind(*reply_pairs, PW_FRAMED_PROTOCOL) == NULL){
		pairadd(reply_pairs, pairmake("Framed-Protocol", DEFAULT_FRAMED_PROTOCOL, T_OP_EQ));
	}
	if(pairfind(*reply_pairs, PW_FRAMED_MTU) == NULL){
		pairadd(reply_pairs, pairmake("Framed-MTU", DEFAULT_FRAMED_MTU, T_OP_EQ));
	}
	if(pairfind(*reply_pairs, PW_FRAMED_COMPRESSION) == NULL){
		pairadd(reply_pairs, pairmake("Framed-Compression", DEFAULT_FRAMED_COMPRESSION, T_OP_EQ));
	}
	if(pairfind(*reply_pairs, PW_IDLE_TIMEOUT) == NULL){
		pairadd(reply_pairs, pairmake("Idle-Timeout", DEFAULT_IDLE_TIMEOUT, T_OP_EQ));       
	}
	if(pairfind(*check_pairs, PW_SIMULTANEOUS_USE) == NULL){
		pairadd(check_pairs, pairmake("Simultaneous-Use", DEFAULT_SIMULTANEOUS_USE, T_OP_EQ));       
	}
#endif
	
	DEBUG("rlm_ldap: user %s authorized to use remote access", name);
	ldap_msgfree(result);
	return RLM_MODULE_OK;
}

/******************************************************************************
 *
 *	Function: rlm_ldap_authenticate
 *
 *	Purpose: Check the user's password against ldap database 
 *
 *****************************************************************************/
static int rlm_ldap_authenticate(void *instance, REQUEST *request)
{
	LDAP *ld_user;
	LDAPMessage *result, *msg;
	char *filter, *passwd, *user_dn, *name;
	const char *attrs[] = { "uid", NULL };
	int  res;
	VALUE_PAIR *vp_user_dn;
	
	DEBUG("rlm_ldap: authenticate");

	/*
	 *	Ensure that we're being passed a plain-text password,
	 *	and not anything else.
	 */
	if (request->password->attribute != PW_PASSWORD) {
		radlog(L_AUTH, "rlm_ldap: Attribute \"Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}
	
	name = request->username->strvalue;
	passwd = request->password->strvalue;
	
	if (request->password->length == 0) {
		radlog(L_ERR, "rlm_ldap: empty password supplied");
		return RLM_MODULE_INVALID;
	}
	
	DEBUG("rlm_ldap: login attempt by \"%s\" with password \"%s\"", name, passwd);
	filter = make_filter(ldap_filter, name);
	
	if((vp_user_dn = pairfind(request->packet->vps, LDAP_USERDN)) == NULL){
		if((res = perform_search(ldap_basedn, filter, attrs, &result)))
			return(res);
		
		if ((msg = ldap_first_entry(ld,result)) == NULL) {
			ldap_msgfree(result);
			
			return RLM_MODULE_FAIL;
		}
		
		if ((user_dn = ldap_get_dn(ld,msg)) == NULL) {
			DEBUG("rlm_ldap: ldap_get_dn() failed");
			ldap_msgfree(result);
			
			return RLM_MODULE_FAIL;
		}
		pairadd(&request->packet->vps,pairmake("Ldap-UserDn",user_dn,T_OP_EQ));
		ldap_msgfree(result);
		
	} else {	
		user_dn = vp_user_dn->strvalue;
	}
	
	DEBUG("rlm_ldap: user DN: %s", user_dn);
	
	if ((ld_user = rlm_ldap_connect(user_dn, passwd, 1, &res)) == NULL)
		return res;
	
	DEBUG("rlm_ldap: user %s authenticated succesfully", name);
	ldap_unbind_s(ld_user);
	return RLM_MODULE_OK;
}

static LDAP *rlm_ldap_connect(const char *dn, const char *password, int auth, int *result)
{
	LDAP *ld;
	int msgid, rc;
	LDAPMessage  *res;
	
	DEBUG("rlm_ldap: (re)connect, authentication %d", auth);
	if ((ld = ldap_init(ldap_server,ldap_port)) == NULL){
		radlog(L_ERR, "rlm_ldap: ldap_init() failed");	    
		*result = RLM_MODULE_FAIL;
		return(NULL);
	}
	
	if (timeout != NULL && ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, (void *)timeout) != LDAP_OPT_SUCCESS) {
		radlog(L_ERR, "rlm_ldap: Could not set LDAP_OPT_NETWORK_TIMEOUT %ld.%ld", timeout->tv_sec, timeout->tv_usec);
	}
	
	if (ldap_timelimit != -1 && ldap_set_option(ld, LDAP_OPT_TIMELIMIT, (void *) &ldap_timelimit) != LDAP_OPT_SUCCESS ){
		radlog(L_ERR, "rlm_ldap: Could not set LDAP_OPT_TIMELIMIT %d", ldap_timelimit );
	}
	
	if(ldap_debug && ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &ldap_debug ) != LDAP_OPT_SUCCESS ) {
		radlog(L_ERR, "rlm_ldap: Could not set LDAP_OPT_DEBUG_LEVEL %d", ldap_debug);
	}
#ifdef HAVE_TLS
	if (ldap_tls_mode && ldap_set_option(ld, LDAP_OPT_X_TLS,(void *) &ldap_tls_mode) != LDAP_OPT_SUCCESS ){
		radlog(L_ERR, "rlm_ldap: Could not set LDAP_OPT_X_TLS_TRY");
	}
#endif
	
	if (!auth)
		if (ldap_enable_cache(ld, ldap_cache_ttl, ldap_cache_size) != LDAP_SUCCESS)
			radlog(L_ERR,"rlm_ldap: ldap_enable_cache failed");
	
	msgid = ldap_bind(ld, dn, password, LDAP_AUTH_SIMPLE);
	if(msgid == -1) {
		ldap_perror(ld, "rlm_ldap: rlm_ldap_connect()" );
		*result = RLM_MODULE_FAIL;
		ldap_unbind_s(ld);
		return(NULL);
	}
	
	DEBUG("rlm_ldap: rlm_ldap_connect() waiting for bind result ...");
	
	rc = ldap_result(ld, msgid, 1, timeout, &res);
	if(rc < 1){
		ldap_perror( ld, "rlm_ldap: ldap_result()" );
		*result = RLM_MODULE_FAIL;
		ldap_unbind_s(ld);
		return(NULL);
	}
	DEBUG("rlm_ldap: rlm_ldap_connect() bind finished, let's check the results");
	switch(ldap_result2error(ld, res, 1)) {
	case LDAP_SUCCESS:
		*result = RLM_MODULE_OK;
		break;
		
	case LDAP_INVALID_CREDENTIALS:
		if(auth){
			*result = RLM_MODULE_REJECT;
			break;
		}
	default:
		ldap_perror( ld, "rlm_ldap: ldap_result()" );
		radlog(L_ERR,"rlm_ldap: ldap_result() failed - %s\n", strerror(errno));
		DEBUG("rlm_ldap: LDAP FAILURE");
		*result = RLM_MODULE_FAIL;
	} 

	if(*result != RLM_MODULE_OK) {
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
static int rlm_ldap_detach(void *instance)
{
	ldap_unbind_s(ld);
	return 0;
}

/*****************************************************************************
 * 
 * This function takes DN as parameter and returns RDN and BASEDN for search.
 * Has anyone better idea about getting object attributes based on its DN?
 *
 *****************************************************************************/
static char *dn_base(char *dn)
{
	char *ptr;
	
	if((ptr = (char *)strchr(dn, ',')) == NULL) {
		DEBUG("Invalid DN syntax: no ',' in the string %s, maibe it's a CN? Returning default base", dn);  
		return(ldap_basedn);
	}
	ptr[0]='\0';
	if(++ptr == NULL) {
		DEBUG("Invalid DN syntax: ',' is the last symbol in the string");  
		return(NULL);
	}
	return(ptr);
}

/*****************************************************************************
 *	Replace %<whatever> in a string.
 *
 *	%u   User name
 *
 *	FIXME: Why is this function even here?  What's wrong with radius_xlat2?
 *
 *****************************************************************************/
static char *make_filter(char *str, char *name)
{
	static char buf[MAX_AUTH_QUERY_LEN];
	int i = 0, c;
	char *p;
	
	for(p = str; *p; p++) {
		c = *p;
		if (c != '%' && c != '\\') {
			buf[i++] = *p;
			continue;
		}
		if (*++p == 0) break;
		if (c == '%') switch(*p) {
		case '%':
			buf[i++] = *p;
			break;
		case 'u': /* User name */
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
		if (c == '\\') switch(*p) {
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

/*****************************************************************************
 *	Get RADIUS attributes from LDAP object
 *	( according to draft-adoba-radius-05.txt 
 *	  <http://www.ietf.org/internet-drafts/draft-adoba-radius-05.txt> )
 *
 *****************************************************************************/

static VALUE_PAIR *ldap_pairget(LDAP *ld, LDAPMessage *entry,
				TLDAP_RADIUS *item_map)
{
	BerElement *berptr;
	char *attr;
	char **vals;
	char *ptr;
	TLDAP_RADIUS *element;
	int token;
	char value[64];
	VALUE_PAIR *pairlist;
	VALUE_PAIR *newpair = NULL;
	pairlist = NULL;

	if ((attr = ldap_first_attribute(ld, entry, &berptr)) == NULL) {
		DEBUG("rlm_ldap: Object has no attributes");
		return NULL;
	}
	
	do {
		for(element=item_map; element->attr != NULL; element++) {
			if(!strncasecmp(attr,element->attr,strlen(element->attr))) {
				if(((vals = ldap_get_values(ld, entry, attr)) == NULL) ||
				   (ldap_count_values(vals) > 1)) {
					DEBUG("rlm_ldap: Attribute %s has multiple values", attr);
					break;
				}
				ptr = vals[0];
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
				if((newpair = pairmake(element->radius_attr, value, token)) == NULL)
					continue;
				pairadd(&pairlist, newpair);
				ldap_value_free(vals);
			}
		}
	} while ((attr = ldap_next_attribute(ld, entry, berptr)) != NULL);
	
	ber_free(berptr, 0);
	return(pairlist);
}

/* globally exported name */
module_t rlm_ldap = {
	"LDAP",
	RLM_TYPE_THREAD_UNSAFE,		/* type: not thread safe */
	NULL,		       		/* initialization */
	rlm_ldap_instantiate,		/* instantiation */
	rlm_ldap_authorize,             /* authorization */
	rlm_ldap_authenticate,          /* authentication */
	NULL,				/* preaccounting */
	NULL,				/* accounting */
	NULL,    			/* checksimul */
	rlm_ldap_detach,            	/* detach */
	NULL,				/* destroy */
};
