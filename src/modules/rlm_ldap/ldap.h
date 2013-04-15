/**
 * $Id$
 * @file ldap.h
 * @brief LDAP authorization and authentication module headers.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 Network RADIUS SARL<info@networkradius.com>
 * @copyright 2013 The FreeRADIUS Server Project.
 */
#ifndef _RLM_LDAP_H
#define _RLM_LDAP_H

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<ldap.h>

#define LDAP_MAX_ATTRMAP		128		//!< Maximum number of mappings between LDAP and 
							//!< FreeRADIUS attributes.
#define LDAP_MAP_RESERVED		4		//!< Number of additional items to allocate in expanded 
							//!< attribute name arrays. Currently for enable attribute, 
							//!< group membership attribute, valuepair attribute, 
							//!< and profile attribute.
					
#define LDAP_MAX_CACHEABLE		64		//!< Maximum number of groups we retrieve from the server for
							//!< a given user. If more than this number are retrieve the 
							//!< module returns invalid.
					
#define LDAP_MAX_GROUP_NAME_LEN		128		//!< Maximum name of a group name.
#define LDAP_MAX_ATTR_STR_LEN		256		//!< Maximum length of an xlat expanded LDAP attribute.
#define LDAP_MAX_FILTER_STR_LEN		1024		//!< Maximum length of an xlat expanded filter.
#define LDAP_MAX_DN_STR_LEN		2048		//!< Maximum length of an xlat expanded DN.

/*
 *	The default setting for TLS Certificate Verification
 */
#define TLS_DEFAULT_VERIFY "allow"

typedef struct ldap_acct_section {
	CONF_SECTION	*cs;				//!< Section configuration.
	
	const char *reference;				//!< Configuration reference string.
} ldap_acct_section_t;

typedef struct ldap_instance {
	CONF_SECTION	*cs;				//!< Main configuration section for this instance.
	fr_connection_pool_t *pool;			//!< Connection pool instance.

	const char	*server;			//!< Initial server to bind to.
	int		is_url;				//!< Whether ldap_is_ldap_url says 'server' is an 
							//!< ldap[s]:// url.
	int		port;				//!< Port to use when binding to the server.

	const char	*admin_dn;			//!< DN we bind as when we need to query the LDAP
							//!< directory.
	const char	*password;			//!< Password used in administrative bind.
	
	const char	*base_dn;			//!< Provided for convenience and backwards compatibility.
							//!< is the default value for userobj_base_dn, and 
							//!< groupobj_base_dn, if no dn is configured explicitly.

	int		chase_referrals;		//!< If the LDAP server returns a referral to another server
							//!< or point in the tree, follow it, establishing new
							//!< connections and binding where necessary.

	int		rebind;				//!< Controls whether we set an ldad_rebind_proc function
							//!< and so determines if we can bind to other servers whilst
							//!< chasing referrals. If this is false, we will still chase
							//!< referrals on the same server, but won't bind to other
							//!< servers.

	int		ldap_debug;			//!< Debug flag for the SDK.

	const char	*xlat_name;			//!< Instance name.

	int		expect_password;		//!< True if the user_map included a mapping between an LDAP
							//!< attribute and one of our password reference attributes.
	
	/*
	 *	RADIUS attribute to LDAP attribute maps
	 */
	value_pair_map_t *user_map; 			//!< Attribute map applied to users and profiles.
	
	/*
	 *	User object attributes and filters
	 */
	const char	*userobj_filter;		//!< Filter to retrieve only retrieve user objects.
	const char	*userobj_base_dn;		//!< DN to search for users under.
	const char	*userobj_scope_str;		//!< Scope (sub, one, base).
	int		userobj_scope;			//!< Search scope.
	
	const char	*userobj_membership_attr;	//!< Attribute that describes groups the user is a member of.
	char		*userobj_access_attr;		//!< Attribute to check to see if the user should be locked out.
	int		access_positive;		//!< If true the presence of the attribute will allow access, 
							//!< else it will deny access.
							
	const char	*valuepair_attr;		//!< Generic dynamic mapping attribute, contains a RADIUS
							//!< attribute and value.

	/*
	 *	Group object attributes and filters
	 */
	 
	const char	*groupobj_filter;		//!< Filter to retrieve only retrieve group objects.
	const char	*groupobj_base_dn;		//!< DN to search for users under.
	const char	*groupobj_scope_str;		//!< Scope (sub, one, base).
	int		groupobj_scope;			//!< Search scope.

	const char	*groupobj_name_attr;		//!< The name of the group.
	const char	*groupobj_membership_filter;	//!< Filter to only retrieve groups which contain
							//!< the user as a member.
						
	int		cacheable_group_name;		//!< If true the server will determine complete set of group
							//!< memberships for the current user object, and perform any
							//!< resolution necessary to determine the names of those
							//!< groups, then right them to the control list (LDAP-Group).
							
	int		cacheable_group_dn;		//!< If true the server will determine complete set of group
							//!< memberships for the current user object, and perform any
							//!< resolution necessary to determine the DNs of those groups,
							//!< then right them to the control list (LDAP-GroupDN).
	
	const DICT_ATTR	*group_da;			//!< The DA associated with this specific version of the
							//!< rlm_ldap module.
	
	/*
	 *	Profiles
	 */
	const char	*default_profile;		//!< If this is set, we will search for a profile object
							//!< with this name, and map any attributes it contains.
							//!< No value should be set if profiles are not being used
							//!< as there is an associated performance penalty.
	const char	*profile_attr;			//!< Attribute that identifies profiles to apply. May appear
							//!< in userobj or groupobj.
	const char	*profile_filter;		//!< Filter to retrieve only retrieve group objects.
	
	/*
	 *	Accounting
	 */
	ldap_acct_section_t *postauth;			//!< Modify mappings for post-auth.
	ldap_acct_section_t *accounting;		//!< Modify mappings for accounting.

	/*
	 *	TLS items.  We should really normalize these with the
	 *	TLS code in 3.0.
	 */
	int		tls_mode;
	int		start_tls;			//!< Send the Start TLS message to the LDAP directory
							//!< to start encrypted communications using the standard
							//!< LDAP port.

	const char	*tls_cacertfile;		//!< Sets the full path to a CA certificate (used to validate
							//!< the certificate the server presents).
							
	const char	*tls_cacertdir;			//!< Sets the path to a directory containing CA certificates.
	
	const char	*tls_certfile;			//!< Sets the path to the public certificate file we present
							//!< to the servers.
							
	const char	*tls_keyfile;			//!< Sets the path to the private key for our public 
							//!< certificate.
							
	const char	*tls_randfile;			//!< Path to the random file if /dev/random and /dev/urandom
							//!< are unavailable.
							
	const char	*tls_require_cert;		//!< Sets requirements for validating the certificate the 
							//!< server presents.

	/*
	 *	Options
	 */
							
	int  		net_timeout;			//!< How long we wait for new connections to the LDAP server
							//!< to be established.
	int		res_timeout;			//!< How long we wait for a result from the server.
	int		srv_timelimit;			//!< How long the server should spent on a single request
							//!< (also bounded by value on the server).

#ifdef WITH_EDIR
 	/*
	 *	eDir support
	 */
	int		edir;				//!< If true attempt to retrieve the user's Cleartext password
							//!< using the Universal Password feature of Novell eDirectory.
	int		edir_autz;			//!< If true, and we have the Universal Password, bind with it
							//!< to perform additional authorisation checks.
#endif
	/*
	 *	For keep-alives.
	 */
#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	int		keepalive_idle;			//!< Number of seconds a connections needs to remain idle
							//!< before TCP starts sending keepalive probes.
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	int		keepalive_probes;		//!< Number of missed timeouts before the connection is
							//!< dropped.
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	int		keepalive_interval;		//!< Interval between keepalive probes.
#endif

} ldap_instance_t;

typedef struct ldap_handle {
	LDAP		*handle;			//!< LDAP LD handle.
	int		rebound;			//!< Whether the connection has been rebound to something 
							//!< other than the admin user.
	int		referred;			//!< Whether the connection is now established a server 
							//!< other than the configured one.
	ldap_instance_t	*inst;				//!< rlm_ldap configuration.
} ldap_handle_t;

typedef struct rlm_ldap_map_xlat {
	const value_pair_map_t *maps;
	const char *attrs[LDAP_MAX_ATTRMAP + LDAP_MAP_RESERVED + 1]; //!< Reserve some space for access attributes
								     //!< and NULL termination.
	int count;
} rlm_ldap_map_xlat_t;

typedef struct rlm_ldap_result {
	char	**values;
	int	count;
} rlm_ldap_result_t;

typedef enum {
	LDAP_PROC_SUCCESS = 0,				//!< Operation was successfull.
	
	LDAP_PROC_ERROR	= -1,				//!< Unrecoverable library/server error.
	
	LDAP_PROC_RETRY	= -2,				//!< Transitory error, caller should retry the operation 
							//!< with a new connection.
					
	LDAP_PROC_NOT_PERMITTED = -3,			//!< Operation was not permitted, either current user was 
							//!< locked out in the case of binds, or has insufficient 
							//!< access.
					
	LDAP_PROC_REJECT = -4,				//!< Bind failed, user was rejected.
	
	LDAP_PROC_BAD_DN = -5,				//!< Specified an invalid object in a bind or search DN.
					
	LDAP_PROC_NO_RESULT = -6			//!< Got no results.
} ldap_rcode_t;

/*
 *	Some functions may be called with a NULL request structure, this
 *	simplifies switching certain messages from the request log to
 *	the main log.
 */
#define LDAP_INFO(fmt, ...) radlog(L_INFO, "rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
 
#define LDAP_DBGW(fmt, ...) radlog(L_DBG_WARN, "rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
#define LDAP_DBGW_REQ(fmt, ...) do { if (request) {RDEBUGW(fmt, ##__VA_ARGS__);} else {LDAP_DBGW(fmt, ##__VA_ARGS__);}} while (0)

#define LDAP_DBG(fmt, ...) radlog(L_DBG, "rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
#define LDAP_DBG_REQ(fmt, ...) do { if (request) {RDEBUG(fmt, ##__VA_ARGS__);} else {LDAP_DBG(fmt, ##__VA_ARGS__);}} while (0)

#define LDAP_ERR(fmt, ...) radlog(L_ERR, "rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
#define LDAP_ERR_REQ(fmt, ...) do { if (request) {RDEBUGE(fmt, ##__VA_ARGS__);} else {LDAP_ERR(fmt, ##__VA_ARGS__);}} while (0)

#define LDAP_EXT() if (extra) LDAP_ERR(extra)
#define LDAP_EXT_REQ() do { if (extra) { if (request) RDEBUGE("%s", extra); else LDAP_ERR("%s", extra); }} while (0)

/*
 *	ldap.c - Wrappers arounds OpenLDAP functions.
 */
size_t rlm_ldap_escape_func(UNUSED REQUEST *request, char *out, size_t outlen, const char *in, UNUSED void *arg);

int rlm_ldap_is_dn(const char *str);

ssize_t rlm_ldap_xlat_filter(REQUEST *request, const char **sub, size_t sublen, char *out, size_t outlen);

ldap_rcode_t rlm_ldap_bind(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn, const char *dn,
			  const char *password, int retry);
			  
ldap_rcode_t rlm_ldap_search(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn,
			     const char *dn, int scope, const char *filter, const char * const *attrs,
			     LDAPMessage **result);
			     
ldap_rcode_t rlm_ldap_modify(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn,
			     const char *dn, LDAPMod *mods[]);
			    	   
const char *rlm_ldap_find_user(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn,
			       const char *attrs[], int force, LDAPMessage **result, rlm_rcode_t *rcode);
       
rlm_rcode_t rlm_ldap_check_access(const ldap_instance_t *inst, REQUEST *request, const ldap_handle_t *conn,
				  LDAPMessage *entry);
				  
void rlm_ldap_check_reply(const ldap_instance_t *inst, REQUEST *request);

/*
 *	ldap.c - Callbacks for the connection pool API.
 */
void *mod_conn_create(void *ctx);

int mod_conn_delete(UNUSED void *ctx, void *connection);

ldap_handle_t *rlm_ldap_get_socket(const ldap_instance_t *inst, REQUEST *request);

void rlm_ldap_release_socket(const ldap_instance_t *inst, ldap_handle_t *conn);

/*
 *	groups.c - Group membership functions.
 */

rlm_rcode_t rlm_ldap_cacheable_userobj(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn,
				       LDAPMessage *entry);
				       
rlm_rcode_t rlm_ldap_cacheable_groupobj(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn);

rlm_rcode_t rlm_ldap_check_groupobj_dynamic(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn,
					    VALUE_PAIR *check);
					    
rlm_rcode_t rlm_ldap_check_userobj_dynamic(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn,
					   const char *dn, VALUE_PAIR *check);

rlm_rcode_t rlm_ldap_check_cached(const ldap_instance_t *inst, REQUEST *request, VALUE_PAIR *check);

/*
 *	attrmap.c - Attribute mapping code.
 */
int rlm_ldap_map_verify(ldap_instance_t *inst, value_pair_map_t **head);

void rlm_ldap_map_xlat_free(const rlm_ldap_map_xlat_t *expanded);

int rlm_ldap_map_xlat(REQUEST *request, const value_pair_map_t *maps, rlm_ldap_map_xlat_t *expanded);

void rlm_ldap_map_do(const ldap_instance_t *inst, REQUEST *request, LDAP *handle,
		     const rlm_ldap_map_xlat_t *expanded, LDAPMessage *entry);

rlm_rcode_t rlm_ldap_map_profile(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn,
			    	 const char *profile, const rlm_ldap_map_xlat_t *expanded);

/*
 *	edir.c - Magic extensions for Novell
 */
#ifdef WITH_EDIR
int nmasldap_get_password(LDAP *ld, const char *dn, char *password, size_t *len);
#endif

#endif
