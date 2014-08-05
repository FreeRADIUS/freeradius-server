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

/*
 *      For compatibility with other LDAP libraries
 */
#if !defined(LDAP_SCOPE_BASE) && defined(LDAP_SCOPE_BASEOBJECT)
#  define LDAP_SCOPE_BASE LDAP_SCOPE_BASEOBJECT
#endif

#if !defined(LDAP_SCOPE_ONE) && defined(LDAP_SCOPE_ONELEVEL)
#  define LDAP_SCOPE_ONE LDAP_SCOPE_ONELEVEL
#endif

#if !defined(LDAP_SCOPE_SUB) && defined(LDAP_SCOPE_SUBTREE)
#  define LDAP_SCOPE_SUB LDAP_SCOPE_SUBTREE
#endif

#if !defined(LDAP_OPT_RESULT_CODE) && defined(LDAP_OPT_ERROR_NUMBER)
#  define LDAP_OPT_RESULT_CODE LDAP_OPT_ERROR_NUMBER
#endif

#ifndef LDAP_CONST
#  define LDAP_CONST
#endif

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

typedef struct ldap_acct_section {
	CONF_SECTION	*cs;				//!< Section configuration.

	char const *reference;				//!< Configuration reference string.
} ldap_acct_section_t;

typedef struct ldap_instance {
	CONF_SECTION	*cs;				//!< Main configuration section for this instance.
	fr_connection_pool_t *pool;			//!< Connection pool instance.

	char const	*server;			//!< Initial server to bind to.
	int		is_url;				//!< Whether ldap_is_ldap_url says 'server' is an
							//!< ldap[s]:// url.
	uint16_t	port;				//!< Port to use when binding to the server.

	char const	*admin_dn;			//!< DN we bind as when we need to query the LDAP
							//!< directory.
	char const	*password;			//!< Password used in administrative bind.

	char const	*dereference_str;		//!< When to dereference (never, searching, finding, always)
	int		dereference;			//!< libldap value specifying dereferencing behaviour.

	bool		chase_referrals;		//!< If the LDAP server returns a referral to another server
							//!< or point in the tree, follow it, establishing new
							//!< connections and binding where necessary.
	bool		chase_referrals_unset;		//!< If true, use the OpenLDAP defaults for chase_referrals.

	bool		rebind;				//!< Controls whether we set an ldad_rebind_proc function
							//!< and so determines if we can bind to other servers whilst
							//!< chasing referrals. If this is false, we will still chase
							//!< referrals on the same server, but won't bind to other
							//!< servers.

	uint32_t	ldap_debug;			//!< Debug flag for the SDK.

	char const	*xlat_name;			//!< Instance name.

	bool		expect_password;		//!< True if the user_map included a mapping between an LDAP
							//!< attribute and one of our password reference attributes.

	/*
	 *	RADIUS attribute to LDAP attribute maps
	 */
	value_pair_map_t *user_map; 			//!< Attribute map applied to users and profiles.

	/*
	 *	User object attributes and filters
	 */
	char const	*userobj_filter;		//!< Filter to retrieve only user objects.
	char const	*userobj_base_dn;		//!< DN to search for users under.
	char const	*userobj_scope_str;		//!< Scope (sub, one, base).
	int		userobj_scope;			//!< Search scope.

	char const	*userobj_membership_attr;	//!< Attribute that describes groups the user is a member of.
	char const	*userobj_access_attr;		//!< Attribute to check to see if the user should be locked out.
	bool		access_positive;		//!< If true the presence of the attribute will allow access,
							//!< else it will deny access.

	char const	*valuepair_attr;		//!< Generic dynamic mapping attribute, contains a RADIUS
							//!< attribute and value.

	/*
	 *	Group object attributes and filters
	 */

	char const	*groupobj_filter;		//!< Filter to retrieve only group objects.
	char const	*groupobj_base_dn;		//!< DN to search for users under.
	char const	*groupobj_scope_str;		//!< Scope (sub, one, base).
	int		groupobj_scope;			//!< Search scope.

	char const	*groupobj_name_attr;		//!< The name of the group.
	char const	*groupobj_membership_filter;	//!< Filter to only retrieve groups which contain
							//!< the user as a member.

	bool		cacheable_group_name;		//!< If true the server will determine complete set of group
							//!< memberships for the current user object, and perform any
							//!< resolution necessary to determine the names of those
							//!< groups, then right them to the control list (LDAP-Group).

	bool		cacheable_group_dn;		//!< If true the server will determine complete set of group
							//!< memberships for the current user object, and perform any
							//!< resolution necessary to determine the DNs of those groups,
							//!< then right them to the control list (LDAP-GroupDN).

	char const	*cache_attribute;		//!< Sets the attribute we use when creating and retrieving
							//!< cached group memberships.

	DICT_ATTR const	*cache_da;			//!< The DA associated with this specific version of the
							//!< rlm_ldap module.

	DICT_ATTR const	*group_da;			//!< The DA associated with this specific version of the
							//!< rlm_ldap module.

	/*
	 *	Dynamic clients
	 */
	char const	*clientobj_filter;		//!< Filter to retrieve only client objects.
	char const	*clientobj_base_dn;		//!< DN to search for clients under.
	char const	*clientobj_scope_str;		//!< Scope (sub, one, base).
	int		clientobj_scope;		//!< Search scope.

	char const	*clientobj_identifier;		//!< IP/FQDN/IP Prefix for the NAS.
	char const	*clientobj_shortname;		//!< Short/Friendly name to assign.
	char const	*clientobj_type;		//!< Type of NAS (not usually used).
	char const	*clientobj_secret;		//!< RADIUS secret.
	char const	*clientobj_server;		//!< Virtual server to associate the client with.
	char const	*clientobj_require_ma;		//!< Require message-authenticator.

	bool		do_clients;			//!< If true, attempt to load clients on instantiation.

	/*
	 *	Profiles
	 */
	char const	*default_profile;		//!< If this is set, we will search for a profile object
							//!< with this name, and map any attributes it contains.
							//!< No value should be set if profiles are not being used
							//!< as there is an associated performance penalty.
	char const	*profile_attr;			//!< Attribute that identifies profiles to apply. May appear
							//!< in userobj or groupobj.
	char const	*profile_filter;		//!< Filter to retrieve only retrieve group objects.

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
	bool		start_tls;			//!< Send the Start TLS message to the LDAP directory
							//!< to start encrypted communications using the standard
							//!< LDAP port.

	char const	*tls_ca_file;			//!< Sets the full path to a CA certificate (used to validate
							//!< the certificate the server presents).

	char const	*tls_ca_path;			//!< Sets the path to a directory containing CA certificates.

	char const	*tls_certificate_file;		//!< Sets the path to the public certificate file we present
							//!< to the servers.

	char const	*tls_private_key_file;		//!< Sets the path to the private key for our public
							//!< certificate.

	char const	*tls_random_file;		//!< Path to the random file if /dev/random and /dev/urandom
							//!< are unavailable.

	char const	*tls_require_cert_str;		//!< Sets requirements for validating the certificate the
							//!< server presents.

	int		tls_require_cert;		//!< OpenLDAP constant representing the require cert string.

	/*
	 *	Options
	 */

	uint32_t  	net_timeout;			//!< How long we wait for new connections to the LDAP server
							//!< to be established.
	uint32_t	res_timeout;			//!< How long we wait for a result from the server.
	uint32_t	srv_timelimit;			//!< How long the server should spent on a single request
							//!< (also bounded by value on the server).

#ifdef WITH_EDIR
	/*
	 *	eDir support
	 */
	bool		edir;				//!< If true attempt to retrieve the user's cleartext password
							//!< using the Universal Password feature of Novell eDirectory.
	bool		edir_autz;			//!< If true, and we have the Universal Password, bind with it
							//!< to perform additional authorisation checks.
#endif
	/*
	 *	For keep-alives.
	 */
#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	uint32_t	keepalive_idle;			//!< Number of seconds a connections needs to remain idle
							//!< before TCP starts sending keepalive probes.
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	uint32_t	keepalive_probes;		//!< Number of missed timeouts before the connection is
							//!< dropped.
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	uint32_t	keepalive_interval;		//!< Interval between keepalive probes.
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
	value_pair_map_t const *maps;
	char const *attrs[LDAP_MAX_ATTRMAP + LDAP_MAP_RESERVED + 1]; //!< Reserve some space for access attributes
								     //!< and NULL termination.
	int count;
} rlm_ldap_map_xlat_t;

typedef struct rlm_ldap_result {
	struct berval	**values;			//!< libldap struct containing bv_val (char *)
							//!< and length bv_len.
	int		count;				//!< Number of values.
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
#define LDAP_INFO(fmt, ...) INFO("rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
#define LDAP_WARN(fmt, ...) WARN("rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)

#define LDAP_DBGW(fmt, ...) radlog(L_DBG_WARN, "rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
#define LDAP_DBGW_REQ(fmt, ...) do { if (request) {RWDEBUG(fmt, ##__VA_ARGS__);} else {LDAP_DBGW(fmt, ##__VA_ARGS__);}} while (0)

#define LDAP_DBG(fmt, ...) radlog(L_DBG, "rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
#define LDAP_DBG_REQ(fmt, ...) do { if (request) {RDEBUG(fmt, ##__VA_ARGS__);} else {LDAP_DBG(fmt, ##__VA_ARGS__);}} while (0)

#define LDAP_DBG2(fmt, ...) if (debug_flag >= L_DBG_LVL_2) radlog(L_DBG, "rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
#define LDAP_DBG_REQ2(fmt, ...) do { if (request) {RDEBUG2(fmt, ##__VA_ARGS__);} else if (debug_flag >= L_DBG_LVL_2) {LDAP_DBG(fmt, ##__VA_ARGS__);}} while (0)

#define LDAP_DBG3(fmt, ...) if (debug_flag >= L_DBG_LVL_3) radlog(L_DBG, "rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
#define LDAP_DBG_REQ3(fmt, ...) do { if (request) {RDEBUG3(fmt, ##__VA_ARGS__);} else if (debug_flag >= L_DBG_LVL_3) {LDAP_DBG(fmt, ##__VA_ARGS__);}} while (0)

#define LDAP_ERR(fmt, ...) ERROR("rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
#define LDAP_ERR_REQ(fmt, ...) do { if (request) {REDEBUG(fmt, ##__VA_ARGS__);} else {LDAP_ERR(fmt, ##__VA_ARGS__);}} while (0)

#define LDAP_EXT() if (extra) LDAP_ERR(extra)
#define LDAP_EXT_REQ() do { if (extra) { if (request) REDEBUG("%s", extra); else LDAP_ERR("%s", extra); }} while (0)

extern FR_NAME_NUMBER const ldap_scope[];
extern FR_NAME_NUMBER const ldap_tls_require_cert[];

/*
 *	ldap.c - Wrappers arounds OpenLDAP functions.
 */
size_t rlm_ldap_escape_func(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *arg);

int rlm_ldap_is_dn(char const *str);

ssize_t rlm_ldap_xlat_filter(REQUEST *request, char const **sub, size_t sublen, char *out, size_t outlen);

ldap_rcode_t rlm_ldap_bind(ldap_instance_t const *inst, REQUEST *request, ldap_handle_t **pconn, char const *dn,
			  char const *password, bool retry);

char const *rlm_ldap_error_str(ldap_handle_t const *conn);

ldap_rcode_t rlm_ldap_search(ldap_instance_t const *inst, REQUEST *request, ldap_handle_t **pconn,
			     char const *dn, int scope, char const *filter, char const * const *attrs,
			     LDAPMessage **result);

ldap_rcode_t rlm_ldap_modify(ldap_instance_t const *inst, REQUEST *request, ldap_handle_t **pconn,
			     char const *dn, LDAPMod *mods[]);

char const *rlm_ldap_find_user(ldap_instance_t const *inst, REQUEST *request, ldap_handle_t **pconn,
			       char const *attrs[], bool force, LDAPMessage **result, rlm_rcode_t *rcode);

rlm_rcode_t rlm_ldap_check_access(ldap_instance_t const *inst, REQUEST *request, ldap_handle_t const *conn,
				  LDAPMessage *entry);

void rlm_ldap_check_reply(ldap_instance_t const *inst, REQUEST *request);

/*
 *	ldap.c - Callbacks for the connection pool API.
 */
void *mod_conn_create(TALLOC_CTX *ctx, void *instance);

ldap_handle_t *rlm_ldap_get_socket(ldap_instance_t const *inst, REQUEST *request);

void rlm_ldap_release_socket(ldap_instance_t const *inst, ldap_handle_t *conn);

/*
 *	groups.c - Group membership functions.
 */

rlm_rcode_t rlm_ldap_cacheable_userobj(ldap_instance_t const *inst, REQUEST *request, ldap_handle_t **pconn,
				       LDAPMessage *entry, char const *attr);

rlm_rcode_t rlm_ldap_cacheable_groupobj(ldap_instance_t const *inst, REQUEST *request, ldap_handle_t **pconn);

rlm_rcode_t rlm_ldap_check_groupobj_dynamic(ldap_instance_t const *inst, REQUEST *request, ldap_handle_t **pconn,
					    VALUE_PAIR *check);

rlm_rcode_t rlm_ldap_check_userobj_dynamic(ldap_instance_t const *inst, REQUEST *request, ldap_handle_t **pconn,
					   char const *dn, VALUE_PAIR *check);

rlm_rcode_t rlm_ldap_check_cached(ldap_instance_t const *inst, REQUEST *request, VALUE_PAIR *check);

/*
 *	attrmap.c - Attribute mapping code.
 */
int rlm_ldap_map_verify(ldap_instance_t *inst, value_pair_map_t **head);

void rlm_ldap_map_xlat_free(rlm_ldap_map_xlat_t const *expanded);

int rlm_ldap_map_xlat(REQUEST *request, value_pair_map_t const *maps, rlm_ldap_map_xlat_t *expanded);

void rlm_ldap_map_do(ldap_instance_t const *inst, REQUEST *request, LDAP *handle,
		     rlm_ldap_map_xlat_t const *expanded, LDAPMessage *entry);

rlm_rcode_t rlm_ldap_map_profile(ldap_instance_t const *inst, REQUEST *request, ldap_handle_t **pconn,
				 char const *profile, rlm_ldap_map_xlat_t const *expanded);

/*
 *	clients.c - Dynamic clients (bulk load).
 */
int  rlm_ldap_load_clients(ldap_instance_t const *inst);

/*
 *	edir.c - Magic extensions for Novell
 */
int nmasldap_get_password(LDAP *ld, char const *dn, char *password, size_t *len);

char const *edir_errstr(int code);

#endif
