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

#define LDAP_MAX_ATTRMAP	128
#define LDAP_MAP_RESERVED	3

#define LDAP_MAX_ATTR_STR_LEN	256
#define LDAP_MAX_FILTER_STR_LEN	1024

/*
 *	The default setting for TLS Certificate Verification
 */
#define TLS_DEFAULT_VERIFY "allow"

typedef struct ldap_acct_section {
	CONF_SECTION	*cs;
	
	const char *reference;
} ldap_acct_section_t;

typedef struct ldap_instance {
	CONF_SECTION	*cs;
	fr_connection_pool_t *pool;

	char		*server;
	int		port;

	char		*login;
	char		*password;

	char		*basedn;

	int		chase_referrals;
	int		rebind;

	int		ldap_debug;		//!< Debug flag for the SDK.

	const char	*xlat_name;		//!< Instance name.

	int		expect_password;
	
	/*
	 *	RADIUS attribute to LDAP attribute maps
	 */
	value_pair_map_t *user_map; 		//!< Attribute map applied 
						//!< to users and profiles.
	
	/*
	 *	User object attributes and filters
	 */
	const char	*userobj_filter;	//!< Filter to retrieve only
						//!< user objects.
	const char	*userobj_membership_attr;	//!< Attribute that
							//!< describes groups
							//!< the user is a
							//!< member of.
	char		*userobj_access_attr;	//!< Attribute to check to see
						//!< if the user should be 
						//!< locked out.
	int		access_positive;	//!< If true the presence of 
						//!< the attribute will allow
						//!< access, else it will
						//!< deny access.

	/*
	 *	Group object attributes and filters
	 */
	const char	*groupobj_name_attr;	//!< The name of the group.
	const char	*groupobj_membership_filter;	//!< Filter to only
							//!< retrieve groups
							//!< which contain
							//!< the user as a 
							//!< member.
	
	/*
	 *	Profiles
	 */
	const char	*base_filter;		//!< Base filter combined with
						//!< all other filters.
	const char	*default_profile;
	const char	*profile_attr;
	

	/*
	 *	Accounting
	 */
	ldap_acct_section_t *postauth;
	ldap_acct_section_t *accounting;

	/*
	 *	TLS items.  We should really normalize these with the
	 *	TLS code in 3.0.
	 */
	int		tls_mode;
	int		start_tls;
	char		*tls_cacertfile;
	char		*tls_cacertdir;
	char		*tls_certfile;
	char		*tls_keyfile;
	char		*tls_randfile;
	char		*tls_require_cert;

	/*
	 *	Options
	 */
	int		timelimit;
	int  		net_timeout;
	int		timeout;
	int		is_url;

#ifdef WITH_EDIR
 	/*
	 *	eDir support
	 */
	int		edir;
	int		edir_autz;
#endif
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

} ldap_instance_t;

typedef struct ldap_handle {
	LDAP		*handle;	//!< LDAP LD handle.
	int		rebound;	//!< Whether the connection has been rebound to something other than the admin
					//!< user.
	int		referred;	//!< Whether the connection is now established a server other than the
					//!< configured one.
	ldap_instance_t	*inst;		//!< rlm_ldap configuration.
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
	LDAP_PROC_SUCCESS = 0,		//!< Operation was successfull.
	LDAP_PROC_ERROR	= -1,		//!< Unrecoverable library/server error.
	LDAP_PROC_RETRY	= -2,		//!< Transitory error, caller should
					//!< retry the operation with a new
					//!< connection.
	LDAP_PROC_NOT_PERMITTED = -3,	//!< Operation was not permitted, 
					//!< either current user was locked out
					//!< in the case of binds, or has
					//!< insufficient access.
	LDAP_PROC_REJECT = -4,		//!< Bind failed, user was rejected.
	LDAP_PROC_BAD_DN = -5,		//!< Specified an invalid object in a
					//!< bind or search DN.
	LDAP_PROC_NO_RESULT = -6	//!< Got no results.
} ldap_rcode_t;

/*
 *	Some functions may be called with a NULL request structure, this
 *	simplifies switching certain messages from the request log to
 *	the main log.
 */
#define LDAP_INFO(fmt, ...) radlog(L_INFO, "rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
 
#define LDAP_DBGW(fmt, ...) radlog(L_DBG_WARN, "rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
#define LDAP_DBGW_REQ(fmt, ...) do { if (request) {RDEBUGW(fmt, ##__VA_ARGS__);} else {LDAP_DBGW(fmt, ##__VA_ARGS__);}} while (0)

#define LDAP_ERR(fmt, ...) radlog(L_ERR, "rlm_ldap (%s): " fmt, inst->xlat_name, ##__VA_ARGS__)
#define LDAP_ERR_REQ(fmt, ...) do { if (request) {RDEBUGE(fmt, ##__VA_ARGS__);} else {LDAP_ERR(fmt, ##__VA_ARGS__);}} while (0)

#define LDAP_EXT() if (extra) LDAP_ERR(extra)
#define LDAP_EXT_REQ() do { if (extra) { if (request) RDEBUGE("%s", extra); else LDAP_ERR("%s", extra); }} while (0)

/*
 *	ldap.c - Wrappers arounds OpenLDAP functions.
 */
size_t rlm_ldap_escape_func(UNUSED REQUEST *request, char *out, size_t outlen, const char *in, UNUSED void *arg);

int rlm_ldap_is_dn(const char *str);

rlm_rcode_t rlm_ldap_bind(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn, const char *dn,
			  const char *password, int retry);
			  
ldap_rcode_t rlm_ldap_search(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn,
			     const char *dn, int scope, const char *filter, const char * const *attrs,
			     LDAPMessage **result);
			     
ldap_rcode_t rlm_ldap_modify(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn,
			     const char *dn, LDAPMod *mods[]);

rlm_rcode_t rlm_ldap_apply_profile(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn,
			    	   const char *profile, const rlm_ldap_map_xlat_t *expanded);
			    	   
const char *rlm_ldap_find_user(const ldap_instance_t *inst, REQUEST *request, ldap_handle_t **pconn,
			       const char *attrs[], int force, LDAPMessage **result, rlm_rcode_t *rcode);
			       
rlm_rcode_t rlm_ldap_check_access(const ldap_instance_t *inst, REQUEST *request, const ldap_handle_t *conn,
				  LDAPMessage *entry);
				  
void rlm_ldap_check_reply(const ldap_instance_t *inst, REQUEST *request);

/*
 *	ldap.c - Callbacks for the connection pool API.
 */
void *rlm_ldap_conn_create(void *ctx);

int rlm_ldap_conn_delete(UNUSED void *ctx, void *connection);

ldap_handle_t *rlm_ldap_get_socket(const ldap_instance_t *inst, REQUEST *request);

void rlm_ldap_release_socket(const ldap_instance_t *inst, ldap_handle_t *conn);

/*
 *	attrmap.c - Attribute mapping code.
 */
int rlm_ldap_map_verify(ldap_instance_t *inst, value_pair_map_t **head);

void rlm_ldap_map_xlat_free(const rlm_ldap_map_xlat_t *expanded);

int rlm_ldap_map_xlat(REQUEST *request, const value_pair_map_t *maps, rlm_ldap_map_xlat_t *expanded);

void rlm_ldap_map_do(const ldap_instance_t *inst, REQUEST *request, LDAP *handle,
		     const rlm_ldap_map_xlat_t *expanded, LDAPMessage *entry);

/*
 *	edir.c - Magic extensions for Novell
 */
#ifdef WITH_EDIR
int nmasldap_get_password(LDAP *ld, const char *dn, char *password, size_t *len);
#endif

#endif
