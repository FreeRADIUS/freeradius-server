/**
 * $Id$
 * @file rlm_ldap.h
 * @brief LDAP authorization and authentication module headers.
 *
 * @note Do not rename to ldap.h.  This causes configure checks to break
 *	in stupid ways, where the configure script will use the local ldap.h
 *	file, instead of the one from libldap.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 Network RADIUS SARL<info@networkradius.com>
 * @copyright 2013-2015 The FreeRADIUS Server Project.
 */
#ifndef _RLM_LDAP_H
#define _RLM_LDAP_H

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include "libldap.h"

typedef struct ldap_inst_s rlm_ldap_t;

typedef struct {
	vp_tmpl_t	*mech;				//!< SASL mech(s) to try.
	vp_tmpl_t	*proxy;				//!< Identity to proxy.
	vp_tmpl_t	*realm;				//!< Kerberos realm.
} ldap_sasl_dynamic_t;

typedef struct ldap_acct_section {
	CONF_SECTION	*cs;				//!< Section configuration.

	char const	*reference;			//!< Configuration reference string.
} ldap_acct_section_t;

struct ldap_inst_s {
	char const	*name;				//!< Instance name.

	CONF_SECTION	*cs;				//!< Main configuration section for this instance.

	bool		expect_password;		//!< True if the user_map included a mapping between an LDAP
							//!< attribute and one of our password reference attributes.

	/*
	 *	RADIUS attribute to LDAP attribute maps
	 */
	vp_map_t	*user_map; 			//!< Attribute map applied to users and profiles.

	/*
	 *	Options
	 */
#ifdef LDAP_CONTROL_X_SESSION_TRACKING
	bool		session_tracking;		//!< Whether we add session tracking controls, which help
							//!< identify the autz or acct session the commands were
							//!< issued for.
#endif

	/*
	 *	User object attributes and filters
	 */
	vp_tmpl_t	*userobj_filter;		//!< Filter to retrieve only user objects.
	vp_tmpl_t	*userobj_base_dn;		//!< DN to search for users under.
	char const	*userobj_scope_str;		//!< Scope (sub, one, base).
	char const	*userobj_sort_by;		//!< List of attributes to sort by.
	LDAPControl	*userobj_sort_ctrl;		//!< Server side sort control.

	int		userobj_scope;			//!< Search scope.

	char const	*userobj_membership_attr;	//!< Attribute that describes groups the user is a member of.
	char const	*userobj_access_attr;		//!< Attribute to check to see if the user should be locked out.
	bool		access_positive;		//!< If true the presence of the attribute will allow access,
							//!< else it will deny access.

	ldap_sasl_dynamic_t user_sasl;			//!< SASL parameters used when binding as the user.

	char const	*valuepair_attr;		//!< Generic dynamic mapping attribute, contains a RADIUS
							//!< attribute and value.


	/*
	 *	Group object attributes and filters
	 */
	char const	*groupobj_filter;		//!< Filter to retrieve only group objects.
	vp_tmpl_t	*groupobj_base_dn;		//!< DN to search for users under.
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

	fr_dict_attr_t const	*cache_da;		//!< The DA associated with this specific instance of the
							//!< rlm_ldap module.

	char const	*group_attribute;		//!< Sets the attribute we use when comparing group
							//!< group memberships.

	fr_dict_attr_t const	*group_da;		//!< The DA associated with this specific instance of the
							//!< rlm_ldap module.

	/*
	 *	Dynamic clients
	 */
	char const	*clientobj_filter;		//!< Filter to retrieve only client objects.
	char const	*clientobj_base_dn;		//!< DN to search for clients under.
	char const	*clientobj_scope_str;		//!< Scope (sub, one, base).
	int		clientobj_scope;		//!< Search scope.

	bool		do_clients;			//!< If true, attempt to load clients on instantiation.

	/*
	 *	Profiles
	 */
	vp_tmpl_t	*default_profile;		//!< If this is set, we will search for a profile object
							//!< with this name, and map any attributes it contains.
							//!< No value should be set if profiles are not being used
							//!< as there is an associated performance penalty.
	char const	*profile_attr;			//!< Attribute that identifies profiles to apply. May appear
							//!< in userobj or groupobj.
	vp_tmpl_t	*profile_filter;		//!< Filter to retrieve only retrieve group objects.

	/*
	 *	Accounting
	 */
	ldap_acct_section_t *postauth;			//!< Modify mappings for post-auth.
	ldap_acct_section_t *accounting;		//!< Modify mappings for accounting.

#ifdef WITH_EDIR
	/*
	 *	eDir support
	 */
	bool		edir;				//!< If true attempt to retrieve the user's cleartext password
							//!< using the Universal Password feature of Novell eDirectory.
	bool		edir_autz;			//!< If true, and we have the Universal Password, bind with it
							//!< to perform additional authorisation checks.
#endif

	fr_connection_pool_t *pool;			//!< Connection pool instance.
	ldap_handle_config_t handle_config;			//!< Connection configuration instance.

	/*
	 *	Global config
	 */
	char const	*tls_random_file;		//!< Path to the random file if /dev/random and /dev/urandom
							//!< are unavailable.

	uint32_t	ldap_debug;			//!< Debug flag for the SDK.
};

/** Result of expanding the RHS of a set of maps
 *
 * Used to store the array of attributes we'll be querying for.
 */
typedef struct rlm_ldap_map_exp {
	vp_map_t const *maps;				//!< Head of list of maps we expanded the RHS of.
	char const	*attrs[LDAP_MAX_ATTRMAP + LDAP_MAP_RESERVED + 1]; //!< Reserve some space for access attributes
							//!< and NULL termination.
	TALLOC_CTX	*ctx;				//!< Context to allocate new attributes in.
	int		count;				//!< Index on next free element.
} rlm_ldap_map_exp_t;

/*
 *	user.c - User lookup functions
 */
char const *rlm_ldap_find_user(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t **pconn,
			       char const *attrs[], bool force, LDAPMessage **result, rlm_rcode_t *rcode);

rlm_rcode_t rlm_ldap_check_access(rlm_ldap_t const *inst, REQUEST *request,
				  ldap_handle_t const *conn, LDAPMessage *entry);

void rlm_ldap_check_reply(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t const *conn);

/*
 *	groups.c - Group membership functions.
 */
rlm_rcode_t rlm_ldap_cacheable_userobj(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t **pconn,
				       LDAPMessage *entry, char const *attr);

rlm_rcode_t rlm_ldap_cacheable_groupobj(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t **pconn);

rlm_rcode_t rlm_ldap_check_groupobj_dynamic(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t **pconn,
					    VALUE_PAIR *check);

rlm_rcode_t rlm_ldap_check_userobj_dynamic(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t **pconn,
					   char const *dn, VALUE_PAIR *check);

rlm_rcode_t rlm_ldap_check_cached(rlm_ldap_t const *inst, REQUEST *request, VALUE_PAIR *check);

/*
 *	conn.c - Connection wrappers.
 */
ldap_handle_t	*mod_conn_get(rlm_ldap_t const *inst, REQUEST *request);

void		mod_conn_release(rlm_ldap_t const *inst, REQUEST *request, ldap_handle_t *conn);

void		*mod_conn_create(TALLOC_CTX *ctx, void *instance, struct timeval const *timeout);

/*
 *	attrmap.c - Attribute mapping code.
 */
int rlm_ldap_map_getvalue(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, vp_map_t const *map, void *uctx);

int rlm_ldap_map_verify(vp_map_t *map, void *instance);

int rlm_ldap_map_expand(rlm_ldap_map_exp_t *expanded, REQUEST *request, vp_map_t const *maps);

int rlm_ldap_map_do(rlm_ldap_t const *inst, REQUEST *request, LDAP *handle,
		    rlm_ldap_map_exp_t const *expanded, LDAPMessage *entry);

/*
 *	clients.c - Dynamic clients (bulk load).
 */
int  rlm_ldap_client_load(rlm_ldap_t const *inst, CONF_SECTION *tmpl, CONF_SECTION *cs);

/*
 *	edir.c - Magic extensions for Novell
 */
int nmasldap_get_password(LDAP *ld, char const *dn, char *password, size_t *len);

char const *edir_errstr(int code);

#endif
