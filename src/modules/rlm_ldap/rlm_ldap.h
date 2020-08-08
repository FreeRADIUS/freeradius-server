#pragma once
/**
 * $Id$
 * @file rlm_ldap.h
 * @brief LDAP authorization and authentication module headers.
 *
 * @note Do not rename to ldap.h.  This causes configure checks to break
 *	in stupid ways, where the configure script will use the local ldap.h
 *	file, instead of the one from libldap.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2013-2015 The FreeRADIUS Server Project.
 */
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/ldap/base.h>

typedef struct ldap_inst_s rlm_ldap_t;

typedef struct {
	tmpl_t	*mech;				//!< SASL mech(s) to try.
	tmpl_t	*proxy;				//!< Identity to proxy.
	tmpl_t	*realm;				//!< Kerberos realm.
} fr_ldap_sasl_t_dynamic_t;

typedef struct {
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
	tmpl_t	*userobj_filter;		//!< Filter to retrieve only user objects.
	tmpl_t	*userobj_base_dn;		//!< DN to search for users under.
	char const	*userobj_scope_str;		//!< Scope (sub, one, base).
	char const	*userobj_sort_by;		//!< List of attributes to sort by.
	LDAPControl	*userobj_sort_ctrl;		//!< Server side sort control.

	int		userobj_scope;			//!< Search scope.

	char const	*userobj_membership_attr;	//!< Attribute that describes groups the user is a member of.
	char const	*userobj_access_attr;		//!< Attribute to check to see if the user should be locked out.
	bool		access_positive;		//!< If true the presence of the attribute will allow access,
							//!< else it will deny access.

	fr_ldap_sasl_t_dynamic_t user_sasl;			//!< SASL parameters used when binding as the user.

	char const	*valuepair_attr;		//!< Generic dynamic mapping attribute, contains a RADIUS
							//!< attribute and value.


	/*
	 *	Group object attributes and filters
	 */
	char const	*groupobj_filter;		//!< Filter to retrieve only group objects.
	tmpl_t	*groupobj_base_dn;		//!< DN to search for users under.
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

	bool		allow_dangling_group_refs;	//!< Don't error if we fail to resolve a group DN referenced
														///< from a user object.

	/*
	 *	Profiles
	 */
	tmpl_t	*default_profile;		//!< If this is set, we will search for a profile object
							//!< with this name, and map any attributes it contains.
							//!< No value should be set if profiles are not being used
							//!< as there is an associated performance penalty.
	char const	*profile_attr;			//!< Attribute that identifies profiles to apply. May appear
							//!< in userobj or groupobj.
	tmpl_t	*profile_filter;		//!< Filter to retrieve only retrieve group objects.

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

	fr_pool_t	*pool;				//!< Connection pool instance.
	fr_ldap_config_t handle_config;			//!< Connection configuration instance.

	/*
	 *	Global config
	 */
	char const	*tls_random_file;		//!< Path to the random file if /dev/random and /dev/urandom
							//!< are unavailable.

	uint32_t	ldap_debug;			//!< Debug flag for the SDK.
};

extern fr_dict_attr_t const *attr_cleartext_password;
extern fr_dict_attr_t const *attr_crypt_password;
extern fr_dict_attr_t const *attr_ldap_userdn;
extern fr_dict_attr_t const *attr_nt_password;
extern fr_dict_attr_t const *attr_password_with_header;

extern fr_dict_attr_t const *attr_user_password;
extern fr_dict_attr_t const *attr_user_name;

/*
 *	user.c - User lookup functions
 */
char const *rlm_ldap_find_user(rlm_ldap_t const *inst, REQUEST *request, fr_ldap_connection_t **pconn,
			       char const *attrs[], bool force, LDAPMessage **result, rlm_rcode_t *rcode);

rlm_rcode_t rlm_ldap_check_access(rlm_ldap_t const *inst, REQUEST *request,
				  fr_ldap_connection_t const *conn, LDAPMessage *entry);

void rlm_ldap_check_reply(rlm_ldap_t const *inst, REQUEST *request, fr_ldap_connection_t const *conn);

/*
 *	groups.c - Group membership functions.
 */
rlm_rcode_t rlm_ldap_cacheable_userobj(rlm_ldap_t const *inst, REQUEST *request, fr_ldap_connection_t **pconn,
				       LDAPMessage *entry, char const *attr);

rlm_rcode_t rlm_ldap_cacheable_groupobj(rlm_ldap_t const *inst, REQUEST *request, fr_ldap_connection_t **pconn);

rlm_rcode_t rlm_ldap_check_groupobj_dynamic(rlm_ldap_t const *inst, REQUEST *request, fr_ldap_connection_t **pconn,
					    VALUE_PAIR *check);

rlm_rcode_t rlm_ldap_check_userobj_dynamic(rlm_ldap_t const *inst, REQUEST *request, fr_ldap_connection_t **pconn,
					   char const *dn, VALUE_PAIR *check);

rlm_rcode_t rlm_ldap_check_cached(rlm_ldap_t const *inst, REQUEST *request, VALUE_PAIR *check);

/*
 *	conn.c - Connection wrappers.
 */
fr_ldap_connection_t	*mod_conn_get(rlm_ldap_t const *inst, REQUEST *request);

void		ldap_mod_conn_release(rlm_ldap_t const *inst, REQUEST *request, fr_ldap_connection_t *conn);

void		*ldap_mod_conn_create(TALLOC_CTX *ctx, void *instance, fr_time_delta_t timeout);
