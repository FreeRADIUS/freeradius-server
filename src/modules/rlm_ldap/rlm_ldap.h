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
 * @copyright 2013 Network RADIUS SAS (legal@networkradius.com)
 * @copyright 2013-2015 The FreeRADIUS Server Project.
 */
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/ldap/base.h>

typedef struct {
	/*
	 *	Options
	 */
#ifdef LDAP_CONTROL_X_SESSION_TRACKING
	bool		session_tracking;		//!< Whether we add session tracking controls, which help
							//!< identify the autz or acct session the commands were
							//!< issued for.
#endif
	struct {
		/*
		 *	User object attributes and filters
		 */
		char const	*obj_sort_by;			//!< List of attributes to sort by.
		LDAPControl	*obj_sort_ctrl;			//!< Server side sort control.

		int		obj_scope;			//!< Search scope.

		char const	*obj_access_attr;		//!< Attribute to check to see if the user should be locked out.
		bool		access_positive;		//!< If true the presence of the attribute will allow access,
								//!< else it will deny access.

		char const	*access_value_negate;           //!< If the value of the access_attr matches this, the result
								///< will be negated.
		char const	*access_value_suspend;          //!< Value that indicates suspension.  Is not affected by
								///< access_positive and will always allow access, but will apply
								///< a different profile.
		bool		expect_password;		//!< Allow the user to forcefully decide if a password should be
								///< expected.  Controls whether warnings are issued.
		bool		expect_password_is_set;		//!< Whether an expect password value was provided.

		char const	*dn_attr_str;			//!< Sets the attribute we use when creating and retrieving
								//!< cached group memberships.

		fr_dict_attr_t const *da;			//!< The DA associated with this specific instance of the
								//!< rlm_ldap module for caching user DNs between autz and
								///< auth phases.
	} user;

	/*
	 *	Group object attributes and filters
	 */
	struct {
		char const	*userobj_membership_attr;	//!< Attribute that describes groups the user is a member of.

		char const	*obj_filter;			//!< Filter to retrieve only group objects.
		int		obj_scope;			//!< Search scope.

		char const	*obj_name_attr;			//!< The name of the group.
		char const	*obj_membership_filter;		//!< Filter to only retrieve groups which contain
								//!< the user as a member.

		bool		cacheable_name;			//!< If true the server will determine complete set of group
								//!< memberships for the current user object, and perform any
								//!< resolution necessary to determine the names of those
								//!< groups, then right them to the control list (LDAP-Group).

		bool		cacheable_dn;			//!< If true the server will determine complete set of group
								//!< memberships for the current user object, and perform any
								//!< resolution necessary to determine the DNs of those groups,
								//!< then right them to the control list (LDAP-GroupDN).

		char const	*cache_attr_str;		//!< Sets the attribute we use when creating and retrieving
								//!< cached group memberships.

		fr_dict_attr_t const	*cache_da;		//!< The DA associated with this specific instance of the
								//!< rlm_ldap module.

		char const	*attribute;			//!< Sets the attribute we use when comparing group
								//!< group memberships.

		fr_dict_attr_t const	*da;			//!< The DA associated with this specific instance of the
								//!< rlm_ldap module.

		bool		allow_dangling_refs;		//!< Don't error if we fail to resolve a group DN referenced
								///< from a user object.

		bool		skip_on_suspend;		//!< Don't process groups if the user is suspended.
	} group;

	char const	*valuepair_attr;		//!< Generic dynamic mapping attribute, contains a RADIUS
							//!< attribute and value.

	/*
	 *	Profiles
	 */
	struct {
		int		obj_scope;			//!< Search scope.
		char const	*attr;				//!< Attribute that identifies profiles to apply. May appear
								//!< in userobj or groupobj.
		char const	*attr_suspend;			//!< Attribute that identifies profiles to apply when the user's
								///< account is suspended. May appear in userobj or groupobj.
		char const	*obj_sort_by;			//!< List of attributes to sort profiles by
		LDAPControl	*obj_sort_ctrl;			//!< Server side sort control
		char const	*check_attr;			//!< LDAP attribute containing check conditions to determine if
								//!< the profile should be applied
		char const	*fallthrough_attr;		//!< LDAP attribute containing conditions to determine if
								///< processing should continue to the next profile when more
								///< than one is returned.
		bool		fallthrough_def;		//!< Should profile processing fall through by default.
	} profile;

#ifdef WITH_EDIR
	/*
	 *	eDir support
	 */
	bool		edir;				//!< If true attempt to retrieve the user's cleartext password
							//!< using the Universal Password feature of Novell eDirectory.
	bool		edir_autz;			//!< If true, and we have the Universal Password, bind with it
							//!< to perform additional authorisation checks.
#endif

	fr_ldap_config_t handle_config;			//!< Connection configuration instance.
	trunk_conf_t	trunk_conf;			//!< Trunk configuration
	trunk_conf_t	bind_trunk_conf;		//!< Trunk configuration for trunk used for bind auths

	module_instance_t const *mi;			//!< Module instance data for thread lookups.

	fr_pair_list_t	*trigger_args;			//!< Pairs passed to trigger request for standard trunk.
	fr_pair_list_t	*bind_trigger_args;		//!< Pairs passed to trigger request for bind trunk.
} rlm_ldap_t;

/** Call environment used in LDAP authorization
 *
 */
typedef struct {
	fr_value_box_t	user_base;			//!< Base DN in which to search for users.
	fr_value_box_t	user_filter;			//!< Filter to use when searching for users.
	fr_value_box_t 	group_base;			//!< Base DN in which to search for groups.
	tmpl_t		*group_filter;			//!< tmpl to expand as group membership filter.
	fr_value_box_t	default_profile;		//!< If this is set, we will search for a profile object
							//!< with this name, and map any attributes it contains.
							//!< No value should be set if profiles are not being used
							//!< as there is an associated performance penalty.
	fr_value_box_t	profile_filter;			//!< Filter to use when searching for profiles.

	map_list_t	*user_map;			//!< Attribute map applied to users and profiles.

	fr_value_box_t 	const *expect_password;		//!< True if the user_map included a mapping between an LDAP
							//!< attribute and one of our password reference attributes.
} ldap_autz_call_env_t;

/** Call environment used in group membership xlat
 *
 */
typedef struct {
	fr_value_box_t	user_base;			//!< Base DN in which to search for users.
	fr_value_box_t	user_filter;			//!< Filter to use when searching for users.
	fr_value_box_t	group_base;			//!< Base DN in which to search for groups.
	tmpl_t		*group_filter;			//!< tmpl to expand as group membership filter.
} ldap_xlat_memberof_call_env_t;

/** State list for resumption of authorization
 *
 */
typedef enum {
	LDAP_AUTZ_FIND = 0,
	LDAP_AUTZ_GROUP,
	LDAP_AUTZ_POST_GROUP,
#ifdef WITH_EDIR
	LDAP_AUTZ_EDIR_BIND,
	LDAP_AUTZ_POST_EDIR,
#endif
	LDAP_AUTZ_MAP,
	LDAP_AUTZ_DEFAULT_PROFILE,
	LDAP_AUTZ_POST_DEFAULT_PROFILE,
	LDAP_AUTZ_USER_PROFILE,
} ldap_autz_status_t;

/** User's access state
 *
 */
typedef enum {
	LDAP_ACCESS_ALLOWED = 0,			//!< User is allowed to login.
	LDAP_ACCESS_DISALLOWED,				//!< User it not allow to login (disabled)
	LDAP_ACCESS_SUSPENDED				//!< User account has been suspended.
} ldap_access_state_t;

/** Holds state of in progress async authorization
 *
 */
typedef struct {
	module_instance_t const	*dlinst;
	rlm_ldap_t const	*inst;
	fr_ldap_map_exp_t	expanded;
	fr_ldap_query_t		*query;
	fr_ldap_thread_trunk_t	*ttrunk;
	ldap_autz_call_env_t	*call_env;
	LDAPMessage		*entry;
	ldap_autz_status_t	status;
	struct berval		**profile_values;
	int			value_idx;
	char			*profile_value;
	char const		*dn;
	ldap_access_state_t	access_state;		//!< What state a user's account is in.
	rlm_rcode_t		rcode;			//!< What rcode we'll finally respond with.
} ldap_autz_ctx_t;

/** State list for xlat evaluation of LDAP group membership
 */
typedef enum {
	GROUP_XLAT_FIND_USER = 0,
	GROUP_XLAT_MEMB_FILTER,
	GROUP_XLAT_MEMB_ATTR
} ldap_group_xlat_status_t;

/** Holds state of in progress group membership check xlat
 *
 */
typedef struct {
	rlm_ldap_t const		*inst;
	fr_value_box_t			*group;
	ldap_xlat_memberof_call_env_t	*env_data;
	bool				group_is_dn;
	char const			*dn;
	char const			*attrs[2];
	fr_value_box_t			*filter;
	fr_value_box_t			*basedn;
	fr_ldap_thread_trunk_t		*ttrunk;
	fr_ldap_query_t			*query;
	ldap_group_xlat_status_t	status;
	unlang_result_t			result;
	bool				found;
} ldap_group_xlat_ctx_t;

extern HIDDEN fr_dict_attr_t const *attr_password;
extern HIDDEN fr_dict_attr_t const *attr_cleartext_password;
extern HIDDEN fr_dict_attr_t const *attr_crypt_password;
extern HIDDEN fr_dict_attr_t const *attr_nt_password;
extern HIDDEN fr_dict_attr_t const *attr_password_with_header;

extern HIDDEN fr_dict_attr_t const *attr_user_password;
extern HIDDEN fr_dict_attr_t const *attr_user_name;

/*
 *	user.c - User lookup functions
 */
static inline char const *rlm_find_user_dn_cached(rlm_ldap_t const *inst, request_t *request)
{
	fr_pair_t	*vp;

	vp = fr_pair_find_by_da(&request->control_pairs, NULL, inst->user.da);
	if (!vp) return NULL;

	RDEBUG2("Using user DN from request \"%pV\"", &vp->data);
	return vp->vp_strvalue;
}

unlang_action_t rlm_ldap_find_user_async(TALLOC_CTX *ctx,
					 unlang_result_t *p_result,
					 rlm_ldap_t const *inst, request_t *request,
					 fr_value_box_t *base, fr_value_box_t *filter_box,
					 fr_ldap_thread_trunk_t *ttrunk, char const *attrs[],
					 fr_ldap_query_t **query_out);

ldap_access_state_t rlm_ldap_check_access(rlm_ldap_t const *inst, request_t *request, LDAPMessage *entry);

void rlm_ldap_check_reply(request_t *request, rlm_ldap_t const *inst, char const *inst_name, bool expect_password, fr_ldap_thread_trunk_t const *ttrunk);

/*
 *	groups.c - Group membership functions.
 */
unlang_action_t rlm_ldap_cacheable_userobj(unlang_result_t *p_result, request_t *request, ldap_autz_ctx_t *autz_ctx,
					   char const *attr);

unlang_action_t rlm_ldap_cacheable_groupobj(unlang_result_t *p_result, request_t *request, ldap_autz_ctx_t *autz_ctx);

unlang_action_t rlm_ldap_check_groupobj_dynamic(unlang_result_t *p_result, request_t *request,
						ldap_group_xlat_ctx_t *xlat_ctx);

unlang_action_t rlm_ldap_check_userobj_dynamic(unlang_result_t *p_result, request_t *request,
					       ldap_group_xlat_ctx_t *xlat_ctx);

unlang_action_t rlm_ldap_check_cached(unlang_result_t *p_result,
				      rlm_ldap_t const *inst, request_t *request, fr_value_box_t const *check);

unlang_action_t rlm_ldap_map_profile(fr_ldap_result_code_t *ret, int *applied,
				     rlm_ldap_t const *inst, request_t *request, fr_ldap_thread_trunk_t *ttrunk,
				     char const *dn, int scope, char const *filter, fr_ldap_map_exp_t const *expanded);
