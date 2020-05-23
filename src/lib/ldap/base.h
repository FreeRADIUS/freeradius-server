#pragma once
/**
 * $Id$
 * @file lib/ldap/base.h
 * @brief Common utility functions for interacting with LDAP directories
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2017 The FreeRADIUS Server Project.
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/server/map.h>

#define LDAP_DEPRECATED 0	/* Quiet warnings about LDAP_DEPRECATED not being defined */

#include <lber.h>
#include <ldap.h>
#include "config.h"

extern LDAP *ldap_global_handle;

/*
 *	Framework on OSX doesn't export the symbols but leaves
 *	the macro defined *sigh*.
 */
#ifndef HAVE_LDAP_CREATE_SESSION_TRACKING_CONTROL
#  undef LDAP_CONTROL_X_SESSION_TRACKING
#endif

/*
 *	There's a typo in libldap's ldap.h which was fixed by
 *	Howard Chu in 19aeb1cd. This typo had the function defined
 *	as ldap_create_session_tracking_control but declared as
 *	ldap_create_session_tracking.
 *
 *	We fix this, by adding the correct declaration here.
 */
#ifdef LDAP_CONTROL_X_SESSION_TRACKING
#  if !defined(HAVE_DECL_LDAP_CREATE_SESSION_TRACKING_CONTROL) || (HAVE_DECL_LDAP_CREATE_SESSION_TRACKING_CONTROL == 0)
LDAP_F( int )
ldap_create_session_tracking_control LDAP_P((
        LDAP            *ld,
        char            *sessionSourceIp,
        char            *sessionSourceName,
        char            *formatOID,
        struct berval   *sessionTrackingIdentifier,
        LDAPControl     **ctrlp ));
#  endif
#endif

/*
 *	Ensure the have the ldap_create_sort_keylist()
 *	function too, else we can't use ldap_create_sort_control()
 */
#if !defined(HAVE_LDAP_CREATE_SORT_KEYLIST) || !defined(HAVE_LDAP_FREE_SORT_KEYLIST)
#  undef HAVE_LDAP_CREATE_SORT_CONTROL
#endif

/*
 *	Because the LTB people define LDAP_VENDOR_VERSION_PATCH
 *	as X, which precludes its use in printf statements *sigh*
 *
 *	Identifiers that are not macros, all evaluate to 0,
 *	which is why this works.
 */
#define X 0
#if !defined(LDAP_VENDOR_VERSION_PATCH) || LDAP_VENDOR_VERSION_PATCH == 0
#  undef LDAP_VENDOR_VERSION_PATCH
#  define LDAP_VENDOR_VERSION_PATCH 0
#endif
#undef X

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

#if defined(HAVE_LDAP_URL_PARSE) && defined(HAVE_LDAP_IS_LDAP_URL) && defined(HAVE_LDAP_URL_DESC2STR)
#  define LDAP_CAN_PARSE_URLS
#endif

#define LDAP_MAX_CONTROLS		10		//!< Maximum number of client/server controls.
							//!< Used to allocate static arrays of control pointers.
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
#define LDAP_MAX_DN_STR_LEN		1024		//!< Maximum length of an xlat expanded DN.

#define LDAP_VIRTUAL_DN_ATTR		"dn"		//!< 'Virtual' attribute which maps to the DN of the object.

typedef enum {
	LDAP_EXT_UNSUPPORTED,				//!< Unsupported extension.
	LDAP_EXT_BINDNAME,				//!< Specifies the user DN or name for an LDAP bind.
	LDAP_EXT_BINDPW,				//!< Specifies the password for an LDAP bind.
} ldap_supported_extension_t;

typedef struct {
	char const	*mech;				//!< SASL mech(s) to try.
	char const	*proxy;				//!< Identity to proxy.
	char const	*realm;				//!< Kerberos realm.
} fr_ldap_sasl_t;

typedef struct {
	LDAPControl 	*control;			//!< LDAP control.
	bool		freeit;				//!< Whether the control should be freed after
							//!< we've finished using it.
} fr_ldap_control_t;

typedef enum {
	FR_LDAP_DIRECTORY_UNKNOWN = 0,			//!< We can't determine the directory server.

	FR_LDAP_DIRECTORY_ACTIVE_DIRECTORY,		//!< Directory server is Active Directory.
	FR_LDAP_DIRECTORY_EDIRECTORY,			//!< Directory server is eDir.
	FR_LDAP_DIRECTORY_IBM,				//!< Directory server is IBM.
	FR_LDAP_DIRECTORY_NETSCAPE,			//!< Directory server is Netscape.
	FR_LDAP_DIRECTORY_OPENLDAP,			//!< Directory server is OpenLDAP.
	FR_LDAP_DIRECTORY_ORACLE_INTERNET_DIRECTORY,	//!< Directory server is Oracle Internet Directory.
	FR_LDAP_DIRECTORY_ORACLE_UNIFIED_DIRECTORY,	//!< Directory server is Oracle Unified Directory.
	FR_LDAP_DIRECTORY_ORACLE_VIRTUAL_DIRECTORY,	//!< Directory server is Oracle Virtual Directory.
	FR_LDAP_DIRECTORY_SUN_ONE_DIRECTORY,		//!< Directory server is Sun One Directory.
	FR_LDAP_DIRECTORY_SIEMENS_AG,			//!< Directory server is Siemens AG.
	FR_LDAP_DIRECTORY_UNBOUND_ID			//!< Directory server is Unbound ID
} fr_ldap_directory_type_t;

/** LDAP connection handle states
 *
 */
typedef enum {
	FR_LDAP_STATE_INIT = 0,				//!< Connection uninitialised.
	FR_LDAP_STATE_START_TLS,			//!< TLS is being negotiated.
	FR_LDAP_STATE_BIND,				//!< Connection is being bound.
	FR_LDAP_STATE_RUN,				//!< Connection is muxing/demuxing requests.
	FR_LDAP_STATE_ERROR				//!< Connection is in an error state.
} fr_ldap_state_t;

typedef struct {
	char const		*vendor_str;		//!< As returned from the vendorName attribute in the
							///< rootDSE.
	char const		*version_str;		//!< As returned from the vendorVersion attribute in the
							///< rootDSE.
	fr_ldap_directory_type_t type;			///< Cannonical server implementation.

	bool			cleartext_password;	//!< Whether the server will return the user's plaintext
							///< password.
} fr_ldap_directory_t;

/** Connection configuration
 *
 * Must not be passed into functions except via the connection handle
 * this avoids problems with not using the connection pool configuration.
 */
typedef struct {
	char const		*name;			//!< Name of the module that created this connection.

	char			*server;		//!< Initial server to bind to.
	char const		**server_str;		//!< Server set in the config.

	uint16_t		port;			//!< Port to use when binding to the server.

	char const		*admin_identity;	//!< Identity we bind as when we need to query the LDAP
							///< directory.
	char const		*admin_password;	//!< Password used in administrative bind.

	fr_ldap_sasl_t		admin_sasl;		//!< SASL parameters used when binding as the admin.

	const char		*sasl_secprops;		//!< SASL Security Properties to set.

	int			dereference;		//!< libldap value specifying dereferencing behaviour.
	char const		*dereference_str;	//!< When to dereference (never, searching, finding, always)

	bool			chase_referrals;	//!< If the LDAP server returns a referral to another server
							///< or point in the tree, follow it, establishing new
							///< connections and binding where necessary.
	bool			chase_referrals_unset;	//!< If true, use the OpenLDAP defaults for chase_referrals.

	bool			use_referral_credentials;	//!< If true use credentials from the referral URL.

	bool			rebind;			//!< Controls whether we set an ldad_rebind_proc function
							///< and so determines if we can bind to other servers whilst
							///< chasing referrals. If this is false, we will still chase
							///< referrals on the same server, but won't bind to other
							///< servers.

	/*
	 *	TLS items.
	 */
	int			tls_mode;

	bool			start_tls;		//!< Send the Start TLS message to the LDAP directory
							///< to start encrypted communications using the standard
							///< LDAP port.

	char const		*tls_ca_file;		//!< Sets the full path to a CA certificate (used to validate
							///< the certificate the server presents).

	char const		*tls_ca_path;		//!< Sets the path to a directory containing CA certificates.

	char const		*tls_certificate_file;	//!< Sets the path to the public certificate file we present
							///< to the servers.

	char const		*tls_private_key_file;	//!< Sets the path to the private key for our public
							///< certificate.

	char const		*tls_require_cert_str;	//!< Sets requirements for validating the certificate the
							///< server presents.

	int			tls_require_cert;	//!< OpenLDAP constant representing the require cert string.


	/*
	 *	For keep-alives.
	 */
#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	fr_time_delta_t		keepalive_idle;		//!< Number of seconds a connections needs to remain idle
							//!< before TCP starts sending keepalive probes.
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	uint32_t		keepalive_probes;	//!< Number of missed timeouts before the connection is
							///< dropped.
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	fr_time_delta_t		keepalive_interval;	//!< Interval between keepalive probes.
#endif

	/*
	 *	Search timelimits
	 */
	fr_time_delta_t		srv_timelimit;		//!< How long the server should spent on a single request
							///< (also bounded by value on the server).

	fr_time_delta_t		res_timeout;		//!< How long we wait for results.

	/*
	 *	I/O timelimits.
	 */
	fr_time_delta_t		net_timeout;		//!< How long we wait in blocking network calls.
							///< We set this in the LDAP API, even though with
							///< async calls, we control this using our event loop.
							///< This is just in case there are blocking calls which
							///< happen internally which we can't work around.

	fr_time_delta_t		tls_handshake_timeout;	//!< How long we wait for the TLS handshake to complete.

	fr_time_delta_t		reconnection_delay;	//!< How long to wait before attempting to reconnect.
} fr_ldap_config_t;

/** Tracks the state of a libldap connection handle
 *
 */
typedef struct {
	LDAP			*handle;		//!< libldap handle.

	bool			rebound;		//!< Whether the connection has been rebound to something
							///< other than the admin user.
	bool			referred;		//!< Whether the connection is now established a server
							///< other than the configured one.

	fr_ldap_control_t	serverctrls[LDAP_MAX_CONTROLS + 1];	//!< Server controls to use for all operations
									///< with this handle.
	fr_ldap_control_t	clientctrls[LDAP_MAX_CONTROLS + 1];	//!< Client controls to use for all operations
									///< with this handle.
	int			serverctrls_cnt;	//!< Number of server controls associated with the handle.
	int			clientctrls_cnt;	//!< Number of client controls associated with the handle.

	fr_ldap_directory_t	*directory;		//!< The type of directory we're connected to.

	fr_ldap_config_t const	*config;		//!< rlm_ldap connection configuration.
	fr_connection_t		*conn;			//!< Connection state handle.

	fr_ldap_state_t		state;			//!< LDAP connection state machine.

	void			*uctx;			//!< User data associated with the handle.
} fr_ldap_connection_t;

/** Contains a collection of values
 *
 */
typedef struct {
	struct berval		**values;		//!< libldap struct containing bv_val (char *)
							///< and length bv_len.
	int			count;			//!< Number of values.
} fr_ldap_result_t;

/** Result of expanding the RHS of a set of maps
 *
 * Used to store the array of attributes we'll be querying for.
 */
typedef struct {
	vp_map_t const *maps;				//!< Head of list of maps we expanded the RHS of.
	char const	*attrs[LDAP_MAX_ATTRMAP + LDAP_MAP_RESERVED + 1]; //!< Reserve some space for access attributes
							//!< and NULL termination.
	TALLOC_CTX	*ctx;				//!< Context to allocate new attributes in.
	int		count;				//!< Index on next free element.
} fr_ldap_map_exp_t;

/** Codes returned by fr_ldap internal functions
 *
 */
typedef enum {
	LDAP_PROC_CONTINUE = 1,				//!< Operation is in progress.
	LDAP_PROC_SUCCESS = 0,				//!< Operation was successfull.

	LDAP_PROC_ERROR	= -1,				//!< Unrecoverable library/server error.

	LDAP_PROC_BAD_CONN = -2,			//!< Transitory error, caller should retry the operation
							//!< with a new connection.

	LDAP_PROC_NOT_PERMITTED = -3,			//!< Operation was not permitted, either current user was
							//!< locked out in the case of binds, or has insufficient
							//!< access.

	LDAP_PROC_REJECT = -4,				//!< Bind failed, user was rejected.

	LDAP_PROC_BAD_DN = -5,				//!< Specified an invalid object in a bind or search DN.

	LDAP_PROC_NO_RESULT = -6,			//!< Got no results.

	LDAP_PROC_TIMEOUT = -7,				//!< Operation timed out.

	LDAP_PROC_REFRESH_REQUIRED = -8			//!< Don't continue with the current refresh phase,
							//!< exit, and retry the operation with a NULL cookie.
} fr_ldap_rcode_t;

/*
 *	Tables for resolving strings to LDAP constants
 */
extern fr_table_num_sorted_t const fr_ldap_connection_states[];
extern size_t fr_ldap_connection_states_len;

extern fr_table_num_sorted_t const fr_ldap_supported_extensions[];
extern size_t fr_ldap_supported_extensions_len;
extern fr_table_num_sorted_t const fr_ldap_dereference[];
extern size_t fr_ldap_dereference_len;
extern fr_table_num_sorted_t const fr_ldap_scope[];
extern size_t fr_ldap_scope_len;
extern fr_table_num_sorted_t const fr_ldap_tls_require_cert[];
extern size_t fr_ldap_tls_require_cert_len;

/** Inline function to copy pointers from a berval to a valuebox
 *
 * @note This results in a shallow copy of the berval, so if the berval is freed
 *	the value box becomes invalidated.
 *
 * @param[out] value	to write berval values to.
 * @param[in] berval	to copy pointers/lengths from.
 */
static inline void fr_ldap_berval_to_value_shallow(fr_value_box_t *value, struct berval *berval)
{
	fr_value_box_memdup_shallow(value, NULL, (uint8_t *)berval->bv_val, berval->bv_len, true);
}

/*
 *	ldap.c - Wrappers arounds OpenLDAP functions.
 */
void		fr_ldap_timeout_debug(REQUEST *request, fr_ldap_connection_t const *conn,
				      fr_time_delta_t timeout, char const *prefix);

size_t		fr_ldap_escape_func(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *arg);

size_t		fr_ldap_unescape_func(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *arg);

ssize_t		fr_ldap_xlat_filter(REQUEST *request, char const **sub, size_t sublen, char *out, size_t outlen);

fr_ldap_rcode_t	fr_ldap_bind(REQUEST *request,
			     fr_ldap_connection_t **pconn,
			     char const *dn, char const *password,
#ifdef WITH_SASL
			     fr_ldap_sasl_t const *sasl,
#else
			     NDEBUG_UNUSED fr_ldap_sasl_t const *sasl,
#endif
			     fr_time_delta_t timeout,
			     LDAPControl **serverctrls, LDAPControl **clientctrls);

char const	*fr_ldap_error_str(fr_ldap_connection_t const *conn);

fr_ldap_rcode_t	fr_ldap_search(LDAPMessage **result, REQUEST *request,
			       fr_ldap_connection_t **pconn,
			       char const *dn, int scope, char const *filter, char const * const * attrs,
			       LDAPControl **serverctrls, LDAPControl **clientctrls);

fr_ldap_rcode_t	fr_ldap_search_async(int *msgid, REQUEST *request,
				     fr_ldap_connection_t **pconn,
				     char const *dn, int scope, char const *filter, char const * const *attrs,
				     LDAPControl **serverctrls, LDAPControl **clientctrls);

fr_ldap_rcode_t	fr_ldap_modify(REQUEST *request, fr_ldap_connection_t **pconn,
			       char const *dn, LDAPMod *mods[],
			       LDAPControl **serverctrls, LDAPControl **clientctrls);

fr_ldap_rcode_t	fr_ldap_error_check(LDAPControl ***ctrls, fr_ldap_connection_t const *conn,
				    LDAPMessage *msg, char const *dn);

fr_ldap_rcode_t	fr_ldap_result(LDAPMessage **result, LDAPControl ***ctrls,
			       fr_ldap_connection_t const *conn, int msgid, int all,
			       char const *dn,
			       fr_time_delta_t timeout);

int		fr_ldap_global_config(int debug_level, char const *tls_random_file);

int		fr_ldap_init(void);

void		fr_ldap_free(void);

/*
 *	control.c - Connection based client/server controls
 */
void		fr_ldap_control_merge(LDAPControl *serverctrls_out[],
				      LDAPControl *clientctrls_out[],
				      size_t serverctrls_len,
				      size_t clientctrls_len,
				      fr_ldap_connection_t *conn,
				      LDAPControl *serverctrls_in[],
				      LDAPControl *clientctrls_in[]);

int		fr_ldap_control_add_server(fr_ldap_connection_t *conn, LDAPControl *ctrl, bool freeit);

int		fr_ldap_control_add_client(fr_ldap_connection_t *conn, LDAPControl *ctrl, bool freeit);

void		fr_ldap_control_clear(fr_ldap_connection_t *conn);

int		fr_ldap_control_add_session_tracking(fr_ldap_connection_t *conn, REQUEST *request);

/*
 *	directory.c - Get directory capabilities from the remote server
 */
int		fr_ldap_directory_alloc(TALLOC_CTX *ctx, fr_ldap_directory_t **out, fr_ldap_connection_t **pconn);

/*
 *	edir.c - Edirectory integrations
 */
int		fr_ldap_edir_get_password(LDAP *ld, char const *dn, char *password, size_t *passlen);

char const	*fr_ldap_edir_errstr(int code);


/*
 *	map.c - Attribute mapping code.
 */
int		fr_ldap_map_getvalue(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request,
				     vp_map_t const *map, void *uctx);

int		fr_ldap_map_verify(vp_map_t *map, void *instance);

int		fr_ldap_map_expand(fr_ldap_map_exp_t *expanded, REQUEST *request, vp_map_t const *maps);

int		fr_ldap_map_do(REQUEST *request, fr_ldap_connection_t *conn,
			       char const *valuepair_attr, fr_ldap_map_exp_t const *expanded, LDAPMessage *entry);

/*
 *	sasl_s.c - SASL synchronous bind functions
 */
#ifdef WITH_SASL
fr_ldap_rcode_t	 fr_ldap_sasl_interactive(REQUEST *request,
					  fr_ldap_connection_t *pconn, char const *dn,
					  char const *password, fr_ldap_sasl_t const *sasl,
					  LDAPControl **serverctrls, LDAPControl **clientctrls,
					  fr_time_delta_t timeout);
#endif

/*
 *	connection.c - Connection configuration functions
 */
fr_ldap_connection_t *fr_ldap_connection_alloc(TALLOC_CTX *ctx);

fr_connection_t	*fr_ldap_connection_state_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
					        fr_ldap_config_t const *config, char *log_prefix);

int		fr_ldap_connection_configure(fr_ldap_connection_t *c, fr_ldap_config_t const *config);

int		fr_ldap_connection_timeout_set(fr_ldap_connection_t const *conn, fr_time_delta_t timeout);

int		fr_ldap_connection_timeout_reset(fr_ldap_connection_t const *conn);

/*
 *	state.c - Connection state machine
 */
fr_ldap_state_t	fr_ldap_state_next(fr_ldap_connection_t *c);

void		fr_ldap_state_error(fr_ldap_connection_t *c);

/*
 *	start_tls.c - Mostly async start_tls
 */
int		fr_ldap_start_tls_async(fr_ldap_connection_t *c,
					LDAPControl **serverctrls, LDAPControl **clientctrls);

/*
 *	sasl.c - Async sasl bind
 */
#ifdef WITH_SASL
int		fr_ldap_sasl_bind_async(fr_ldap_connection_t *c,
					char const *mechs,
			    		char const *identity,
			    		char const *password,
			    		char const *proxy,
			    		char const *realm,
			    		LDAPControl **serverctrls, LDAPControl **clientctrls);
#endif

/*
 *	bind.c - Async bind
 */
int		fr_ldap_bind_async(fr_ldap_connection_t *c,
				   char const *bind_dn, char const *password,
				   LDAPControl **serverctrls, LDAPControl **clientctrls);


/*
 *	uti.c - Utility functions
 */
size_t		fr_ldap_common_dn(char const *full, char const *part);

bool		fr_ldap_util_is_dn(char const *in, size_t inlen);

size_t		fr_ldap_util_normalise_dn(char *out, char const *in);

char		*fr_ldap_berval_to_string(TALLOC_CTX *ctx, struct berval const *in);

uint8_t		*fr_ldap_berval_to_bin(TALLOC_CTX *ctx, struct berval const *in);

int		fr_ldap_parse_url_extensions(LDAPControl **sss, REQUEST *request,
					     fr_ldap_connection_t *conn, char **extensions);
