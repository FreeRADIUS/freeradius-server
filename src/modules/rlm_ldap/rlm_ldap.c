/*
 * rlm_ldap.c	LDAP authorization and authentication module.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *   Copyright 1999-2012 The FreeRADIUS Server Project.
 *
 *   Copyright 2012 Alan DeKok <aland@freeradius.org>
 *   Copyright 2012 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>

#include	<stdarg.h>
#include	<ctype.h>

#include	<lber.h>
#include	<ldap.h>

#define MAX_ATTRMAP		128
#define MAX_ATTR_STR_LEN	256
#define MAX_FILTER_STR_LEN	1024

#ifdef WITH_EDIR
extern int nmasldap_get_password(LDAP *ld,char *objectDN, char *pwd, size_t *pwdSize);

#endif

typedef struct ldap_acct_section {
	CONF_SECTION	*cs;
	
	const char *reference;
} ldap_acct_section_t;


typedef struct {
	CONF_SECTION	*cs;
	fr_connection_pool_t *pool;

	char		*server;
	int		port;

	char		*login;
	char		*password;

	char		*filter;
	char		*basedn;

	int		chase_referrals;
	int		rebind;

	int		ldap_debug; /* Debug flag for LDAP SDK */

	const char	*xlat_name; /* name used to xlat */

	int		expect_password;
	
	/*
	 *	RADIUS attribute to LDAP attribute maps
	 */
	VALUE_PAIR_MAP	*user_map;	/* Applied to users and profiles */
	
	/*
	 *	Access related configuration
	 */
	char		*access_attr;
	int		positive_access_attr;

	/*
	 *	Profiles
	 */
	char		*base_filter;
	char		*default_profile;
	char		*profile_attr;

	/*
	 *	Group checking.
	 */
	char		*groupname_attr;
	char		*groupmemb_filter;
	char		*groupmemb_attr;
	
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

}  ldap_instance;

/* The default setting for TLS Certificate Verification */
#define TLS_DEFAULT_VERIFY "allow"

/*
 *	TLS Configuration
 */
static CONF_PARSER tls_config[] = {
	{"start_tls", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,start_tls), NULL, "no"},
	{"cacertfile", PW_TYPE_FILENAME,
	 offsetof(ldap_instance,tls_cacertfile), NULL, NULL},
	{"cacertdir", PW_TYPE_FILENAME,
	 offsetof(ldap_instance,tls_cacertdir), NULL, NULL},
	{"certfile", PW_TYPE_FILENAME,
	 offsetof(ldap_instance,tls_certfile), NULL, NULL},
	{"keyfile", PW_TYPE_FILENAME,
	 offsetof(ldap_instance,tls_keyfile), NULL, NULL},
	{"randfile", PW_TYPE_STRING_PTR, /* OK if it changes on HUP */
	 offsetof(ldap_instance,tls_randfile), NULL, NULL},
	{"require_cert", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,tls_require_cert), NULL, TLS_DEFAULT_VERIFY},
	{ NULL, -1, 0, NULL, NULL }
};


static CONF_PARSER attr_config[] = {
	/*
	 *	Access limitations
	 */
	/* LDAP attribute name that controls remote access */
	{"access_attr", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,access_attr), NULL, NULL},
	{"positive_access_attr", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,positive_access_attr), NULL, "yes"},

	{"base_filter", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,base_filter), NULL,
	 "(objectclass=radiusprofile)"},
	{"default_profile", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,default_profile), NULL, NULL},
	{"profile_attribute", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,profile_attr), NULL, NULL},

	{ NULL, -1, 0, NULL, NULL }
};


/*
 *	Group configuration
 */
static CONF_PARSER group_config[] = {
	/*
	 *	Group checks.  These could probably be done
	 *	via dynamic xlat's.
	 */
	{"name_attribute", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,groupname_attr), NULL, "cn"},
	{"membership_filter", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,groupmemb_filter), NULL,
	 "(|(&(objectClass=GroupOfNames)(member=%{Ldap-UserDn}))"
	 "(&(objectClass=GroupOfUniqueNames)(uniquemember=%{Ldap-UserDn})))"},
	{"membership_attribute", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,groupmemb_attr), NULL, NULL},


	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	Reference for accounting updates
 */
static const CONF_PARSER acct_section_config[] = {
	{"reference", PW_TYPE_STRING_PTR,
	  offsetof(ldap_acct_section_t, reference), NULL, "."},
	{NULL, -1, 0, NULL, NULL}
};

/*
 *	Various options that don't belong in the main configuration.
 *
 *	Note that these overlap a bit with the connection pool code!
 */
static CONF_PARSER option_config[] = {
	/*
	 *	Debugging flags to the server
	 */
	{"ldap_debug", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,ldap_debug), NULL, "0x0000"},

	{"chase_referrals", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,chase_referrals), NULL, NULL},

	{"rebind", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,rebind), NULL, NULL},

	/* timeout on network activity */
	{"net_timeout", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,net_timeout), NULL, "10"},

	/* timeout for search results */
	{"timeout", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,timeout), NULL, "20"},

	/* allow server unlimited time for search (server-side limit) */
	{"timelimit", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,timelimit), NULL, "20"},

#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	{"idle", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,keepalive_idle), NULL, "60"},
#endif
#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	{"probes", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,keepalive_probes), NULL, "3"},
#endif
#ifdef LDAP_OPT_ERROR_NUMBER
	{"interval", PW_TYPE_INTEGER, 
	 offsetof(ldap_instance,keepalive_interval), NULL, "30"},
#endif
	{ NULL, -1, 0, NULL, NULL }
};


static const CONF_PARSER module_config[] = {
	{"server", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,server), NULL, "localhost"},
	{"port", PW_TYPE_INTEGER,
	 offsetof(ldap_instance,port), NULL, "389"},

	{"password", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,password), NULL, ""},
	{"identity", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,login), NULL, ""},

	/*
	 *	DN's and filters.
	 */
	{"basedn", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,basedn), NULL, "o=notexist"},

	{"filter", PW_TYPE_STRING_PTR,
	 offsetof(ldap_instance,filter), NULL, "(uid=%u)"},

	/* turn off the annoying warning if we don't expect a password */
	{"expect_password", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,expect_password), NULL, "yes"},
	 
#ifdef WITH_EDIR
	/* support for eDirectory Universal Password */
	{"edir", PW_TYPE_BOOLEAN,
	 offsetof(ldap_instance,edir), NULL, NULL}, /* NULL defaults to "no" */
#endif

	/*
	 *	Terrible things which should be deleted.
	 */
	{ "profiles", PW_TYPE_SUBSECTION, 0, NULL, (const void *) attr_config },

	{ "group", PW_TYPE_SUBSECTION, 0, NULL, (const void *) group_config },

	{ "options", PW_TYPE_SUBSECTION, 0, NULL,
	 (const void *) option_config },

	{ "tls", PW_TYPE_SUBSECTION, 0, NULL, (const void *) tls_config },

	{NULL, -1, 0, NULL, NULL}
};

typedef struct ldap_conn {
	LDAP	*handle;
	int	rebound;
	int	referred;
	ldap_instance *inst;
} LDAP_CONN;

typedef struct xlat_attrs {
	const VALUE_PAIR_MAP *maps;
	const char *attrs[MAX_ATTRMAP];
} xlat_attrs_t;

typedef struct rlm_ldap_result {
	char	**values;
	int	count;
} rlm_ldap_result_t;


#if LDAP_SET_REBIND_PROC_ARGS == 3
/*
 *	Rebind && chase referral stuff
 */
static int ldap_rebind(LDAP *handle, LDAP_CONST char *url,
		       UNUSED ber_tag_t request, UNUSED ber_int_t msgid,
		       void *ctx )
{
	LDAP_CONN *conn = ctx;

	conn->referred = TRUE;
	conn->rebound = TRUE;	/* not really, but oh well... */
	rad_assert(handle == conn->handle);

	DEBUG("rlm_ldap (%s): Rebinding to URL %s", conn->inst->xlat_name, url);
	
	return ldap_bind_s(handle, conn->inst->login, conn->inst->password,
			   LDAP_AUTH_SIMPLE);
}
#endif

static int ldap_bind_wrapper(LDAP_CONN **pconn, const char *user,
			     const char *password,
			     const char **perror_str, int do_rebind)
{
	int		rcode, ldap_errno;
	int		module_rcode = RLM_MODULE_FAIL;
	int		reconnect = FALSE;
	const char	*error_string;
	LDAP_CONN	*conn = *pconn;
	ldap_instance   *inst = conn->inst;
	LDAPMessage	*result = NULL;
	struct timeval tv;

redo:
	ldap_errno = ldap_bind(conn->handle, user, password, LDAP_AUTH_SIMPLE);
	if (ldap_errno < 0) {
	get_error:
		ldap_get_option(conn->handle, LDAP_OPT_ERROR_NUMBER,
				&ldap_errno);
		error_string = ldap_err2string(ldap_errno);

		if (do_rebind && !reconnect) {
			conn = fr_connection_reconnect(inst->pool, conn);
			*pconn = conn;
			if (!conn) return RLM_MODULE_FAIL;
			goto redo;
		}

	print_error:
		if (perror_str) *perror_str = error_string;

#ifdef HAVE_LDAP_INITIALIZE
		if (inst->is_url) {
			radlog(L_ERR, "rlm_ldap (%s): %s bind to %s failed: %s",
			       inst->xlat_name, user,
			       inst->server, error_string);
		} else
#endif
		{
			radlog(L_ERR, "rlm_ldap (%s): %s bind to %s:%d "
				      "failed: %s",
			       inst->xlat_name, user,
			       inst->server, inst->port,
			       error_string);
		}

		return module_rcode; /* caller closes the connection */
	}

	DEBUG3("rlm_ldap (%s): Waiting for bind result...", inst->xlat_name);

	tv.tv_sec = inst->timeout;
	tv.tv_usec = 0;
	rcode = ldap_result(conn->handle, ldap_errno, 1, &tv, &result);
	if (rcode < 0) goto get_error;

	if (rcode == 0) {
		error_string = "timeout";
		goto print_error;
	}

	ldap_errno = ldap_result2error(conn->handle, result, 1);
	switch (ldap_errno) {
	case LDAP_SUCCESS:
		break;

	case LDAP_INVALID_CREDENTIALS:
	case LDAP_CONSTRAINT_VIOLATION:
		rcode = RLM_MODULE_REJECT;
		/* FALL-THROUGH */

	default:
		goto get_error;
	}

	return RLM_MODULE_OK;
}

/** Create and return a new connection
 * This function is probably too big.
 */
static void *ldap_conn_create(void *ctx)
{
	int module_rcode;
	int ldap_errno, ldap_version;
	struct timeval tv;
	ldap_instance *inst = ctx;
	LDAP *handle = NULL;
	LDAP_CONN *conn = NULL;
	const char *error;

#ifdef HAVE_LDAP_INITIALIZE
	if (inst->is_url) {
		DEBUG("rlm_ldap (%s): Connect to %s", inst->xlat_name,
		      inst->server);

		ldap_errno = ldap_initialize(&handle, inst->server);

		if (ldap_errno != LDAP_SUCCESS) {
			radlog(L_ERR, "rlm_ldap (%s): ldap_initialize() "
			       "failed: %s",
			       inst->xlat_name, ldap_err2string(ldap_errno));
			goto conn_fail;
		}
	} else
#endif
	{
		DEBUG("rlm_ldap (%s): Connect to %s:%d", inst->xlat_name,
		      inst->server, inst->port);

		handle = ldap_init(inst->server, inst->port);
		if (!handle) {
			radlog(L_ERR, "rlm_ldap (%s): ldap_init() failed",
			       inst->xlat_name);
		conn_fail:
			if (handle) ldap_unbind_s(handle);
			return NULL;
		}
	}

	/*
	 *	We now have a connection structure, but no actual TCP connection.
	 *
	 *	Set a bunch of LDAP options, using common code.
	 */
#define do_ldap_option(_option, _name, _value) \
	if (ldap_set_option(handle, _option, _value) != LDAP_OPT_SUCCESS) { \
		ldap_get_option(handle, LDAP_OPT_ERROR_NUMBER, &ldap_errno); \
		radlog(L_ERR, "rlm_ldap (%s): Could not set %s: %s", \
		       inst->xlat_name, _name, ldap_err2string(ldap_errno)); \
	}
		
	if (inst->ldap_debug) {
		do_ldap_option(LDAP_OPT_DEBUG_LEVEL, "ldap_debug",
			       &(inst->ldap_debug));
	}

	/*
	 *	Leave "chase_referrals" unset to use the OpenLDAP
	 *	default.
	 */
	if (inst->chase_referrals != 2) {
		if (inst->chase_referrals) {
			do_ldap_option(LDAP_OPT_REFERRALS, "chase_referrals",
				       LDAP_OPT_ON);
			
#if LDAP_SET_REBIND_PROC_ARGS == 3
			if (inst->rebind == 1) {
				ldap_set_rebind_proc(handle, ldap_rebind, inst);
			}
#endif
		} else {
			do_ldap_option(LDAP_OPT_REFERRALS, "chase_referrals",
				       LDAP_OPT_OFF);
		}
	}

	tv.tv_sec = inst->net_timeout;
	tv.tv_usec = 0;
	do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout", &tv);

	do_ldap_option(LDAP_OPT_TIMELIMIT, "timelimit",
		       &(inst->timelimit));

	ldap_version = LDAP_VERSION3;
	do_ldap_option(LDAP_OPT_PROTOCOL_VERSION, "ldap_version",
		       &ldap_version);

#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_IDLE, "keepalive idle",
		       &(inst->keepalive_idle));
#endif

#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_PROBES, "keepalive probes",
		       &(inst->keepalive_probes));
#endif

#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_INTERVAL, "keepalive interval",
		       &(inst->keepalive_interval));
#endif

#ifdef HAVE_LDAP_START_TLS
	/*
	 *	Set all of the TLS options
	 */
	if (inst->tls_mode) {
		do_ldap_option(LDAP_OPT_X_TLS, "tls_mode", &(inst->tls_mode));
	}

#define maybe_ldap_option(_option, _name, _value) \
	if (_value) do_ldap_option(_option, _name, _value)

	maybe_ldap_option(LDAP_OPT_X_TLS_CACERTFILE,
			  "cacertfile", inst->tls_cacertfile);
	maybe_ldap_option(LDAP_OPT_X_TLS_CACERTDIR,
			  "cacertdir", inst->tls_cacertdir);

#ifdef HAVE_LDAP_INT_TLS_CONFIG
	if (ldap_int_tls_config(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
				(inst->tls_require_cert)) != LDAP_OPT_SUCCESS) {
		ldap_get_option(handle, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		radlog(L_ERR, "rlm_ldap (%s): could not set "
		       "LDAP_OPT_X_TLS_REQUIRE_CERT option to %s: %s",
		       inst->xlat_name, 
		       inst->tls_require_cert,
		       ldap_err2string(ldap_errno));
	}
#endif

	maybe_ldap_option(LDAP_OPT_X_TLS_CERTFILE,
			  "certfile", inst->tls_certfile);
	maybe_ldap_option(LDAP_OPT_X_TLS_KEYFILE,
			  "keyfile", inst->tls_keyfile);
	maybe_ldap_option(LDAP_OPT_X_TLS_RANDOM_FILE,
			  "randfile", inst->tls_randfile);

	/*
	 *	And finally start the TLS code.
	 */
	if (inst->start_tls && (inst->port != 636)) {
		ldap_errno = ldap_start_tls_s(handle, NULL, NULL);
		if (ldap_errno != LDAP_SUCCESS) {
			ldap_get_option(handle, LDAP_OPT_ERROR_NUMBER,
					&ldap_errno);
			radlog(L_ERR, "rlm_ldap (%s): could not start TLS: %s",
			       inst->xlat_name,
			       ldap_err2string(ldap_errno));
			goto conn_fail;
		}
	}
#endif /* HAVE_LDAP_START_TLS */

	conn = rad_malloc(sizeof(*conn));
	conn->inst = inst;
	conn->handle = handle;
	conn->rebound = FALSE;
	conn->referred = FALSE;

	module_rcode = ldap_bind_wrapper(&conn, inst->login, inst->password,
					 &error, FALSE);
	if (module_rcode != RLM_MODULE_OK) {
		radlog(L_ERR, "rlm_ldap (%s): failed binding to LDAP "
		       "server: %s",
		       inst->xlat_name, error);

		/*
		 *	FIXME: print "check config, morians!
		 */
		goto conn_fail;
	}

	return conn;
}


/** Close and delete a connection
 *
 */
static int ldap_conn_delete(UNUSED void *ctx, void *connection)
{
	LDAP_CONN *conn = connection;

	ldap_unbind_s(conn->handle);
	free(conn);

	return 0;
}


/** Gets an LDAP socket from the connection pool
 *
 */
static LDAP_CONN *ldap_get_socket(ldap_instance *inst)
{
	LDAP_CONN *conn;

	conn = fr_connection_get(inst->pool);
	if (!conn) {
		radlog(L_ERR, "rlm_ldap (%s): all ldap connections are in use",
		       inst->xlat_name);
		return NULL;
	}

	return conn;
}

/** Frees an LDAP socket back to the connection pool
 *
 */
static void ldap_release_socket(ldap_instance *inst, LDAP_CONN *conn)
{
	/*
	 *	Could have already been free'd due to a previous error.
	 */
	if (!conn) return;

	/*
	 *	We chased a referral to another server.
	 *
	 *	This connection is no longer part of the pool which is
	 *	connected to and bound to the configured server.
	 *	Close it.
	 *
	 *	Note that we do NOT close it if it was bound to
	 *	another user.  Instead, we let the next caller do the
	 *	rebind.
	 */
	if (conn->referred) {
		fr_connection_del(inst->pool, conn);
		return;
	}

	fr_connection_release(inst->pool, conn);
	return;
}


/* Converts "bad" strings into ones which are safe for LDAP
 *
 */
static size_t ldap_escape_func(UNUSED REQUEST *request, char *out,
			       size_t outlen, const char *in, UNUSED void *arg)
{
	size_t len = 0;

	while (in[0]) {
		/*
		 *	Encode unsafe characters.
		 */
		if (((len == 0) &&
		    ((in[0] == ' ') || (in[0] == '#'))) ||
		    (strchr(",+\"\\<>;*=()", *in))) {
			static const char hex[] = "0123456789abcdef";

			/*
			 *	Only 3 or less bytes available.
			 */
			if (outlen <= 3) {
				break;
			}

			*(out++) = '\\';
			*(out++) = hex[((*in) >> 4) & 0x0f];
			*(out++) = hex[(*in) & 0x0f];
			outlen -= 3;
			len += 3;
			in++;
			continue;
		}

		/*
		 *	Only one byte left.
		 */
		if (outlen <= 1) {
			break;
		}

		/*
		 *	Allowed character.
		 */
		*(out++) = *(in++);
		outlen--;
		len++;
	}
	*out = '\0';
	return len;
}

/** Do a search and get a response
 *
 */
static int perform_search(ldap_instance *inst, REQUEST *request,
			  LDAP_CONN **pconn, const char *search_basedn,
			  int scope, const char *filter, 
			  const char * const *attrs, LDAPMessage **presult)
{
	int		ldap_errno;
	int		count = 0;
	int		reconnect = FALSE;
	LDAP_CONN	*conn = *pconn;
	struct timeval  tv;

	/*
	 *	OpenLDAP library doesn't declare attrs array as const, but
	 *	it really should be *sigh*.
	 */
	char **search_attrs;
	memcpy(&search_attrs, &attrs, sizeof(attrs));

	*presult = NULL;

	/*
	 *	Do all searches as the default admin user.
	 */
	if (conn->rebound) {
		ldap_errno = ldap_bind_wrapper(pconn,
					       inst->login, inst->password,
					       NULL, TRUE);
		if (ldap_errno != RLM_MODULE_OK) {
			return -1;
		}

		rad_assert(*pconn != NULL);
		conn = *pconn;
		conn->rebound = FALSE;
	}

	tv.tv_sec = inst->timeout;
	tv.tv_usec = 0;
	RDEBUG2("Performing search in '%s' with filter '%s'",
	        search_basedn ? search_basedn : "(null)" ,
	        filter);

retry:
	ldap_errno = ldap_search_ext_s(conn->handle, search_basedn, scope,
				       filter, search_attrs, 0, NULL, NULL,
				       &tv, 0, presult);
	switch (ldap_errno) {
	case LDAP_SUCCESS:
	case LDAP_NO_SUCH_OBJECT:
		break;

	case LDAP_SERVER_DOWN:
	do_reconnect:
		ldap_msgfree(*presult);

		if (reconnect) return -1;
		reconnect = TRUE;

		conn = fr_connection_reconnect(inst->pool, conn);
		*pconn = conn;	/* tell the caller we have a new connection */
		if (!conn) return -1;
		goto retry;

	case LDAP_INSUFFICIENT_ACCESS:
		radlog(L_ERR, "rlm_ldap (%s): Search failed: "
		       "Insufficient access. Check the identity and password "
		       "configuration directives", inst->xlat_name);
		ldap_msgfree(*presult);
		return -1;

	case LDAP_TIMEOUT:
		exec_trigger(NULL, inst->cs, "modules.ldap.timeout", TRUE);
		radlog(L_ERR, "rlm_ldap (%s): Search failed: Timed out "
		       "while waiting for server to respond"
		       "Please increase the timeout", inst->xlat_name);
		ldap_msgfree(*presult);
		return -1;

	case LDAP_FILTER_ERROR:
		radlog(L_ERR, "rlm_ldap (%s): Search failed: Bad search "
		       "filter: %s", inst->xlat_name,filter);
		ldap_msgfree(*presult);
		return -1;

	case LDAP_TIMELIMIT_EXCEEDED:
		exec_trigger(NULL, inst->cs, "modules.ldap.timeout", TRUE);

	case LDAP_BUSY:
	case LDAP_UNAVAILABLE:
		/*
		 *	Reconnect.  There's an issue with the socket
		 *	or LDAP server.
		 */
		ldap_get_option(conn->handle, LDAP_OPT_ERROR_NUMBER,
				&ldap_errno);
		radlog(L_ERR, "rlm_ldap (%s): Search failed: %s",
		       inst->xlat_name, ldap_err2string(ldap_errno));
		goto do_reconnect;

	default:
		ldap_get_option(conn->handle, LDAP_OPT_ERROR_NUMBER,
				&ldap_errno);
		radlog(L_ERR, "rlm_ldap (%s): Search failed: %s",
		       inst->xlat_name, ldap_err2string(ldap_errno));
		ldap_msgfree(*presult);
		return -1;
	}

	count = ldap_count_entries(conn->handle, *presult);
	if (count == 0) {
		ldap_msgfree(*presult);
		RDEBUG("Search returned no results");
		
		return -2;
	}

	if (count != 1) {
		ldap_msgfree(*presult);
		RDEBUG("Got ambiguous search result (%d results)", count);
		      
		return -2;
	}

	return 0;
}

/** Expand an LDAP URL into a query, and return a string result from that query.
 *
 */
static size_t ldap_xlat(void *instance, REQUEST *request, const char *fmt,
			char *out, size_t freespace)
{
	int rcode;
	size_t length = 0;
	ldap_instance *inst = instance;
	LDAPURLDesc *ldap_url;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	char **vals;
	LDAP_CONN *conn;
	int ldap_errno;
	const char *url;
	const char **attrs;
	char buffer[MAX_FILTER_STR_LEN];

	if (strchr(fmt, '%') != NULL) {
		if (!radius_xlat(buffer, sizeof(buffer), fmt, request,
				 ldap_escape_func, NULL)) {
			radlog(L_ERR,
			       "rlm_ldap (%s): Unable to create LDAP URL", 
			       inst->xlat_name);
			return 0;
		}
		url = buffer;
	} else {
		url = fmt;
	}

	if (!ldap_is_ldap_url(url)) {
		radlog(L_ERR, "rlm_ldap (%s): String passed does not look "
		       "like an LDAP URL", inst->xlat_name);
		return 0;
	}

	if (ldap_url_parse(url, &ldap_url)){
		radlog(L_ERR, "rlm_ldap (%s): Parsing LDAP URL failed",
		       inst->xlat_name);
		return 0;
	}

	/*
	 *	Nothing, empty string, "*" string, or got 2 things, die.
	 */
	if (!ldap_url->lud_attrs || !ldap_url->lud_attrs[0] ||
	    !*ldap_url->lud_attrs[0] ||
	    (strcmp(ldap_url->lud_attrs[0], "*") == 0) ||
	    ldap_url->lud_attrs[1]) {
		radlog(L_ERR, "rlm_ldap (%s): Bad attributes list in LDAP "
		       "URL. URL must specify exactly one attribute to "
		       "retrieve",
		       inst->xlat_name);
		       
		goto free_urldesc;
	}

	if (ldap_url->lud_host &&
	    ((strncmp(inst->server, ldap_url->lud_host,
		      strlen(inst->server)) != 0) ||
	     (ldap_url->lud_port != inst->port))) {
		RDEBUG("Requested server/port is \"%s:%i\"", ldap_url->lud_host,
		       inst->port);
		
		goto free_urldesc;
	}

	conn = ldap_get_socket(inst);
	if (!conn) goto free_urldesc;

	memcpy(&attrs, &ldap_url->lud_attrs, sizeof(attrs));
	
	rcode = perform_search(inst, request, &conn, ldap_url->lud_dn, 
			       ldap_url->lud_scope, ldap_url->lud_filter, attrs,
			       &result);
	if (rcode < 0) {
		if (rcode == -2) {
			RDEBUG("Search returned not found", inst->xlat_name);
			goto free_socket;
		}

		goto free_socket;
	}

	entry = ldap_first_entry(conn->handle, result);
	if (!entry) {
		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE,
				&ldap_errno);
		radlog(L_ERR, "rlm_ldap (%s): Failed retrieving entry: %s", 
		       inst->xlat_name,
		       ldap_err2string(ldap_errno));
		goto free_result;
	}

	vals = ldap_get_values(conn->handle, entry, ldap_url->lud_attrs[0]);
	if (!vals) {
		RDEBUG("No \"%s\" attributes found in specified object",
		       inst->xlat_name, ldap_url->lud_attrs[0]);
		goto free_result;
	}

	length = strlen(vals[0]);
	if (length >= freespace){

		goto free_vals;
	}

	strlcpy(out, vals[0], freespace);

free_vals:
	ldap_value_free(vals);
free_result:
	ldap_msgfree(result);
free_socket:
	ldap_release_socket(inst, conn);
free_urldesc:
	ldap_free_urldesc(ldap_url);

	return length;
}


static char *get_userdn(LDAP_CONN **pconn, REQUEST *request, int *module_rcode)
{
	int		rcode;
	VALUE_PAIR	*vp;
	ldap_instance	*inst = (*pconn)->inst;
	LDAP		*handle = (*pconn)->handle;
	LDAPMessage	*result, *entry;
	int		ldap_errno;
	static char	firstattr[] = "uid";
	char		*user_dn;
	const char	*attrs[] = {firstattr, NULL};
	char	    	filter[MAX_FILTER_STR_LEN];	
	char	    	basedn[MAX_FILTER_STR_LEN];	

	*module_rcode = RLM_MODULE_FAIL;

	vp = pairfind(request->config_items, PW_LDAP_USERDN, 0);
	if (vp) return vp->vp_strvalue;

	if (!radius_xlat(filter, sizeof(filter), inst->filter,
			 request, ldap_escape_func, NULL)) {
		radlog(L_ERR, "rlm_ldap (%s): Unable to create filter",
		       inst->xlat_name);
		*module_rcode = RLM_MODULE_INVALID;
		return NULL;
	}

	if (!radius_xlat(basedn, sizeof(basedn), inst->basedn,
			 request, ldap_escape_func, NULL)) {
		radlog(L_ERR, "rlm_ldap (%s): Unable to create basedn",
		       inst->xlat_name);
		*module_rcode = RLM_MODULE_INVALID;
		return NULL;
	}

	rcode = perform_search(inst, request, pconn, basedn, LDAP_SCOPE_SUBTREE,
			       filter, attrs, &result);
	if (rcode < 0) {
		if (rcode == -2) {
			*module_rcode = RLM_MODULE_NOTFOUND;
		}

		return NULL;
	}

	if ((entry = ldap_first_entry(handle, result)) == NULL) {
		ldap_get_option(handle, LDAP_OPT_RESULT_CODE,
				&ldap_errno);
		radlog(L_ERR, "rlm_ldap (%s): Failed retrieving entry: %s", 
		       inst->xlat_name,
		       ldap_err2string(ldap_errno));
		ldap_msgfree(result);
		return NULL;
	}

	if ((user_dn = ldap_get_dn(handle, entry)) == NULL) {
		ldap_get_option(handle, LDAP_OPT_RESULT_CODE,
				&ldap_errno);
		radlog(L_ERR, "rlm_ldap (%s): ldap_get_dn() failed: %s",
		       inst->xlat_name,
		       ldap_err2string(ldap_errno));
		       
		ldap_msgfree(result);
		return NULL;
	}

	vp = pairmake("LDAP-UserDn", user_dn, T_OP_EQ);
	if (!vp) {
		ldap_memfree(user_dn);
		ldap_msgfree(result);
		return NULL;
	}
	
	pairadd(&request->config_items, vp);
	ldap_memfree(user_dn);
	ldap_msgfree(result);

	return vp->vp_strvalue;
}


/** Perform LDAP-Group comparison checking
 *
 */
static int ldap_groupcmp(void *instance, REQUEST *request,
			 UNUSED VALUE_PAIR *thing, VALUE_PAIR *check,
			 UNUSED VALUE_PAIR *check_pairs,
			 UNUSED VALUE_PAIR **reply_pairs)
{
	ldap_instance   *inst = instance;
	int		i, rcode, found, module_rcode;
	LDAPMessage     *result = NULL;
	LDAPMessage     *entry = NULL;
	int		ldap_errno;
	int		check_is_dn = FALSE, value_is_dn = FALSE;
	static char	firstattr[] = "dn";
	const char	*attrs[] = {firstattr, NULL};
	char		**vals;
	const char	*group_attrs[] = {inst->groupmemb_attr, NULL};
	LDAP_CONN	*conn;
	char		*user_dn;

	char		gr_filter[MAX_FILTER_STR_LEN];
	char		filter[MAX_FILTER_STR_LEN];
	char		basedn[MAX_FILTER_STR_LEN];

	RDEBUG("Searching for user in group \"%s\"", check->vp_strvalue);

	if (check->length == 0) {
		RDEBUG("Cannot do comparison (group name is empty)");
		return 1;
	}

	conn = ldap_get_socket(inst);
	if (!conn) return 1;

	/*
	 *	This is used in the default membership filter.
	 */
	user_dn = get_userdn(&conn, request, &module_rcode);
	if (!user_dn) {
		ldap_release_socket(inst, conn);
		return 1;
	}

	if (!inst->groupmemb_filter) goto check_attr;

	if (!radius_xlat(gr_filter, sizeof(gr_filter),
			 inst->groupmemb_filter, request, ldap_escape_func,
			 NULL)) {
		radlog(L_ERR, "rlm_ldap (%s): Failed creating group filter",
		       inst->xlat_name);
		return 1;
	}

	/*
	 *	If it's a DN, use that.
	 */
	check_is_dn = strchr(check->vp_strvalue,',') == NULL ? FALSE : TRUE;
	
	if (check_is_dn) {
		strlcpy(filter, gr_filter, sizeof(filter));
		strlcpy(basedn, check->vp_strvalue, sizeof(basedn));	
	} else {
		snprintf(filter, sizeof(filter), "(&(%s=%s)%s)",
			 inst->groupname_attr,
			 check->vp_strvalue, gr_filter);

		/*
		 *	get_userdn does this, too.  Oh well.
		 */
		if (!radius_xlat(basedn, sizeof(basedn), inst->basedn,
				 request, ldap_escape_func, NULL)) {
			radlog(L_ERR, "rlm_ldap (%s): Failed creating basedn",
			       inst->xlat_name);
			return 1;
		}
	}

	rcode = perform_search(inst, request, &conn, basedn, LDAP_SCOPE_SUBTREE,
			       filter, attrs, &result);
	if (rcode == 0) {
		ldap_release_socket(inst, conn);
		ldap_msgfree(result);
			
		RDEBUG("User found in group object");
		
		return 0;
	}

	if (rcode == -1) {
		ldap_release_socket(inst, conn);
		return 1;
	}

	/* else the search returned -2, for "not found" */

	/*
	 *	Else the search returned NOTFOUND.  See if we're
	 *	configured to search for group membership using user
	 *	object attribute.
	 */
	if (!inst->groupmemb_attr) {
		ldap_release_socket(inst, conn);
		RDEBUG("Group object \"%s\" not found, or user is not a member",
		       check->vp_strvalue);
		return 1;
	}

check_attr:
	RDEBUG2("Checking user object membership (%s) attributes",
		inst->groupmemb_attr);

	snprintf(filter ,sizeof(filter), "(objectclass=*)");

	rcode = perform_search(inst, request, &conn, user_dn, LDAP_SCOPE_BASE,
			       filter, group_attrs, &result);
	if (rcode < 0) {
		if (rcode == -2) {
			RDEBUG("Can't check membership attributes, user object "
			       "not found");
		}
		ldap_release_socket(inst, conn);
		return 1;
	}

	entry = ldap_first_entry(conn->handle, result);
	if (!entry) {
		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE,
				&ldap_errno);
		radlog(L_ERR, "rlm_ldap (%s): Failed retrieving entry: %s", 
		       inst->xlat_name,
		       ldap_err2string(ldap_errno));
			       
		ldap_release_socket(inst, conn);
		ldap_msgfree(result);
		return 1;
	}

	vals = ldap_get_values(conn->handle, entry, inst->groupmemb_attr);
	if (!vals) {
		RDEBUG("No group membership attribute(s) found in user object");
		ldap_release_socket(inst, conn);
		ldap_msgfree(result);
		return 1;
	}

	/*
	 *	Loop over the list of groups the user is a member of,
	 *	looking for a match.
	 */
	found = FALSE;
	for (i = 0; i < ldap_count_values(vals); i++) {
		LDAPMessage *gr_result = NULL;
		
		value_is_dn = strchr(vals[i], ',') == NULL ? FALSE : TRUE;
		
		RDEBUG2("Processing group membership value \"%s\"", vals[i]);

		/*
		 *	Both literal group names, do case sensitive comparison
		 */
		if (!check_is_dn && !value_is_dn) {
			if (strcmp(vals[i], check->vp_strvalue) == 0){
				RDEBUG("User found (membership value matches "
				       "check value)");
			       
				found = TRUE;
				break;
			}
			
			continue;
		}

		/*
		 *	Both DNs, do case insensitive comparison
		 */
		if (check_is_dn && value_is_dn) {
			if (strcasecmp(vals[i], check->vp_strvalue) == 0){
				RDEBUG("User found (membership DN matches "
				       "check DN)");
			       
				found = TRUE;
				break;
			}
			
			continue;
		}
		
		/*
		 *	If the value is not a DN, or the check item is a DN
		 *	there's nothing more we can do.
		 */
		if (!value_is_dn && check_is_dn) continue;

		/*
		 *	We have a value which is a DN, and a check item which
		 *	specifies the name of a group, search using the value
		 *	DN for the group, and see if it has a groupname_attr
		 *	which matches our check val.
		 */
		RDEBUG2("Searching with membership DN and group name");

		snprintf(filter,sizeof(filter), "(%s=%s)",
			 inst->groupname_attr, check->vp_strvalue);

		rcode = perform_search(inst, request, &conn, vals[i],
				       LDAP_SCOPE_BASE, filter, attrs,
				       &gr_result);
				       
		ldap_msgfree(gr_result);

		/* Error occurred */
		if (rcode == -1) {
			ldap_value_free(vals);
			ldap_msgfree(result);
			ldap_release_socket(inst, conn);
			return 1;
		}
		
		/*
		 *	Either the group DN wasn't found, or it didn't have the
		 *	correct name. Continue looping over the attributes.
		 */
		if (rcode == -2) {
			ldap_msgfree(gr_result);
			continue;
		}

		found = TRUE;

		RDEBUG("User found (group name in membership DN matches check "
		       "value)");

		break;
	}

	ldap_value_free(vals);
	ldap_msgfree(result);
	ldap_release_socket(inst, conn);

	if (!found){
		RDEBUG("User is not a member of specified group");
		return 1;
	}

	return 0;
}

/** Parse update section
 *
 * Verify that the ldap update section makes sense, and add attribute names
 * to array of attributes for efficient querying later.
 */
static int build_attrmap(CONF_SECTION *cs, VALUE_PAIR_MAP **head)
{
	const char *cs_list, *p;

	request_refs_t request_def = REQUEST_CURRENT;
	pair_lists_t list_def = PAIR_LIST_REQUEST;

	CONF_ITEM *ci = cf_sectiontoitem(cs);
	CONF_PAIR *cp;

	unsigned int total = 0;
	VALUE_PAIR_MAP **tail, *map;
	*head = NULL;
	tail = head;
	
	if (!cs) return 0;
	
	cs_list = p = cf_section_name2(cs);
	if (cs_list) {
		request_def = radius_request_name(&p, REQUEST_UNKNOWN);
		if (request_def == REQUEST_UNKNOWN) {
			cf_log_err(ci, "rlm_ldap: Default request specified "
				   "in mapping section is invalid");
			return -1;
		}
		
		list_def = fr_str2int(pair_lists, p, PAIR_LIST_UNKNOWN);
		if (list_def == PAIR_LIST_UNKNOWN) {
			cf_log_err(ci, "rlm_ldap: Default list specified "
				   "in mapping section is invalid");
			return -1;
		}
	}

	for (ci = cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(cs, ci)) {
	     	if (total++ == MAX_ATTRMAP) {
	     		cf_log_err(ci, "rlm_ldap: Attribute map size exceeded");
	     		goto error;
	     	}
	     	
		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "rlm_ldap: Entry is not in \"attribute ="
				       " ldap-attribute\" format");
			goto error;
		}
	
		cp = cf_itemtopair(ci);
		map = radius_cp2map(cp, REQUEST_CURRENT, list_def);
		if (!map) {
			goto error;
		}
		
		*tail = map;
		tail = &(map->next);
	}

	return 0;
	
	error:
		radius_mapfree(head);
		return -1;
}

/** Detach from the LDAP server and cleanup internal state.
 *
 */
static int ldap_detach(void *instance)
{
	ldap_instance *inst = instance;

	if (inst->postauth) free(inst->postauth);
	if (inst->accounting) free(inst->accounting);
	
	fr_connection_pool_delete(inst->pool);
	
	if (inst->user_map) {
		radius_mapfree(&inst->user_map);
	}

	free(inst);

	return 0;
}

static int parse_sub_section(CONF_SECTION *parent, 
	 		     UNUSED ldap_instance *inst,
	 		     ldap_acct_section_t **config,
	 		     rlm_components_t comp)
{
	CONF_SECTION *cs;

	const char *name = section_type_value[comp].section;
	
	cs = cf_section_sub_find(parent, name);
	if (!cs) {
		radlog(L_INFO, "Couldn't find configuration for %s. "
		       "Will return NOOP for calls from this section.", name);
		
		return 0;
	}
	
	*config = rad_calloc(sizeof(**config));
	if (cf_section_parse(cs, *config, acct_section_config) < 0) {
		radlog(L_ERR, "Failed parsing configuration for section %s",
		       name);
		
		free(*config);
		*config = NULL;
		
		return -1;
	}
		
	(*config)->cs = cs;

	return 0;
}

/** Parses config
 * Uses section of radiusd config file passed as parameter to create an
 * instance of the module.
 */
static int ldap_instantiate(CONF_SECTION * conf, void **instance)
{
	ldap_instance *inst;
	CONF_SECTION *cs;

	inst = rad_calloc(sizeof *inst);
	inst->cs = conf;

	inst->chase_referrals = 2; /* use OpenLDAP defaults */
	inst->rebind = 2;
	
	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}
		
	rad_assert(inst->xlat_name);

	/*
	 *	If the configuration parameters can't be parsed, then fail.
	 */
	if ((cf_section_parse(conf, inst, module_config) < 0) ||
	    (parse_sub_section(conf, inst,
			       &inst->accounting,
			       RLM_COMPONENT_ACCT) < 0) ||
	    (parse_sub_section(conf, inst,
			       &inst->postauth,
			       RLM_COMPONENT_POST_AUTH) < 0)) {
		radlog(L_ERR, "rlm_ldap (%s): Failed parsing configuration",
		       inst->xlat_name);
		goto error;
	}

	if (inst->server == NULL) {
		radlog(L_ERR, "rlm_ldap (%s): Missing 'server' directive",
		       inst->xlat_name);
		goto error;
	}

	/*
	 *	Check for URLs.  If they're used and the library doesn't
	 *	support them, then complain.
	 */
	inst->is_url = 0;
	if (ldap_is_ldap_url(inst->server)) {
#ifdef HAVE_LDAP_INITIALIZE
		inst->is_url = 1;
		inst->port = 0;
#else
		radlog(L_ERR, "rlm_ldap (%s): 'server' directive is in URL "
		       "form but ldap_initialize() is not available",
		       inst->xlat_name);
		goto error;
#endif
	}

	/* workaround for servers which support LDAPS but not START TLS */
	if (inst->port == LDAPS_PORT || inst->tls_mode) {
		inst->tls_mode = LDAP_OPT_X_TLS_HARD;
	} else {
		inst->tls_mode = 0;
	}

#if LDAP_SET_REBIND_PROC_ARGS != 3
	/*
	 *	The 2-argument rebind doesn't take an instance
	 *	variable.  Our rebind function needs the instance
	 *	variable for the username, password, etc.
	 */
	if (inst->rebind == 1) {
		radlog(L_ERR, "rlm_ldap (%s): Cannot use 'rebind' directive "
		       "as this version of libldap does not support the API "
		       "that we need", inst->xlat-name);
		goto error;
	}
#endif

	/*
	 *	Build the attribute map
	 */
	cs = cf_section_sub_find(conf, "update");
	if (cs) {	
		if (build_attrmap(cs, &(inst->user_map)) < 0) {
			goto error;
		}
	}

	/*
	 *	Group comparison checks.
	 */
	paircompare_register(PW_LDAP_GROUP, PW_USER_NAME, ldap_groupcmp, inst);	
	if (cf_section_name2(conf)) {
		DICT_ATTR *da;
		ATTR_FLAGS flags;
		char buffer[256];

		snprintf(buffer, sizeof(buffer), "%s-Ldap-Group",
			 inst->xlat_name);
		memset(&flags, 0, sizeof(flags));

		dict_addattr(buffer, -1, 0, PW_TYPE_STRING, flags);
		da = dict_attrbyname(buffer);
		if (!da) {
			radlog(L_ERR, "rlm_ldap (%s): Failed creating "
			       "attribute %s", inst->xlat_name, buffer);
			goto error;
		}

		paircompare_register(da->attr, PW_USER_NAME, ldap_groupcmp,
				     inst);
	}

	xlat_register(inst->xlat_name, ldap_xlat, inst);

	/*
	 *	Initialize the socket pool.
	 */
	inst->pool = fr_connection_pool_init(inst->cs, inst,
					     ldap_conn_create,
					     NULL,
					     ldap_conn_delete);
	if (!inst->pool) {
		ldap_detach(inst);
		return -1;
	}
	
	*instance = inst;
	return 0;
	
	error:
	ldap_detach(inst);
	return -1;
}

static int check_access(ldap_instance *inst, REQUEST* request, LDAP_CONN *conn,
			LDAPMessage *entry)
{
	int rcode = -1;
	char **vals = NULL;

	vals = ldap_get_values(conn->handle, entry, inst->access_attr);
	if (vals) {
		if (inst->positive_access_attr) {
			if (strncmp(vals[0], "FALSE", 5) == 0) {
				RDEBUG("Dialup access disabled");

			} else {
				rcode = 0;
			}

		} else {
			RDEBUG("\"%s\" attribute exists - access denied by"
			       " default", inst->access_attr);
		}

		ldap_value_free(vals);

	} else if (inst->positive_access_attr) {
		RDEBUG("No %s attribute - access denied by default",
		       inst->access_attr);

	} else {
		rcode = 0;
	}

	return rcode;
}


static VALUE_PAIR *ldap_getvalue(REQUEST *request, const VALUE_PAIR_TMPL *dst,
				 void *ctx)
{
	rlm_ldap_result_t *self = ctx;
	VALUE_PAIR *head, **tail, *vp;
	int i;
	
	request = request;
	
	head = NULL;
	tail = &head;
	
	/*
	 *	Iterate over all the retrieved values,
	 *	don't try and be clever about changing operators
	 *	just use whatever was set in the attribute map.	
	 */
	for (i = 0; i < self->count; i++) {
		vp = pairalloc(dst->da);
		rad_assert(vp);

		pairparsevalue(vp, self->values[i]);
		
		*tail = vp;
		tail = &(vp->next);
	}
	
	return head;		
}


static void xlat_attrsfree(const xlat_attrs_t *expanded)
{
	const VALUE_PAIR_MAP *map;
	unsigned int total = 0;
	
	const char *name;
	
	for (map = expanded->maps; map != NULL; map = map->next)
	{
		name = expanded->attrs[total++];
		if (!name) return;
		
		if (map->src->do_xlat) {
			cfree(name);
		}
	}
}


static int xlat_attrs(REQUEST *request, const VALUE_PAIR_MAP *maps,
		      xlat_attrs_t *expanded)
{
	const VALUE_PAIR_MAP *map;
	unsigned int total = 0;
	
	size_t len;
	char *buffer;

	for (map = maps; map != NULL; map = map->next)
	{
		if (map->src->do_xlat) {
			buffer = rad_malloc(MAX_ATTR_STR_LEN);
			len = radius_xlat(buffer, MAX_ATTR_STR_LEN,
					  map->src->name, request, NULL, NULL);
					  
			if (!len) {
				RDEBUG("Expansion of LDAP attribute "
				       "\"%s\" failed", map->src->name);
				       
				expanded->attrs[total] = NULL;
				
				xlat_attrsfree(expanded);
				
				return -1;
			}
			
			expanded->attrs[total++] = buffer;
		} else {
			expanded->attrs[total++] = map->src->name;
		}
	}
	
	expanded->attrs[total] = NULL;
	expanded->maps = maps;
	
	return 0;
}


/** Convert attribute map into valuepairs
 *
 * Use the attribute map built earlier to convert LDAP values into valuepairs
 * and insert them into whichever list they need to go into.
 *
 * This is *NOT* atomic, but there's no condition in which we should error
 * out...
 */
static void do_attrmap(UNUSED ldap_instance *inst, REQUEST *request,
		       LDAP *handle, const xlat_attrs_t *expanded,
		       LDAPMessage *entry)
{
	const VALUE_PAIR_MAP 	*map;
	unsigned int		total = 0;
	
	rlm_ldap_result_t	result;
	const char		*name;

	for (map = expanded->maps; map != NULL; map = map->next)
	{
		name = expanded->attrs[total++];
		
		result.values = ldap_get_values(handle, entry, name);
		if (!result.values) {
			RDEBUG2("Attribute \"%s\" not found in LDAP object",
				name);
				
			goto next;
		}
		
		/*
		 *	Find out how many values there are for the
		 *	attribute and extract all of them.
		 */
		result.count = ldap_count_values(result.values);
		
		/*
		 *	If something bad happened, just skip, this is probably
		 *	a case of the dst being incorrect for the current
		 *	request context
		 */
		if (radius_map2request(request, map, name, ldap_getvalue,
				       &result) < 0) {
			goto next;
		}
		
		next:
		
		ldap_value_free(result.values);
	}
}


static void do_check_reply(ldap_instance *inst, REQUEST *request)
{
       /*
	*	More warning messages for people who can't be bothered
	*	to read the documentation.
	*/
	if (inst->expect_password && (debug_flag > 1)) {
		if (!pairfind(request->config_items,PW_CLEARTEXT_PASSWORD, 0) &&
			!pairfind(request->config_items,
				  PW_NT_PASSWORD, 0) &&
			!pairfind(request->config_items,
				  PW_USER_PASSWORD, 0) &&
			!pairfind(request->config_items,
				  PW_PASSWORD_WITH_HEADER, 0) &&
			!pairfind(request->config_items,
				  PW_CRYPT_PASSWORD, 0)) {
				RDEBUG("WARNING: No \"known good\" password "
				       "was found in LDAP.  Are you sure that "
				       "the user is configured correctly?");
	       }
       }
}


static void apply_profile(ldap_instance *inst, REQUEST *request,
			  LDAP_CONN **pconn, const char *profile,
			  const xlat_attrs_t *expanded)
{
	int rcode;
	LDAPMessage	*result, *entry;
	int		ldap_errno;
	LDAP		*handle = (*pconn)->handle;
	char		filter[MAX_FILTER_STR_LEN];

	if (!profile || !*profile) return;

	strlcpy(filter, inst->base_filter, sizeof(filter));

	rcode = perform_search(inst, request, pconn, profile, LDAP_SCOPE_BASE,
			       filter, expanded->attrs, &result);
		
	if (rcode < 0) {
		if (rcode == -2) {
			RDEBUG("Profile \"%s\" not found", profile);
		}
		goto free_result;
	}

	entry = ldap_first_entry(handle, result);
	if (!entry) {
		ldap_get_option(handle, LDAP_OPT_RESULT_CODE,
				&ldap_errno);
		radlog(L_ERR, "rlm_ldap (%s): Failed retrieving entry: %s", 
		       inst->xlat_name,
		       ldap_err2string(ldap_errno));
		       
	 	goto free_result;
	}
	
	do_attrmap(inst, request, handle, expanded, entry);

free_result:
	ldap_msgfree(result);
}


/** Check if user is authorized for remote access
 *
 */
static int ldap_authorize(void *instance, REQUEST * request)
{
	int rcode;
	int module_rcode = RLM_MODULE_OK;
	ldap_instance	*inst = instance;
	char		*user_dn;
	char		**vals;
	VALUE_PAIR	*vp;
	LDAP_CONN	*conn;
	LDAPMessage	*result, *entry;
	int		ldap_errno;
	char		filter[MAX_FILTER_STR_LEN];
	char		basedn[MAX_FILTER_STR_LEN];
	xlat_attrs_t	expanded; /* faster that mallocing every time */
	
	if (!request->username) {
		RDEBUG2("Attribute \"User-Name\" is required for "
			"authorization.");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Check for valid input, zero length names not permitted
	 */
	if (request->username->length == 0) {
		RDEBUG2("Zero length username not permitted");
		return RLM_MODULE_INVALID;
	}

	if (!radius_xlat(filter, sizeof(filter), inst->filter,
			 request, ldap_escape_func, NULL)) {
		radlog(L_ERR, "rlm_ldap (%s): Failed creating filter",
		       inst->xlat_name);
		return RLM_MODULE_INVALID;
	}

	if (!radius_xlat(basedn, sizeof(basedn), inst->basedn,
			 request, ldap_escape_func, NULL)) {
		radlog(L_ERR, "rlm_ldap (%s): Failed creating basedn",
		       inst->xlat_name);
		return RLM_MODULE_INVALID;
	}

	conn = ldap_get_socket(inst);
	if (!conn) return RLM_MODULE_FAIL;
	
	if (xlat_attrs(request, inst->user_map, &expanded) < 0) {
		return RLM_MODULE_FAIL;
	}
	
	rcode = perform_search(inst, request, &conn, basedn,
			       LDAP_SCOPE_SUBTREE, filter, expanded.attrs,
			       &result);
	
	if (rcode < 0) {
		if (rcode == -2) {
			module_failure_msg(request,
					   "rlm_ldap (%s): User object not "
					   " found",
					   inst->xlat_name);
					   
			RDEBUG("User object not found", inst->xlat_name);
			       
			module_rcode = RLM_MODULE_NOTFOUND;
			goto free_socket;
		}

		goto free_socket;
	}

	entry = ldap_first_entry(conn->handle, result);
	if (!entry) {
		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE,
				&ldap_errno);
		radlog(L_ERR, "rlm_ldap (%s): Failed retrieving entry: %s", 
		       inst->xlat_name,
		       ldap_err2string(ldap_errno));
		       
		goto free_result;
	}

	user_dn = ldap_get_dn(conn->handle, entry);
	if (!user_dn) {
		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE,
				&ldap_errno);
		radlog(L_ERR, "rlm_ldap (%s): ldap_get_dn() failed: %s",
		       inst->xlat_name,
		       ldap_err2string(ldap_errno));
		goto free_result;
	}
	
	RDEBUG2("User found at DN \"%s\"", user_dn);
	/*
	 *	Adding attribute containing the Users' DN.
	 */
	pairadd(&request->config_items,
		pairmake("Ldap-UserDn", user_dn, T_OP_EQ));

#ifdef WITH_EDIR
	/*
	 *	We already have a Cleartext-Password.  Skip edir.
	 */
	if (inst->edir && pairfind(request->config_items,
				   PW_CLEARTEXT_PASSWORD, 0)) {
		goto skip_edir;
	}

	/*
	 *      Retrieve Universal Password if we use eDirectory
	 */
	if (inst->edir) {
		int res = 0;
		size_t bufsize;
		char buffer[256];

		bufsize = sizeof(buffer);

		/* retrive universal password */
		res = nmasldap_get_password(conn->handle, user_dn,
					    buffer, &bufsize);
		if (res != 0) {
			RDEBUG2("Failed to retrieve eDirectory password. Check your configuration !");
			module_rcode = RLM_MODULE_NOOP;
			goto free_result;
		}

		/* add Cleartext-Password attribute to the request */
		vp = radius_paircreate(request, &request->config_items,
				       PW_CLEARTEXT_PASSWORD, 0, PW_TYPE_STRING);
		strlcpy(vp->vp_strvalue, buffer, sizeof(vp->vp_strvalue));
		vp->length = strlen(vp->vp_strvalue);
		
		RDEBUG2("Added eDirectory password in check items as %s = %s",
			vp->name, vp->vp_strvalue);
	}

skip_edir:
#endif

	ldap_memfree(user_dn);

	/*
	 *	Check for access.
	 */
	if (inst->access_attr) {
		if (check_access(inst, request, conn, entry) < 0) {
			module_rcode = RLM_MODULE_USERLOCK;
			goto free_result;
		}
	}

	/*
	 *	Apply ONE user profile, or a default user profile.
	 */
	vp = pairfind(request->config_items, PW_USER_PROFILE, 0);
	if (vp || inst->default_profile) {
		char *profile = inst->default_profile;

		if (vp) profile = vp->vp_strvalue;

		apply_profile(inst, request, &conn, profile, &expanded);
	}

	/*
	 *	Apply a SET of user profiles.
	 */
	if (inst->profile_attr) {
		vals = ldap_get_values(conn->handle, entry, inst->profile_attr);
		if (vals != NULL) {
			int i;
	
			for (i = 0; (vals[i] != NULL) && (*vals[i] != '\0');
			     i++) {
				apply_profile(inst, request, &conn, vals[i],
					      &expanded);
			}
	
			ldap_value_free(vals);
		}
	}

	if (inst->user_map) {
		do_attrmap(inst, request, conn->handle, &expanded, entry);
		do_check_reply(inst, request);
	}
	
free_result:
	xlat_attrsfree(&expanded);
	ldap_msgfree(result);
free_socket:
	ldap_release_socket(inst, conn);

	return module_rcode;
}


/** Check the user's password against ldap database
 *
 */
static int ldap_authenticate(void *instance, REQUEST * request)
{
	int		module_rcode;
	const char	*user_dn;
	ldap_instance	*inst = instance;
	LDAP_CONN	*conn;

	/*
	 * Ensure that we're being passed a plain-text password, and not
	 * anything else.
	 */

	if (!request->username) {
		radlog(L_AUTH, "rlm_ldap (%s): Attribute \"User-Name\" is "
		       "required for authentication", inst->xlat_name);
		return RLM_MODULE_INVALID;
	}

	if (!request->password) {
		radlog(L_AUTH, "rlm_ldap (%s): Attribute \"User-Password\" "
		       "is required for authentication.", inst->xlat_name);
		RDEBUG2("  You have set \"Auth-Type := LDAP\" somewhere.");
		RDEBUG2("  *********************************************");
		RDEBUG2("  * THAT CONFIGURATION IS WRONG.  DELETE IT.   ");
		RDEBUG2("  * YOU ARE PREVENTING THE SERVER FROM WORKING.");
		RDEBUG2("  *********************************************");
		return RLM_MODULE_INVALID;
	}

	if (request->password->attribute != PW_USER_PASSWORD) {
		radlog(L_AUTH, "rlm_ldap (%s): Attribute \"User-Password\" "
		       "is required for authentication. Cannot use \"%s\".",
		       inst->xlat_name, request->password->name);
		return RLM_MODULE_INVALID;
	}

	if (request->password->length == 0) {
		module_failure_msg(request,
				   "rlm_ldap (%s): Empty password supplied",
				   inst->xlat_name);
		return RLM_MODULE_INVALID;
	}

	conn = ldap_get_socket(inst);
	if (!conn) return RLM_MODULE_FAIL;

	RDEBUG("Login attempt by \"%s\" with password \"%s\"",
	       request->username->vp_strvalue, request->password->vp_strvalue);

	/*
	 *	Get the DN by doing a search.
	 */
	user_dn = get_userdn(&conn, request, &module_rcode);
	if (!user_dn) {
		ldap_release_socket(inst, conn);
		return module_rcode;
	}

	/*
	 *	Bind as the user
	 */
	conn->rebound = TRUE;
	module_rcode = ldap_bind_wrapper(&conn, user_dn,
					 request->password->vp_strvalue,
					 NULL, TRUE);
	if (module_rcode == RLM_MODULE_OK) {
		RDEBUG("Bind as user \"%s\" was successful", user_dn);
	}

	ldap_release_socket(inst, conn);
	return module_rcode;
}

/** Modify user's object in LDAP
 *
 */
static int user_modify(ldap_instance *inst, REQUEST *request,
		       ldap_acct_section_t *section)
{
	int		module_rcode = RLM_MODULE_OK;
	int		ldap_errno;
	const char	*error_string;
	
	LDAP_CONN	*conn;
	LDAPMod 	*modify[MAX_ATTRMAP];
	LDAPMod		**mod_p = modify;
	
	char		*passed[MAX_ATTRMAP * 2];
	int		i, last_pass = 0;
	
	char 		*expanded[MAX_ATTRMAP];
	int		last_exp = 0;
	
	const char	*attr;
	const char	*value;
	
	int		presult = 0;
	
	const char	*user_dn;

	conn = ldap_get_socket(inst);
	if (!conn) return RLM_MODULE_FAIL;

	/*
	 *	Build our set of modifications using the update sections in
	 *	the config.
	 */
	CONF_ITEM  	*ci;
	CONF_PAIR	*cp;
	CONF_SECTION 	*cs;
	FR_TOKEN	op;
	char		path[MAX_STRING_LEN];
	
	char	*p = path;

	rad_assert(section);
	
	/*
	 *	Locate the update section were going to be using
	 */
	if (section->reference[0] != '.')
		*p++ = '.';
	
	if (!radius_xlat(p, (sizeof(path) - (p - path)) - 1,
			 section->reference, request, NULL, NULL)) {
		goto error;	
	}

	ci = cf_reference_item(NULL, section->cs, path);
	if (!ci) {
		goto error;	
	}
	
	if (!cf_item_is_section(ci)){
		radlog(L_ERR, "rlm_ldap (%s): Reference must resolve to a "
		       "section", inst->xlat_name);
		
		goto error;	
	}
	
	cs = cf_section_sub_find(cf_itemtosection(ci), "update");
	if (!cs) {
		radlog(L_ERR, "rlm_ldap (%s): Section must contain 'update' "
		       "subsection",
		       inst->xlat_name);
		
		goto error;
	}
	
	/*
	 *	Iterate over all the pairs, building our mods array
	 */
	for (ci = cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(cs, ci)) {
	     	int do_xlat = FALSE;
	     	
	     	if ((modify - mod_p) == MAX_ATTRMAP) {
	     		radlog(L_ERR, "rlm_ldap (%s): Modify map size exceeded",
	     		       inst->xlat_name);
	
	     		goto error;
	     	}
	     	
		if (!cf_item_is_pair(ci)) {
			radlog(L_ERR, "rlm_ldap (%s): Entry is not in "
			       "\"ldap-attribute = value\" format",
			       inst->xlat_name);
			       
			goto error;
		}
	
		cp = cf_itemtopair(ci);
		
		switch (cf_pair_value_type(cp))
		{
			case T_BARE_WORD:
			case T_SINGLE_QUOTED_STRING:
			break;
			case T_BACK_QUOTED_STRING:
			case T_DOUBLE_QUOTED_STRING:
				do_xlat = TRUE;		
			break;
			default:
				rad_assert(0);
				goto error;
		}
		
		attr = cf_pair_attr(cp);
		value = cf_pair_value(cp);
		
		if (do_xlat) {
			p = rad_malloc(1024);	
			
			if (radius_xlat(p, 1024, value, request,
					NULL, NULL) == 0) {
				RDEBUG("xlat failed or expanded to empty "
				       "string, skipping attribute \"%s\"",
				       attr);
			
				free(p);
				
				continue;				
			}
			
			expanded[last_exp++] = p;
			
			passed[last_pass] = p;
		} else {
			passed[last_pass] = value;
		}
		
		passed[last_pass + 1] = NULL;
		
		(*mod_p)->mod_values = &passed[last_pass];
					
		last_pass += 2;
		
		/*
		 *	Now we know the value is ok, copy the pointers into
		 *	the ldapmod struct.
		 */
		memcpy(&((*mod_p)->mod_type), &(attr),
		       sizeof((*mod_p)->mod_type));

		op = cf_pair_operator(cp);
		switch (op)
		{
			/*
			 *  T_OP_EQ is *NOT* supported, it is impossible to
			 *  support because of the lack of transactions in LDAP
			 */
			case T_OP_ADD:
				(*mod_p)->mod_op = LDAP_MOD_ADD;
			break;
			case T_OP_SET:
				(*mod_p)->mod_op = LDAP_MOD_REPLACE;
			break;
			case T_OP_SUB:
				(*mod_p)->mod_op = LDAP_MOD_DELETE;
			break;
			default:
				radlog(L_ERR, "rlm_ldap (%s): Operator '%s' "
				       "is not supported for LDAP modify "
				       "operations", inst->xlat_name,
				       fr_int2str(fr_tokens, op, "¿unknown?"));
				       
				goto error;
		}
		
		mod_p++;
	}
	
	*mod_p = NULL;
	
	/*
	 *	Perform all modifications as the default admin user.
	 */
	if (conn->rebound) {
		ldap_errno = ldap_bind_wrapper(&conn,
					       inst->login, inst->password,
					       NULL, TRUE);
		if (ldap_errno != RLM_MODULE_OK) {
			radlog(L_AUTH, "rlm_ldap (%s): Bind error",
			       inst->xlat_name);

			goto error;
		}

		rad_assert(conn != NULL);
		conn->rebound = FALSE;
	}

	user_dn = get_userdn(&conn, request, &module_rcode);
	if (!user_dn) {
		module_rcode = RLM_MODULE_NOTFOUND;
		goto release;
	}
	
	RDEBUG2("Modifying user object with DN \"%s\"", user_dn);
	
	ldap_errno = ldap_modify_ext(conn->handle, user_dn, modify, NULL, NULL,
				     &presult);
			     
	if (ldap_errno < 0) {
		ldap_get_option(conn->handle, LDAP_OPT_ERROR_NUMBER,
				&ldap_errno);
				
		error_string = ldap_err2string(ldap_errno);

		radlog(L_ERR, "rlm_ldap (%s): Modifying DN \"%s\" failed: %s",
		       inst->xlat_name, user_dn, error_string);
		
	error:
		module_rcode = RLM_MODULE_FAIL;
		
		goto release;
	}
	
	RDEBUG2("Modification successful!");
	
	release:
	
	/*
	 *	Free up any buffers we allocated for xlat expansion
	 */	
	for (i = 0; i < last_exp; i++) {
		free(expanded[i]);
	}
	
	ldap_release_socket(inst, conn);
	
	return module_rcode;
}


static int ldap_accounting(void *instance, REQUEST * request) {
	ldap_instance *inst = instance;		

	if (inst->accounting) {
		return user_modify(inst, request, inst->accounting); 
	}
	
	return RLM_MODULE_NOOP;
}


/** Check the user's password against ldap database
 *
 */
static int ldap_postauth(void *instance, REQUEST * request)
{
	ldap_instance	*inst = instance;
#ifdef WITH_EDIR
	int		module_rcode;
	const char	*user_dn;
	LDAP_CONN	*conn;
	VALUE_PAIR	*vp;


	conn = ldap_get_socket(inst);
	if (!conn) return RLM_MODULE_FAIL;
	
	/*
	 *	Ensure that we have a username and a
	 *	Cleartext-Password in the request
	 */
	if (!request->username) {
		radlog(L_AUTH, "rlm_ldap (%s): Attribute \"User-Name\" is "
		       "required for authentication", inst->xlat_name);
		return RLM_MODULE_INVALID;
	}

	vp = pairfind(request->config_items, PW_CLEARTEXT_PASSWORD, 0);
	if (!vp) {
		radlog(L_AUTH, "rlm_ldap (%s): Attribute \"Cleartext-Password\" "
		       "is required for authentication.", inst->xlat_name);
		return RLM_MODULE_INVALID;
	}

	if (!*vp->vp_strvalue) {
		radlog(L_AUTH, "rlm_ldap (%s): Attribute \"Cleartext-Password\" "
		       "is empty.", inst->xlat_name);
		return RLM_MODULE_INVALID;
	}

	RDEBUG("Login attempt by \"%s\" with password \"%s\"",
	       request->username->vp_strvalue, vp->vp_strvalue);

	/*
	 *	Get the DN by doing a search.
	 */
	user_dn = get_userdn(&conn, request, &module_rcode);
	if (!user_dn) {
		ldap_release_socket(inst, conn);
		return module_rcode;
	}

	/*
	 *	Bind as the user
	 */
	conn->rebound = TRUE;
	module_rcode = ldap_bind_wrapper(&conn, user_dn,
					 vp->vp_strvalue,
					 NULL, TRUE);
	if (module_rcode == RLM_MODULE_OK) {
		RDEBUG("Bind as user \"%s\" was successful", user_dn);
	}
	
	ldap_release_socket(inst, conn);
	return module_rcode;
#endif

	if (inst->postauth) {
		return user_modify(inst, request, inst->postauth); 
	}

	return RLM_MODULE_NOOP;
}


/* globally exported name */
module_t rlm_ldap = {
	RLM_MODULE_INIT,
	"ldap",
	RLM_TYPE_THREAD_SAFE,	/* type: reserved 	 */
	ldap_instantiate,	/* instantiation 	 */
	ldap_detach,		/* detach 		 */
	{
		ldap_authenticate,	/* authentication 	 */
		ldap_authorize,		/* authorization 	 */
		NULL,			/* preaccounting 	 */
		ldap_accounting,	/* accounting 		 */
		NULL,			/* checksimul 		 */
		NULL,			/* pre-proxy 		 */
		NULL,			/* post-proxy 		 */
		ldap_postauth		/* post-auth */
	},
};
