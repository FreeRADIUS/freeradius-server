/* Copyright 2006-2015 The FreeRADIUS server project */

#ifndef _RLM_MSCHAP_H
#define _RLM_MSCHAP_H

RCSIDH(rlm_mschap_h, "$Id$")

#include "config.h"

#ifdef WITH_AUTH_WINBIND
#  include <wbclient.h>
#endif

/* Method of authentication we are going to use */
typedef enum {
	AUTH_INTERNAL		= 0,
	AUTH_NTLMAUTH_EXEC	= 1
#ifdef WITH_AUTH_WINBIND
	,AUTH_WBCLIENT       	= 2
#endif
} MSCHAP_AUTH_METHOD;

typedef struct rlm_mschap_t {
	bool			use_mppe;
	bool			require_encryption;
	bool			require_strong;
	bool			with_ntdomain_hack;	/* this should be in another module */
	char const		*xlat_name;
	char const		*ntlm_auth;
	uint32_t		ntlm_auth_timeout;
	char const		*ntlm_cpw;
	char const		*ntlm_cpw_username;
	char const		*ntlm_cpw_domain;
	char const		*local_cpw;
	char const		*auth_type;
	bool			allow_retry;
	char const		*retry_msg;
	MSCHAP_AUTH_METHOD	method;
	vp_tmpl_t		*wb_username;
	vp_tmpl_t		*wb_domain;
	fr_connection_pool_t    *wb_pool;
	bool			wb_retry_with_normalised_username;
#ifdef __APPLE__
	bool			open_directory;
#endif
} rlm_mschap_t;

#endif

