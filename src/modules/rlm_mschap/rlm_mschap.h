/* Copyright 2006-2014 The FreeRADIUS server project */

#ifndef _RLM_MSCHAP_H
#define _RLM_MSCHAP_H

RCSIDH(rlm_mschap_h, "$Id$")

typedef enum {
	AUTH_INTERNAL		= 0,
	AUTH_NTLMAUTH_EXEC	= 1
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
	char const		*method_s;
	MSCHAP_AUTH_METHOD	method;
	fr_connection_pool_t	*ntlm_auth_pool;
#ifdef WITH_OPEN_DIRECTORY
	bool		open_directory;
#endif
} rlm_mschap_t;

#endif

