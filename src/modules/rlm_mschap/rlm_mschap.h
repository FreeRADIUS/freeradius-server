#pragma once
/* @copyright 2006-2015 The FreeRADIUS server project */
RCSIDH(rlm_mschap_h, "$Id$")

#include "config.h"

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/server/tmpl.h>

#ifdef WITH_AUTH_WINBIND
#  include <wbclient.h>

#include <freeradius-devel/server/pool.h>
#endif

/* Method of authentication we are going to use */
typedef enum {
	AUTH_INTERNAL		= 0,
	AUTH_NTLMAUTH_EXEC	= 1
#ifdef WITH_AUTH_WINBIND
	,AUTH_WBCLIENT       	= 2
#endif
} MSCHAP_AUTH_METHOD;

extern HIDDEN fr_dict_attr_t const *attr_auth_type;
extern HIDDEN fr_dict_attr_t const *attr_cleartext_password;
extern HIDDEN fr_dict_attr_t const *attr_eap_identity;
extern HIDDEN fr_dict_attr_t const *attr_nt_password;
extern HIDDEN fr_dict_attr_t const *attr_lm_password;
extern HIDDEN fr_dict_attr_t const *attr_ms_chap_use_ntlm_auth;

extern HIDDEN fr_dict_attr_t const *attr_ms_chap_user_name;

extern HIDDEN fr_dict_attr_t const *attr_ms_chap_peer_challenge;
extern HIDDEN fr_dict_attr_t const *attr_ms_chap_new_nt_password;
extern HIDDEN fr_dict_attr_t const *attr_ms_chap_new_cleartext_password;
extern HIDDEN fr_dict_attr_t const *attr_smb_account_ctrl;
extern HIDDEN fr_dict_attr_t const *attr_smb_account_ctrl_text;

extern HIDDEN fr_dict_attr_t const *attr_user_name;
extern HIDDEN fr_dict_attr_t const *attr_ms_chap_error;

extern HIDDEN fr_dict_attr_t const *attr_ms_chap_challenge;
extern HIDDEN fr_dict_attr_t const *attr_ms_chap_response;
extern HIDDEN fr_dict_attr_t const *attr_ms_chap2_response;
extern HIDDEN fr_dict_attr_t const *attr_ms_chap2_success;

extern HIDDEN fr_dict_attr_t const *attr_ms_chap_mppe_keys;
extern HIDDEN fr_dict_attr_t const *attr_ms_mppe_encryption_policy;
extern HIDDEN fr_dict_attr_t const *attr_ms_mppe_recv_key;
extern HIDDEN fr_dict_attr_t const *attr_ms_mppe_send_key;
extern HIDDEN fr_dict_attr_t const *attr_ms_mppe_encryption_types;
extern HIDDEN fr_dict_attr_t const *attr_ms_chap2_cpw;

typedef struct {
	fr_dict_enum_value_t	*auth_type;

	bool			normify;

	bool			use_mppe;
	bool			require_encryption;
	bool			require_strong;
	bool			with_ntdomain_hack;	/* this should be in another module */

	char const		*ntlm_auth;
	fr_time_delta_t		ntlm_auth_timeout;
	char const		*ntlm_cpw;
	char const		*ntlm_cpw_username;
	char const		*ntlm_cpw_domain;
	char const		*local_cpw;

	bool			allow_retry;
	char const		*retry_msg;
	MSCHAP_AUTH_METHOD	method;
	tmpl_t		*wb_username;
	tmpl_t		*wb_domain;
#ifdef WITH_AUTH_WINBIND
	fr_pool_t		*wb_pool;
	bool			wb_retry_with_normalised_username;
#endif
#ifdef __APPLE__
	bool			open_directory;
#endif
} rlm_mschap_t;
