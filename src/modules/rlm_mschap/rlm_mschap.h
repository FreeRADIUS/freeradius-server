#pragma once
/* @copyright 2006-2015 The FreeRADIUS server project */
RCSIDH(rlm_mschap_h, "$Id$")

#include "config.h"
#include "mschap.h"

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/slab.h>
#include <freeradius-devel/server/tmpl.h>

#ifdef WITH_AUTH_WINBIND
#  include <wbclient.h>
#endif

/* Method of authentication we are going to use */
typedef enum {
	AUTH_INTERNAL		= 0, /* MS-CHAP-Use-NTLM-Auth = no */
	AUTH_NTLMAUTH_EXEC	= 1, /* MS-CHAP-Use-NTLM-Auth = yes */
	AUTH_AUTO		= 2, /* MS-CHAP-Use-NTLM-Auth = auto */
#ifdef WITH_AUTH_WINBIND
	AUTH_WBCLIENT       	= 3
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

typedef struct {
	fr_dict_enum_value_t const	*auth_type;

	bool				normify;

	bool				use_mppe;
	bool				require_encryption;
	bool				require_strong;
	bool				with_ntdomain_hack;	/* this should be in another module */

	char const			*ntlm_auth;
	fr_time_delta_t			ntlm_auth_timeout;
	char const			*ntlm_cpw;

	bool				allow_retry;
	char const			*retry_msg;
	MSCHAP_AUTH_METHOD		method;
	char const			*wb_username;
#ifdef WITH_AUTH_WINBIND
	bool				wb_retry_with_normalised_username;
	fr_slab_config_t		reuse;
#endif
#ifdef __APPLE__
	bool				open_directory;
#endif
} rlm_mschap_t;

#ifdef WITH_AUTH_WINBIND
typedef struct {
	struct wbcContext	*ctx;
} winbind_ctx_t;

FR_SLAB_TYPES(mschap, winbind_ctx_t)
FR_SLAB_FUNCS(mschap, winbind_ctx_t)

typedef struct {
	rlm_mschap_t const	*inst;		//!< Instance of rlm_mschap.
	mschap_slab_list_t	*slab;		//!< Slab list for winbind handles.
} rlm_mschap_thread_t;
#endif
typedef struct {
	tmpl_t const	*username;
	tmpl_t const	*chap_error;
	tmpl_t const	*chap_challenge;
	tmpl_t const	*chap_response;
	tmpl_t const	*chap2_response;
	tmpl_t const	*chap2_success;
	tmpl_t const	*chap_mppe_keys;
	tmpl_t const	*mppe_encryption_policy;
	tmpl_t const	*mppe_recv_key;
	tmpl_t const	*mppe_send_key;
	tmpl_t const	*mppe_encryption_types;
	tmpl_t const	*chap2_cpw;
	tmpl_t const	*chap_nt_enc_pw;
	fr_value_box_t	wb_username;
	fr_value_box_t	wb_domain;
	tmpl_t const	*ntlm_cpw_username;
	tmpl_t const	*ntlm_cpw_domain;
	tmpl_t const	*local_cpw;
} mschap_auth_call_env_t;

typedef struct {
	fr_value_box_list_t	cpw_user;
	fr_value_box_list_t	cpw_domain;
	fr_value_box_list_t	local_cpw_result;
	uint8_t			new_nt_encrypted[516];
	uint8_t			old_nt_hash[NT_DIGEST_LENGTH];
	fr_pair_t		*new_hash;
} mschap_cpw_ctx_t;

typedef struct {
	char const		*name;
	rlm_mschap_t const	*inst;
	mschap_auth_call_env_t	*env_data;
	MSCHAP_AUTH_METHOD	method;
	fr_pair_t		*nt_password;
	fr_pair_t		*smb_ctrl;
	fr_pair_t		*cpw;
	mschap_cpw_ctx_t	*cpw_ctx;
#ifdef WITH_AUTH_WINBIND
	rlm_mschap_thread_t	*t;
#endif
} mschap_auth_ctx_t;
