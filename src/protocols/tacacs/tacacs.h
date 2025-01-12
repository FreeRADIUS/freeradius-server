#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/util/dbuff.h>

#include <freeradius-devel/protocol/tacacs/freeradius.internal.h>
#include <freeradius-devel/protocol/tacacs/dictionary.h>

#define FR_HEADER_LENGTH 		sizeof(fr_tacacs_packet_hdr_t)
#define FR_MAX_PACKET_SIZE		4096
#define FR_MAX_ATTRIBUTES 		255


#define FR_TAC_PLUS_MAJOR_VER			12
#define FR_TAC_PLUS_MINOR_VER_DEFAULT		0
#define FR_TAC_PLUS_MINOR_VER_ONE		1

/**
 * 3.4. The TACACS+ Packet Header
 *
 * seq_no
 *
 * This is the sequence number of the current packet for the current session.
 * The first packet in a session MUST have the sequence number 1 and each subsequent
 * packet will increment the sequence number by one. Thus clients only send packets
 * containing odd sequence numbers, and TACACS+ servers only send packets containing
 * even sequence numbers.
 *
 * The sequence number must never wrap i.e. if the sequence number 2^8-1 is ever reached,
 * that session must terminate and be restarted with a sequence number of 1.
 */
#define packet_is_authen_start_request(p)	(((p)->hdr.type == FR_TAC_PLUS_AUTHEN) && ((p)->hdr.seq_no == 1))
#define packet_is_authen_continue(p)		(((p)->hdr.type == FR_TAC_PLUS_AUTHEN) && ((p)->hdr.seq_no > 1) && (((p)->hdr.seq_no % 2) == 1))
#define packet_is_authen_reply(p)		(((p)->hdr.type == FR_TAC_PLUS_AUTHEN) && (((p)->hdr.seq_no % 2) == 0))

#define packet_is_author_request(p)		(((p)->hdr.type == FR_TAC_PLUS_AUTHOR) && (((p)->hdr.seq_no % 2) == 1))
#define packet_is_author_reply(p)		(((p)->hdr.type == FR_TAC_PLUS_AUTHOR) && (((p)->hdr.seq_no % 2) == 0))

#define packet_is_acct_request(p)		(((p)->hdr.type == FR_TAC_PLUS_ACCT) && (((p)->hdr.seq_no % 2) == 1))
#define packet_is_acct_reply(p)			(((p)->hdr.type == FR_TAC_PLUS_ACCT) && (((p)->hdr.seq_no % 2) == 0))

#define packet_has_valid_seq_no(p)		((p)->hdr.seq_no != 0)

#define packet_is_encrypted(p)			(((p)->hdr.flags & FR_TAC_PLUS_UNENCRYPTED_FLAG) == 0)

typedef enum {
	FR_TAC_PLUS_INVALID			= 0x00,
	FR_TAC_PLUS_AUTHEN			= 0x01,
	FR_TAC_PLUS_AUTHOR			= 0x02,
	FR_TAC_PLUS_ACCT			= 0x03,
	FR_TAC_PLUS_MAX				= 0x04
} fr_tacacs_type_t;

/*
 * GCC doesn't support flag_enum (yet)
 *
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=81665
 */
DIAG_OFF(attributes)
typedef enum CC_HINT(flag_enum) {
	FR_TAC_PLUS_FLAGS_NONE			= 0x00,
	FR_TAC_PLUS_UNENCRYPTED_FLAG		= 0x01,
	FR_TAC_PLUS_SINGLE_CONNECT_FLAG		= 0x04
} fr_tacacs_flags_t;
DIAG_ON(attributes)

typedef struct CC_HINT(__packed__) {
	union {
		uint8_t	version;
		struct CC_HINT(__packed__) {
#ifdef WORDS_BIGENDIAN
			unsigned int	major:4;
			unsigned int	minor:4;
#else
			unsigned int	minor:4;
			unsigned int	major:4;
#endif
		} ver;
	};
	fr_tacacs_type_t	type:8;
	uint8_t 		seq_no;
	fr_tacacs_flags_t	flags:8;
	uint32_t 		session_id;
	uint32_t 		length;
} fr_tacacs_packet_hdr_t;

typedef enum {
	FR_TAC_PLUS_AUTHEN_LOGIN		= 0x01,
	FR_TAC_PLUS_AUTHEN_CHPASS		= 0x02,
	FR_TAC_PLUS_AUTHEN_SENDAUTH		= 0x04
} fr_tacacs_action_t;

typedef enum {
	FR_TAC_PLUS_AUTHEN_TYPE_ASCII		= 0x01,
	FR_TAC_PLUS_AUTHEN_TYPE_PAP		= 0x02,
	FR_TAC_PLUS_AUTHEN_TYPE_CHAP		= 0x03,
	FR_TAC_PLUS_AUTHEN_TYPE_ARAP		= 0x04,	/* deprecated */
	FR_TAC_PLUS_AUTHEN_TYPE_MSCHAP		= 0x05,
	FR_TAC_PLUS_AUTHEN_TYPE_MSCHAPV2	= 0x06
} fr_tacacs_authentype_t;

typedef enum {
	FR_TAC_PLUS_PRIV_LVL_MAX		= 0x0f,
	FR_TAC_PLUS_PRIV_LVL_ROOT		= 0x0f,
	FR_TAC_PLUS_PRIV_LVL_USER		= 0x01,
	FR_TAC_PLUS_PRIV_LVL_MIN		= 0x00
} fr_tacacs_privlvl_t;

typedef enum {
	FR_TAC_PLUS_AUTHEN_SVC_NONE		= 0x00,
	FR_TAC_PLUS_AUTHEN_SVC_LOGIN		= 0x01,
	FR_TAC_PLUS_AUTHEN_SVC_ENABLE		= 0x02,
	FR_TAC_PLUS_AUTHEN_SVC_PPP		= 0x03,
	FR_TAC_PLUS_AUTHEN_SVC_ARAP		= 0x04,
	FR_TAC_PLUS_AUTHEN_SVC_PT		= 0x05,
	FR_TAC_PLUS_AUTHEN_SVC_RCMD		= 0x06,
	FR_TAC_PLUS_AUTHEN_SVC_X25		= 0x07,
	FR_TAC_PLUS_AUTHEN_SVC_NASI		= 0x08,
	FR_TAC_PLUS_AUTHEN_SVC_FWPROXY		= 0x09
} fr_tacacs_authenservice_t;

typedef struct CC_HINT(__packed__) {
	fr_tacacs_action_t		action:8;
	fr_tacacs_privlvl_t		priv_lvl:8;
	fr_tacacs_authentype_t		authen_type:8;
	fr_tacacs_authenservice_t	authen_service:8;
	uint8_t				user_len;
	uint8_t				port_len;
	uint8_t				rem_addr_len;
	uint8_t				data_len;
} fr_tacacs_packet_authen_start_hdr_t;

typedef enum {
	FR_TAC_PLUS_AUTHEN_STATUS_PASS		= 0x01, /* accept */
	FR_TAC_PLUS_AUTHEN_STATUS_FAIL		= 0x02, /* reject */
	FR_TAC_PLUS_AUTHEN_STATUS_GETDATA	= 0x03, /* prompt for data */
	FR_TAC_PLUS_AUTHEN_STATUS_GETUSER	= 0x04, /* prompt for username */
	FR_TAC_PLUS_AUTHEN_STATUS_GETPASS	= 0x05, /* prmpt for password */
	FR_TAC_PLUS_AUTHEN_STATUS_RESTART	= 0x06, /* client restarts with START and seq_no=1 */
	FR_TAC_PLUS_AUTHEN_STATUS_ERROR		= 0x07, /* server has unrecoverable error */
	FR_TAC_PLUS_AUTHEN_STATUS_FOLLOW	= 0x21 /* forward, should be treated as FR_TAC_PLUS_AUTHEN_STATUS_FAIL */
} fr_tacacs_authen_reply_status_t;

typedef enum {
	FR_TAC_PLUS_REPLY_FLAG_UNSET		= 0x00,	/* gdb candy */
	FR_TAC_PLUS_REPLY_FLAG_NOECHO		= 0x01
} fr_tacacs_authen_reply_flags_t;

typedef struct CC_HINT(__packed__) {
	fr_tacacs_authen_reply_status_t	status:8;
	fr_tacacs_authen_reply_flags_t	flags:8;
	uint16_t			server_msg_len;
	uint16_t			data_len;
} fr_tacacs_packet_authen_reply_hdr_t;

typedef enum {
	FR_TAC_PLUS_CONTINUE_FLAG_UNSET	= 0x00,	/* gdb candy */
	FR_TAC_PLUS_CONTINUE_FLAG_ABORT	= 0x01
} fr_tacacs_authen_cont_flags_t;

typedef struct CC_HINT(__packed__) {
	uint16_t			user_msg_len;
	uint16_t			data_len;
	fr_tacacs_authen_cont_flags_t	flags:8;
} fr_tacacs_packet_authen_cont_hdr_t;

typedef enum {
	FR_TAC_PLUS_AUTHEN_METH_NOT_SET		= 0x00,
	FR_TAC_PLUS_AUTHEN_METH_NONE		= 0x01,
	FR_TAC_PLUS_AUTHEN_METH_KRB5		= 0x02,
	FR_TAC_PLUS_AUTHEN_METH_LINE		= 0x03,
	FR_TAC_PLUS_AUTHEN_METH_ENABLE		= 0x04,
	FR_TAC_PLUS_AUTHEN_METH_LOCAL		= 0x05,
	FR_TAC_PLUS_AUTHEN_METH_TACACSPLUS	= 0x06,
	FR_TAC_PLUS_AUTHEN_METH_GUEST		= 0x08,
	FR_TAC_PLUS_AUTHEN_METH_RADIUS		= 0x10,
	FR_TAC_PLUS_AUTHEN_METH_KRB4		= 0x11,
	FR_TAC_PLUS_AUTHEN_METH_RCMD		= 0x20
} fr_tacacs_author_authen_method_t;

typedef struct CC_HINT(__packed__) {
	fr_tacacs_author_authen_method_t	authen_method:8;
	fr_tacacs_privlvl_t		priv_lvl:8;
	fr_tacacs_authentype_t		authen_type:8;
	fr_tacacs_authenservice_t		authen_service:8;
	uint8_t				user_len;
	uint8_t				port_len;
	uint8_t				rem_addr_len;
	uint8_t				arg_cnt;
	uint8_t				arg_len[];
} fr_tacacs_packet_author_req_hdr_t;

typedef enum {
	FR_TAC_PLUS_AUTHOR_STATUS_PASS_ADD	= 0x01, /* authorized, append new arguments (if any) */
	FR_TAC_PLUS_AUTHOR_STATUS_PASS_REPL	= 0x02, /* authorized, replace arguments */
	FR_TAC_PLUS_AUTHOR_STATUS_FAIL		= 0x10, /* reject */
	FR_TAC_PLUS_AUTHOR_STATUS_ERROR		= 0x11, /* server error, no argument values */
	FR_TAC_PLUS_AUTHOR_STATUS_FOLLOW	= 0x21 /* forward, should be treated as FR_TAC_PLUS_AUTHOR_STATUS_FAIL */
} fr_tacacs_author_reply_status_t;

typedef struct CC_HINT(__packed__) {
	fr_tacacs_author_reply_status_t	status:8;
	uint8_t				arg_cnt;
	uint16_t			server_msg_len;
	uint16_t			data_len;
	uint8_t				arg_len[];
} fr_tacacs_packet_author_reply_hdr_t;

typedef enum {
	FR_TAC_PLUS_ACCT_FLAG_START		= 0x02,
	FR_TAC_PLUS_ACCT_FLAG_STOP		= 0x04,
	FR_TAC_PLUS_ACCT_FLAG_WATCHDOG		= 0x08
} fr_tacacs_acct_req_flags_t;

typedef struct CC_HINT(__packed__) {
	fr_tacacs_acct_req_flags_t		flags:8;
	fr_tacacs_author_authen_method_t	authen_method:8;
	fr_tacacs_privlvl_t		priv_lvl:8;
	fr_tacacs_authentype_t		authen_type:8;
	fr_tacacs_authenservice_t		authen_service:8;
	uint8_t				user_len;
	uint8_t				port_len;
	uint8_t				rem_addr_len;
	uint8_t				arg_cnt;
	uint8_t				arg_len[];
} fr_tacacs_packet_acct_req_hdr_t;

typedef enum {
	FR_PACKET_BODY_TYPE_UNKNOWN  	= 0,
	FR_PACKET_BODY_TYPE_START    	= 1,
	FR_PACKET_BODY_TYPE_REPLY    	= 2,
	FR_PACKET_BODY_TYPE_CONTINUE 	= 3,
	FR_PACKET_BODY_TYPE_REQUEST  	= 4,
	FR_PACKET_BODY_TYPE_RESPONSE 	= 5
} fr_tacacs_packet_body_type_t;

typedef enum {
	FR_TAC_PLUS_ACCT_STATUS_SUCCESS		= 0x01,
	FR_TAC_PLUS_ACCT_STATUS_ERROR		= 0x02,
	FR_TAC_PLUS_ACCT_STATUS_FOLLOW		= 0x21 /* forward, should be treated as FR_TAC_PLUS_ACCT_STATUS_ERROR */
} fr_tacacs_acct_reply_status_t;

typedef struct CC_HINT(__packed__) {
	uint16_t			server_msg_len;
	uint16_t			data_len;
	fr_tacacs_acct_reply_status_t	status:8;
} fr_tacacs_packet_acct_reply_hdr_t;

/*
 * Technically the flexible array extensions aren't allowed
 * but clang and GCC still seem to do the right thing.
 *
 * If this ever becomes an issue the code will need to be
 * refactored.
 */
#ifdef __clang__
DIAG_OFF(flexible-array-extensions)
#endif
typedef struct CC_HINT(__packed__) {
	fr_tacacs_packet_hdr_t					hdr;
	union {
		fr_tacacs_packet_authen_start_hdr_t	authen_start;
		fr_tacacs_packet_authen_reply_hdr_t	authen_reply;
		fr_tacacs_packet_authen_cont_hdr_t	authen_cont;
		fr_tacacs_packet_author_req_hdr_t	author_req;
		fr_tacacs_packet_author_reply_hdr_t	author_reply;
		fr_tacacs_packet_acct_req_hdr_t		acct_req;
		fr_tacacs_packet_acct_reply_hdr_t	acct_reply;
	};
} fr_tacacs_packet_t;
#ifdef __clang__
DIAG_ON(flexible-array-extensions)
#endif

typedef enum {
	FR_TACACS_CODE_INVALID = 0,

	FR_TACACS_CODE_AUTH_START		= FR_PACKET_TYPE_VALUE_AUTHENTICATION_START,
	FR_TACACS_CODE_AUTH_PASS		= FR_PACKET_TYPE_VALUE_AUTHENTICATION_PASS,
	FR_TACACS_CODE_AUTH_FAIL		= FR_PACKET_TYPE_VALUE_AUTHENTICATION_FAIL,
	FR_TACACS_CODE_AUTH_GETDATA		= FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETDATA,
	FR_TACACS_CODE_AUTH_GETUSER		= FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETUSER,
	FR_TACACS_CODE_AUTH_GETPASS		= FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETPASS,
	FR_TACACS_CODE_AUTH_RESTART		= FR_PACKET_TYPE_VALUE_AUTHENTICATION_RESTART,
	FR_TACACS_CODE_AUTH_ERROR		= FR_PACKET_TYPE_VALUE_AUTHENTICATION_ERROR,

	FR_TACACS_CODE_AUTH_CONT		= FR_PACKET_TYPE_VALUE_AUTHENTICATION_CONTINUE,
	FR_TACACS_CODE_AUTH_CONT_ABORT		= FR_PACKET_TYPE_VALUE_AUTHENTICATION_CONTINUE_ABORT,

	FR_TACACS_CODE_AUTZ_REQUEST		= FR_PACKET_TYPE_VALUE_AUTHORIZATION_REQUEST,
	FR_TACACS_CODE_AUTZ_PASS_ADD     	= FR_PACKET_TYPE_VALUE_AUTHORIZATION_PASS_ADD,
	FR_TACACS_CODE_AUTZ_PASS_REPLACE	= FR_PACKET_TYPE_VALUE_AUTHORIZATION_PASS_REPLACE,
	FR_TACACS_CODE_AUTZ_FAIL		= FR_PACKET_TYPE_VALUE_AUTHORIZATION_FAIL,
	FR_TACACS_CODE_AUTZ_ERROR		= FR_PACKET_TYPE_VALUE_AUTHORIZATION_ERROR,

	FR_TACACS_CODE_ACCT_REQUEST		= FR_PACKET_TYPE_VALUE_ACCOUNTING_REQUEST,
	FR_TACACS_CODE_ACCT_SUCCESS		= FR_PACKET_TYPE_VALUE_ACCOUNTING_SUCCESS,
	FR_TACACS_CODE_ACCT_ERROR		= FR_PACKET_TYPE_VALUE_ACCOUNTING_ERROR,

	FR_TACACS_CODE_MAX = 19,
	FR_TACACS_CODE_DO_NOT_RESPOND = 256,
} fr_tacacs_packet_code_t;


#define FR_TACACS_PACKET_CODE_VALID(_code) (((_code) > 0) && ((_code) < FR_TACACS_CODE_MAX))

extern char const *fr_tacacs_packet_names[FR_TACACS_CODE_MAX];

/** Used as the decoder ctx
 *
 */
typedef struct {
	fr_dict_attr_t const *root;
	char const           *secret;
} fr_tacacs_ctx_t;

/* encode.c */
ssize_t		fr_tacacs_encode(fr_dbuff_t *dbuff, uint8_t const *original, char const *const secret, size_t secret_len,
				 unsigned int code, fr_pair_list_t *vps);

int		fr_tacacs_code_to_packet(fr_tacacs_packet_t *pkt, uint32_t code);

/* decode.c */
ssize_t fr_tacacs_decode(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *vendor, uint8_t const *buffer, size_t buffer_len,
			 UNUSED const uint8_t *original, char const * const secret, size_t secret_len, int *code);

int		fr_tacacs_packet_to_code(fr_tacacs_packet_t const *pkt);

/* base.c */
ssize_t		fr_tacacs_length(uint8_t const *buffer, size_t buffer_len);

int		fr_tacacs_global_init(void);

void		fr_tacacs_global_free(void);

int		fr_tacacs_body_xor(fr_tacacs_packet_t const *pkt, uint8_t *body, size_t body_len, char const *secret, size_t secret_len) CC_HINT(nonnull(1,2,4));

#define fr_tacacs_packet_log_hex(_log, _packet, _size) _fr_tacacs_packet_log_hex(_log, _packet, _size, __FILE__, __LINE__)
void		_fr_tacacs_packet_log_hex(fr_log_t const *log, fr_tacacs_packet_t const *packet, size_t packet_len, char const *file, int line) CC_HINT(nonnull);
