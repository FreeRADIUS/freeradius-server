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
 */

/*
 * $Id$
 *
 * @file protocols/bfd/bfd.h
 * @brief Structures and prototypes for base BFD functionality.
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/dbuff.h>

typedef enum bfd_session_state_t {
	BFD_STATE_ADMIN_DOWN = 0,
	BFD_STATE_DOWN,
	BFD_STATE_INIT,
	BFD_STATE_UP
} bfd_session_state_t;

typedef enum bfd_diag_t {
	BFD_DIAG_NONE = 0,
	BFD_CTRL_EXPIRED,
	BFD_ECHO_FAILED,
	BFD_NEIGHBOR_DOWN,
	BFD_FORWARD_PLANE_RESET,
	BFD_PATH_DOWN,
	BFD_CONCATENATED_PATH_DOWN,
	BFD_ADMIN_DOWN,
	BFD_REVERSE_CONCAT_PATH_DOWN
} bfd_diag_t;

typedef enum bfd_auth_type_t {
	BFD_AUTH_RESERVED = 0,
	BFD_AUTH_SIMPLE,
	BFD_AUTH_KEYED_MD5,
	BFD_AUTH_MET_KEYED_MD5,
	BFD_AUTH_KEYED_SHA1,
	BFD_AUTH_MET_KEYED_SHA1,
} bfd_auth_type_t;

#define BFD_AUTH_INVALID (BFD_AUTH_MET_KEYED_SHA1 + 1)

typedef struct {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
} __attribute__ ((packed)) bfd_auth_basic_t;


typedef struct {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
	uint8_t		password[16];
} __attribute__ ((packed)) bfd_auth_simple_t;

typedef struct {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
	uint8_t		reserved;
	uint32_t	sequence_no;
	uint8_t		digest[MD5_DIGEST_LENGTH];
} __attribute__ ((packed)) bfd_auth_md5_t;

typedef struct {
	uint8_t		auth_type;
	uint8_t		auth_len;
	uint8_t		key_id;
	uint8_t		reserved;
	uint32_t	sequence_no;
	uint8_t		digest[SHA1_DIGEST_LENGTH];
} __attribute__ ((packed)) bfd_auth_sha1_t;

typedef union bfd_auth_t {
	union {
		bfd_auth_basic_t        basic;
		bfd_auth_simple_t	password;
		bfd_auth_md5_t		md5;
		bfd_auth_sha1_t		sha1;
	};
} __attribute__ ((packed)) bfd_auth_t;


/*
 *	A packet
 */
typedef struct {
#ifdef WORDS_BIGENDIAN
	unsigned int	version : 3;
	unsigned int	diag : 5;
	unsigned int	state : 2;
	unsigned int	poll : 1;
	unsigned int	final : 1;
	unsigned int	control_plane_independent : 1;
	unsigned int	auth_present : 1;
	unsigned int	demand : 1;
	unsigned int	multipoint : 1;
#else
	unsigned int	diag : 5;
	unsigned int	version : 3;

	unsigned int	multipoint : 1;
	unsigned int	demand : 1;
	unsigned int	auth_present : 1;
	unsigned int	control_plane_independent : 1;
	unsigned int	final : 1;
	unsigned int	poll : 1;
	unsigned int	state : 2;
#endif
	uint8_t		detect_multi;
	uint8_t		length;
	uint32_t	my_disc;
	uint32_t	your_disc;
	uint32_t	desired_min_tx_interval;
	uint32_t	required_min_rx_interval;
	uint32_t	min_echo_rx_interval;
	bfd_auth_t	auth;
} __attribute__ ((packed)) bfd_packet_t;

#define FR_BFD_HEADER_LENGTH (24)

typedef enum {
	FR_BFD_ADMIN_DOWN,
	FR_BFD_DOWN,
	FR_BFD_INIT,
	FR_BFD_UP,
} fr_bfd_packet_code_t;
#define FR_BFD_CODE_MAX (4)

extern char const *fr_bfd_packet_names[FR_BFD_CODE_MAX];
#define FR_BFD_PACKET_CODE_VALID(_code) (_code < FR_BFD_CODE_MAX)

typedef struct {
	TALLOC_CTX		*tmp_ctx;		//!< for temporary things cleaned up during decoding
	char const		*secret;		//!< shared secret.  MUST be talloc'd
} fr_bfd_ctx_t;

ssize_t		fr_bfd_encode(uint8_t *packet, size_t packet_len,  uint8_t const *original,
			      char const *secret,  size_t secret_len, fr_pair_list_t *vps);

ssize_t		fr_bfd_decode(TALLOC_CTX *ctx, fr_pair_list_t *out,
			      uint8_t const *packet, size_t packet_len,
			      char const *secret, size_t secret_len);

bool		fr_bfd_packet_ok(char const **err, uint8_t const *packet, size_t packet_len);

int	fr_bfd_init(void);
void	fr_bfd_free(void);

extern fr_table_num_ordered_t const bfd_auth_type_table[];
extern size_t const bfd_auth_type_table_len;
