#pragma once
/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <ctype.h>

#include "config.h"

#ifdef HAVE_YKCLIENT
#include <ykclient.h>
#endif

#ifdef HAVE_YUBIKEY
#include <yubikey.h>
#endif

#define YUBIKEY_TOKEN_LEN 32

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	char const 		*name;			//!< Instance name.
	fr_dict_enum_t		*auth_type;		//!< Our Auth-Type.
	unsigned int		id_len;			//!< The length of the Public ID portion of the OTP string.
	bool			split;			//!< Split password string into components.
	bool			decrypt;		//!< Decrypt the OTP string using the yubikey library.
	bool			validate;		//!< Validate the OTP string using the ykclient library.
	char const		**uris;			//!< Yubicloud URLs to validate the token against.

#ifdef HAVE_YKCLIENT
	unsigned int		client_id;		//!< Validation API client ID.
	char const		*api_key;		//!< Validation API signing key.
	ykclient_t		*ykc;			//!< ykclient configuration.
	fr_pool_t	*pool;			//!< Connection pool instance.
#endif
} rlm_yubikey_t;


/*
 *	decrypt.c - Decryption functions
 */
rlm_rcode_t rlm_yubikey_decrypt(rlm_yubikey_t const *inst, REQUEST *request, char const *passcode);

/*
 *	validate.c - Connection pool and validation functions
 */
int rlm_yubikey_ykclient_init(CONF_SECTION *conf, rlm_yubikey_t *inst);

int rlm_yubikey_ykclient_detach(rlm_yubikey_t *inst);

rlm_rcode_t rlm_yubikey_validate(rlm_yubikey_t const *inst, REQUEST *request, char const *passcode);
