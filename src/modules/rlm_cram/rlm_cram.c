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

/**
 * $Id$
 * @file rlm_cram.c
 * @brief CRAM mail authentication (APOP, CRAM-MD5)
   @verbatim
	Attributes used (Vendor Code/PEN: 11406, you may change it to your own)
	101 (Sandy-Mail-Authtype), selects CRAM protocol, possible values:
		2: CRAM-MD5
		3: APOP
		8: CRAM-MD4
		9: CRAM-SHA1
	102 (Sandy-Mail-Challenge), contains server's challenge (usually
	text banner)
	103 (Sandy-Mail-Response), contains client's response, 16 octets
	for APOP/CRAM-MD5/CRAM-MD4, 20 octets for CRAM-SHA1
   @endverbatim
 * @copyright 2001,2006  The FreeRADIUS server project
 * @copyright 2002 SANDY (http://www.sandy.ru/) under GPLr
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_cram - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>

#include <freeradius-devel/util/md5.h>

#include <ctype.h>

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_cram_dict[];
fr_dict_autoload_t rlm_cram_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_cleartext_password;

static fr_dict_attr_t const *attr_sandy_mail_authtype;
static fr_dict_attr_t const *attr_sandy_mail_challenge;
static fr_dict_attr_t const *attr_sandy_mail_response;

extern fr_dict_attr_autoload_t rlm_cram_dict_attr[];
fr_dict_attr_autoload_t rlm_cram_dict_attr[] = {
	{ .out = &attr_cleartext_password, .name = "Cleartext-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_sandy_mail_authtype, .name = "Sandy-Mail-Authtype", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_sandy_mail_challenge, .name = "Sandy-Mail-Challenge", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_sandy_mail_response, .name = "Sandy-Mail-Response", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ NULL }
};

static void calc_apop_digest(uint8_t *buffer, uint8_t const *challenge,
			     size_t challen, char const *password)
{
	FR_MD5_CTX context;

	fr_md5_init(&context);
	fr_md5_update(&context, challenge, challen);
	fr_md5_update(&context, (uint8_t const *) password, strlen(password));
	fr_md5_final(buffer, &context);
}


static void calc_md5_digest(uint8_t *buffer, uint8_t const *challenge, size_t challen, char const *password)
{
	uint8_t buf[1024];
	int i;
	FR_MD5_CTX context;

	memset(buf, 0, 1024);
	memset(buf, 0x36, 64);
	for(i=0; i<64 && password[i]; i++) buf[i]^=password[i];
	memcpy(buf+64, challenge, challen);
	fr_md5_init(&context);
	fr_md5_update(&context, buf, 64+challen);
	memset(buf, 0x5c, 64);
	for(i=0; i<64 && password[i]; i++) buf[i]^=password[i];
	fr_md5_final(buf+64,&context);
	fr_md5_init(&context);
	fr_md5_update(&context,buf,64+16);
	fr_md5_final(buffer,&context);
}

static void calc_md4_digest(uint8_t *buffer, uint8_t const *challenge, size_t challen, char const *password)
{
	uint8_t buf[1024];
	int i;
	FR_MD4_CTX context;

	memset(buf, 0, 1024);
	memset(buf, 0x36, 64);
	for(i=0; i<64 && password[i]; i++) buf[i]^=password[i];
	memcpy(buf+64, challenge, challen);
	fr_md4_init(&context);
	fr_md4_update(&context,buf,64+challen);
	memset(buf, 0x5c, 64);
	for(i=0; i<64 && password[i]; i++) buf[i]^=password[i];
	fr_md4_final(buf+64,&context);
	fr_md4_init(&context);
	fr_md4_update(&context,buf,64+16);
	fr_md4_final(buffer,&context);
}

static void calc_sha1_digest(uint8_t *buffer, uint8_t const *challenge,
			     size_t challen, char const *password)
{
	uint8_t buf[1024];
	int i;
	fr_sha1_ctx context;

	memset(buf, 0, 1024);			//-V512
	memset(buf, 0x36, 64);			//-V512
	for(i=0; i<64 && password[i]; i++) buf[i]^=password[i];
	memcpy(buf+64, challenge, challen);
	fr_sha1_init(&context);
	fr_sha1_update(&context,buf,64+challen);
	memset(buf, 0x5c, 64);			//-V512
	for(i=0; i<64 && password[i]; i++) buf[i]^=password[i];
	fr_sha1_final(buf+64,&context);
	fr_sha1_init(&context);
	fr_sha1_update(&context,buf,64+20);
	fr_sha1_final(buffer,&context);
}


static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(UNUSED void *instance, UNUSED void *thread, REQUEST *request)
{
	VALUE_PAIR *authtype, *challenge, *response, *password;


	password = fr_pair_find_by_da(request->control, attr_cleartext_password, TAG_ANY);
	if (!password) {
		REDEBUG("&Cleartext-Password is required for authentication");
		return RLM_MODULE_INVALID;
	}

	authtype = fr_pair_find_by_da(request->packet->vps, attr_sandy_mail_authtype, TAG_ANY);
	if (!authtype) {
		REDEBUG("Required attribute &Sandy-Mail-Authtype missing");
		return RLM_MODULE_INVALID;
	}

	challenge = fr_pair_find_by_da(request->packet->vps, attr_sandy_mail_challenge, TAG_ANY);
	if (!challenge) {
		REDEBUG("Required attribute &Sandy-Mail-Challenge missing");
		return RLM_MODULE_INVALID;
	}

	response = fr_pair_find_by_da(request->packet->vps, attr_sandy_mail_response, TAG_ANY);
	if (!response) {
		REDEBUG("Required attribute &Sandy-Mail-Response missing");
		return RLM_MODULE_INVALID;
	}

	switch (authtype->vp_uint32){
		case 2:				/*	CRAM-MD5	*/
		{
			uint8_t buffer[MD5_DIGEST_LENGTH];

			if (challenge->vp_length < 5 || response->vp_length != 16) {
				REDEBUG("Invalid MD5 challenge/response length");
				return RLM_MODULE_INVALID;
			}
			calc_md5_digest(buffer, challenge->vp_octets, challenge->vp_length, password->vp_strvalue);
			if (!memcmp(buffer, response->vp_octets, sizeof(buffer))) return RLM_MODULE_OK;
		}
			break;

		case 3:				/*	APOP	*/
		{
			uint8_t buffer[16];

			if (challenge->vp_length < 5 || response->vp_length != 16) {
				REDEBUG("Invalid APOP challenge/response length");
				return RLM_MODULE_INVALID;
			}
			calc_apop_digest(buffer, challenge->vp_octets, challenge->vp_length, password->vp_strvalue);
			if (!memcmp(buffer, response->vp_octets, sizeof(buffer))) return RLM_MODULE_OK;
		}
			break;

		case 8:				/*	CRAM-MD4	*/
		{
			uint8_t buffer[MD4_DIGEST_LENGTH];

			if (challenge->vp_length < 5 || response->vp_length != 16) {
				REDEBUG("Invalid MD4 challenge/response length");
				return RLM_MODULE_INVALID;
			}
			calc_md4_digest(buffer, challenge->vp_octets, challenge->vp_length, password->vp_strvalue);
			if (!memcmp(buffer, response->vp_octets, sizeof(buffer))) return RLM_MODULE_OK;
		}
			break;

		case 9:				/*	CRAM-SHA1	*/
		{
			uint8_t buffer[SHA1_DIGEST_LENGTH];

			if (challenge->vp_length < 5 || response->vp_length != 20) {
				REDEBUG("Invalid MD4 challenge/response length");
				return RLM_MODULE_INVALID;
			}
			calc_sha1_digest(buffer, challenge->vp_octets, challenge->vp_length, password->vp_strvalue);
			if (!memcmp(buffer, response->vp_octets, sizeof(buffer))) return RLM_MODULE_OK;
		}
			break;

		default:
			REDEBUG("Unsupported &Sandy-Mail-Authtype");
			return RLM_MODULE_INVALID;
	}
	return RLM_MODULE_NOTFOUND;

}

extern rad_module_t rlm_cram;
rad_module_t rlm_cram = {
	.magic		= RLM_MODULE_INIT,
	.name		= "cram",
	.type		= RLM_TYPE_THREAD_SAFE,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate
	},
};
