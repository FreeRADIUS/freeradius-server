/*
 * rlm_pap.h    Local Header file.
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
 * Copyright 2001-2012  The FreeRADIUS server project
 * Copyright 2012       Matthew Newton <matthew@newtoncomputing.co.uk>
 * Copyright 2001       Kostas Kalevras <kkalev@noc.ntua.gr>
 */

#ifndef _RLM_PAP_H
#define _RLM_PAP_H

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_pap_t {
	const char *name;	/* CONF_SECTION->name, not strdup'd */
	int auto_header;
	int auth_type;
} rlm_pap_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed. When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'. This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "auto_header", PW_TYPE_BOOLEAN, offsetof(rlm_pap_t,auto_header), NULL, "no" },
	{ NULL, -1, 0, NULL, NULL }
};


/*
 *	For auto-header discovery.
 */
static const FR_NAME_NUMBER header_names[] = {
	{ "{clear}",		PW_CLEARTEXT_PASSWORD },
	{ "{cleartext}",	PW_CLEARTEXT_PASSWORD },
	{ "{md5}",		PW_MD5_PASSWORD },
	{ "{BASE64_MD5}",	PW_MD5_PASSWORD },
	{ "{smd5}",		PW_SMD5_PASSWORD },
	{ "{crypt}",		PW_CRYPT_PASSWORD },
	{ "{sha}",		PW_SHA_PASSWORD },
	{ "{ssha}",		PW_SSHA_PASSWORD },
	{ "{nt}",		PW_NT_PASSWORD },
	{ "{nthash}",		PW_NT_PASSWORD },
	{ "{x-nthash}",		PW_NT_PASSWORD },
	{ "{ns-mta-md5}",	PW_NS_MTA_MD5_PASSWORD },
	{ "{x- orcllmv}",	PW_LM_PASSWORD },
	{ "{X- ORCLNTV}",	PW_NT_PASSWORD },
	{ NULL, 0 }
};


/*
 * PAP auth functions
 */

static int pap_auth_clear(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_crypt(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_md5(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_smd5(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_sha(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_ssha(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_nt(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_lm(REQUEST *, VALUE_PAIR *, char *);
static int pap_auth_ns_mta_md5(REQUEST *, VALUE_PAIR *, char *);

#endif /*_RLM_PAP_H*/
