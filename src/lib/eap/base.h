#pragma once
/*
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
 */

/**
 * $Id$
 * @file lib/eap/base.h
 * @brief Interface into the base EAP library
 *
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(lib_eap_base_h, "$Id$")

#include <freeradius-devel/eap/types.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/rad_assert.h>

#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/eap/compose.h>
#include <freeradius-devel/eap/types.h>
#include <freeradius-devel/eap/session.h>
#include <freeradius-devel/eap/submodule.h>
#include <freeradius-devel/eap/types.h>

/* TLS configuration name */
#define TLS_CONFIG_SECTION "tls-config"

#define EAP_STATE_LEN (RADIUS_AUTH_VECTOR_LENGTH)

#define REQUEST_DATA_EAP_TUNNEL_CALLBACK FR_EAP_MESSAGE
#define REQUEST_DATA_EAP_MSCHAP_TUNNEL_CALLBACK ((FR_EAP_MESSAGE << 16) | FR_EAP_METHOD_MSCHAPV2)


#define EAP_SECTION_COMPILE(_out, _field, _verb, _name) \
do { \
	CONF_SECTION *_tmp; \
	_tmp = cf_section_find(server_cs, _verb, _name); \
	if (_tmp) { \
		if (unlang_compile(_tmp, MOD_AUTHORIZE, NULL, NULL) < 0) return -1; \
		found = true; \
	} \
	if (_out) _out->_field = _tmp; \
} while (0)

#define EAP_PROCESS_SECTION_COMPILE(_out, _field, _verb, _name) \
do { \
	CONF_SECTION *_tmp; \
	_tmp = cf_section_find(server_cs, _verb, _name); \
	if (_tmp) { \
		if (unlang_compile(_tmp, MOD_AUTHENTICATE, NULL, NULL) < 0) return -1; \
		found = true; \
	} \
	if (_out) _out->_field = _tmp; \
} while (0)


/*
 *	This is for tunneled callbacks
 */
typedef int (*eap_tunnel_callback_t)(eap_session_t *eap_session, void *tls_session);

typedef struct {
	void			*tls_session;
	eap_tunnel_callback_t	callback;
} eap_tunnel_data_t;


/*
 *	interfaces in eapcommon.c
 */
VALUE_PAIR		*eap_packet_to_vp(RADIUS_PACKET *packet, eap_packet_raw_t const *reply);
eap_packet_raw_t	*eap_packet_from_vp(TALLOC_CTX *ctx, VALUE_PAIR *vps);
void			eap_add_reply(REQUEST *request, fr_dict_attr_t const *da, uint8_t const *value, int len);

rlm_rcode_t		eap_virtual_server(REQUEST *request, eap_session_t *eap_session, char const *virtual_server);

int			eap_base_init(void);

void			eap_base_free(void);

