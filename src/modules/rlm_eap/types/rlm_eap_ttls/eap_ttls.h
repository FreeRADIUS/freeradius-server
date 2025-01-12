#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file eap_ttls.h
 * @brief Declarations for EAP-TTLS as defined by RFC 5281
 *
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006 The FreeRADIUS server project
 */
RCSIDH(eap_ttls_h, "$Id$")

#include <freeradius-devel/eap/tls.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/radius/defs.h>

extern HIDDEN fr_dict_attr_t const *attr_eap_tls_require_client_cert;
extern HIDDEN fr_dict_attr_t const *attr_chap_challenge;
extern HIDDEN fr_dict_attr_t const *attr_ms_chap2_success;
extern HIDDEN fr_dict_attr_t const *attr_eap_message;
extern HIDDEN fr_dict_attr_t const *attr_ms_chap_challenge;
extern HIDDEN fr_dict_attr_t const *attr_reply_message;
extern HIDDEN fr_dict_attr_t const *attr_eap_channel_binding_message;
extern HIDDEN fr_dict_attr_t const *attr_user_name;
extern HIDDEN fr_dict_attr_t const *attr_user_password;
extern HIDDEN fr_dict_attr_t const *attr_vendor_specific;

typedef struct {
	fr_pair_t	*username;
	bool		authenticated;
	CONF_SECTION	*server_cs;
} ttls_tunnel_t;

/*
 *	Process the TTLS portion of an EAP-TTLS request.
 */
unlang_action_t eap_ttls_process(request_t *request, eap_session_t *eap_session, fr_tls_session_t *tls_session) CC_HINT(nonnull);
unlang_action_t eap_ttls_success(rlm_rcode_t *p_result, request_t *request, eap_session_t *eap_session);
