#pragma once
/*
 * eap_peap.h
 *
 * Version:     $Id$
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
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006 The FreeRADIUS server project
 */
RCSIDH(eap_peap_h, "$Id$")

#include <freeradius-devel/eap/tls.h>
#include <freeradius-devel/soh/base.h>

typedef enum {
	PEAP_STATUS_INVALID,
	PEAP_STATUS_SENT_TLV_SUCCESS,
	PEAP_STATUS_SENT_TLV_FAILURE,
	PEAP_STATUS_TUNNEL_ESTABLISHED,
	PEAP_STATUS_INNER_IDENTITY_REQ_SENT,
	PEAP_STATUS_PHASE2_INIT,
	PEAP_STATUS_PHASE2,
	PEAP_STATUS_WAIT_FOR_SOH_RESPONSE
} peap_status;

typedef enum {
	PEAP_RESUMPTION_NO,
	PEAP_RESUMPTION_YES,
	PEAP_RESUMPTION_MAYBE
} peap_resumption;

typedef struct {
	VALUE_PAIR	*username;
	peap_status	status;
	bool		home_access_accept;
	int		default_method;
	bool		proxy_tunneled_request_as_eap;
	char const	*virtual_server;
	bool		soh;
	char const	*soh_virtual_server;
	VALUE_PAIR	*soh_reply_vps;
	peap_resumption	session_resumption_state;
} peap_tunnel_t;

extern fr_dict_attr_t const *attr_auth_type;
extern fr_dict_attr_t const *attr_eap_tls_require_client_cert;
extern fr_dict_attr_t const *attr_proxy_to_realm;
extern fr_dict_attr_t const *attr_soh_supported;

extern fr_dict_attr_t const *attr_eap_message;
extern fr_dict_attr_t const *attr_freeradius_proxied_to;
extern fr_dict_attr_t const *attr_user_name;


#define EAP_TLV_SUCCESS (1)
#define EAP_TLV_FAILURE (2)
#define EAP_TLV_ACK_RESULT (3)

#define FR_PEAP_EXTENSIONS_TYPE 33

/*
 *	Process the PEAP portion of an EAP-PEAP request.
 */
rlm_rcode_t eap_peap_process(REQUEST *request, eap_session_t *eap_session, tls_session_t *tls_session) CC_HINT(nonnull);
