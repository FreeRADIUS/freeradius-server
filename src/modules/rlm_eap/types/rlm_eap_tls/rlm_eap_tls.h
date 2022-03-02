#pragma once
/*
 * rlm_eap_tls.h
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
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006 The FreeRADIUS server project
 */
RCSIDH(rlm_eap_tls_h, "$Id$")

#include <freeradius-devel/eap/tls.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>

/** Cache sections to call on various protocol events
 *
 */
typedef struct {
	CONF_SECTION			*recv_access_request;
} eap_tls_actions_t;

typedef struct {
	/*
	 *	TLS configuration
	 */
	char const		*tls_conf_name;		//!< The name of the shared TLS configuration.
	fr_tls_conf_t		*tls_conf;		//!< Shared TLS configuration structure.

	bool			include_length;

	bool			req_client_cert;	//!< Whether we require the client to provide
							//!< a certificate or not.  RFC 5216 says it's
							//!< not mandatory, and there are some situations
							//!< where it's useful to allow client access without
							//!< a certificate.

	char const		*virtual_server;	//!< Virtual server used for validating certificates.
} rlm_eap_tls_t;
