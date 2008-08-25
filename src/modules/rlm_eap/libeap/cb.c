/*
 * cb.c
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
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include "eap_tls.h"

#ifndef NO_OPENSSL

void cbtls_info(const SSL *s, int where, int ret)
{
	const char *str, *state;
	int w;
	EAP_HANDLER *handler = (EAP_HANDLER *)SSL_get_ex_data(s, 0);
	REQUEST *request = NULL;

	if (handler) request = handler->request;

	w = where & ~SSL_ST_MASK;
	if (w & SSL_ST_CONNECT) str="    TLS_connect";
	else if (w & SSL_ST_ACCEPT) str="    TLS_accept";
	else str="    (other)";

	state = SSL_state_string_long(s);
	state = state ? state : "NULL";

	if (where & SSL_CB_LOOP) {
		RDEBUG2("%s: %s\n", str, state);
	} else if (where & SSL_CB_HANDSHAKE_START) {
		RDEBUG2("%s: %s\n", str, state);
	} else if (where & SSL_CB_HANDSHAKE_DONE) {
		RDEBUG2("%s: %s\n", str, state);
	} else if (where & SSL_CB_ALERT) {
		str=(where & SSL_CB_READ)?"read":"write";
		radlog(L_ERR,"TLS Alert %s:%s:%s\n", str,
			SSL_alert_type_string_long(ret),
			SSL_alert_desc_string_long(ret));
	} else if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			radlog(L_ERR, "%s:failed in %s\n", str, state);
		} else if (ret < 0) {
			if (SSL_want_read(s)) {
				RDEBUG2("%s: Need to read more data: %s",
				       str, state);
			} else {
				radlog(L_ERR, "%s:error in %s\n", str, state);
			}
		}
	}
}

/*
 *	Fill in our 'info' with TLS data.
 */
void cbtls_msg(int write_p, int msg_version, int content_type,
	       const void *buf, size_t len,
	       SSL *ssl UNUSED, void *arg)
{
	tls_session_t *state = (tls_session_t *)arg;

	/*
	 *	Work around bug #298, where we may be called with a NULL
	 *	argument.  We should really log a serious error
	 */
	if (!arg) return;

	state->info.origin = (unsigned char)write_p;
	state->info.content_type = (unsigned char)content_type;
	state->info.record_len = len;
	state->info.version = msg_version;
	state->info.initialized = 1;

	if (content_type == SSL3_RT_ALERT) {
		state->info.alert_level = ((const unsigned char*)buf)[0];
		state->info.alert_description = ((const unsigned char*)buf)[1];
		state->info.handshake_type = 0x00;

	} else if (content_type == SSL3_RT_HANDSHAKE) {
		state->info.handshake_type = ((const unsigned char*)buf)[0];
		state->info.alert_level = 0x00;
		state->info.alert_description = 0x00;
	}
	tls_session_information(state);
}

int cbtls_password(char *buf,
		   int num UNUSED,
		   int rwflag UNUSED,
		   void *userdata)
{
	strcpy(buf, (char *)userdata);
	return(strlen((char *)userdata));
}

/*
 *	For callbacks
 */
int eaptls_handle_idx = -1;
int eaptls_conf_idx = -1;
int eaptls_session_idx = -1;

#endif /* !defined(NO_OPENSSL) */
