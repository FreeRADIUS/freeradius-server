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

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/radiusd.h>

#ifdef WITH_TLS
void cbtls_info(SSL const *s, int where, int ret)
{
	char const *str, *state;
	REQUEST *request = SSL_get_ex_data(s, FR_TLS_EX_INDEX_REQUEST);

	if ((where & ~SSL_ST_MASK) & SSL_ST_CONNECT) {
		str="TLS_connect";
	} else if (((where & ~SSL_ST_MASK)) & SSL_ST_ACCEPT) {
		str="TLS_accept";
	} else {
		str="(other)";
	}

	state = SSL_state_string_long(s);
	state = state ? state : "<none>";

	if ((where & SSL_CB_LOOP) || (where & SSL_CB_HANDSHAKE_START) || (where & SSL_CB_HANDSHAKE_DONE)) {
		RDEBUG2("%s: %s", str, state);
		return;
	}

	if (where & SSL_CB_ALERT) {
		if ((ret & 0xff) == SSL_AD_CLOSE_NOTIFY) return;

		RERROR("TLS Alert %s:%s:%s", (where & SSL_CB_READ) ? "read": "write",
		       SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
		return;
	}

	if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			RERROR("%s: Failed in %s", str, state);
			return;
		}

		if (ret < 0) {
			if (SSL_want_read(s)) {
				RDEBUG2("%s: Need to read more data: %s", str, state);
				return;
			}
			ERROR("tls: %s: Error in %s", str, state);
		}
	}
}

/*
 *	Fill in our 'info' with TLS data.
 */
void cbtls_msg(int write_p, int msg_version, int content_type,
	       void const *buf, size_t len,
	       SSL *ssl UNUSED, void *arg)
{
	tls_session_t *state = (tls_session_t *)arg;

	/*
	 *	Work around bug #298, where we may be called with a NULL
	 *	argument.  We should really log a serious error
	 */
	if (!state) return;

	state->info.origin = (unsigned char)write_p;
	state->info.content_type = (unsigned char)content_type;
	state->info.record_len = len;
	state->info.version = msg_version;
	state->info.initialized = 1;

	if (content_type == SSL3_RT_ALERT) {
		state->info.alert_level = ((unsigned char const *)buf)[0];
		state->info.alert_description = ((unsigned char const *)buf)[1];
		state->info.handshake_type = 0x00;

	} else if (content_type == SSL3_RT_HANDSHAKE) {
		state->info.handshake_type = ((unsigned char const *)buf)[0];
		state->info.alert_level = 0x00;
		state->info.alert_description = 0x00;

#ifdef SSL3_RT_HEARTBEAT
	} else if (content_type == TLS1_RT_HEARTBEAT) {
		uint8_t *p = buf;

		if ((len >= 3) && (p[0] == 1)) {
			size_t payload_len;

			payload_len = (p[1] << 8) | p[2];

			if ((payload_len + 3) > len) {
				state->invalid_hb_used = true;
				ERROR("OpenSSL Heartbeat attack detected.  Closing connection");
				return;
			}
		}
#endif
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

#endif
