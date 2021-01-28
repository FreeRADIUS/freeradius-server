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
 * @file lib/ldap/start_tls.c
 * @brief Start TLS asynchronously
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/ldap/base.h>

#define STATE_TRANSITION(_new) \
do { \
	DEBUG4("Changed state %s -> %s", \
	       fr_table_str_by_value(fr_ldap_connection_states, c->state, "<INVALID>"), \
	       fr_table_str_by_value(fr_ldap_connection_states, _new, "<INVALID>")); \
	c->state = _new; \
} while (0)

/** Move between LDAP connection states
 *
 * Bringing up an LDAP connection is quite complex, as we need to do multiple operations
 * before we can install the main mux/demux functions which do the work of sending
 * requests to the directory and processing the responses.
 *
 * This function moves the connection through different states, setting different I/O
 * handlers.
 *
 * If any of the states
 */
fr_ldap_state_t fr_ldap_state_next(fr_ldap_connection_t *c)
{
again:
	switch (c->state) {
	/*
	 *	Start by negotiating TLS, or binding
	 */
	case FR_LDAP_STATE_INIT:
		if (c->config->start_tls) {
			if (fr_ldap_start_tls_async(c, NULL, NULL) < 0) {
				STATE_TRANSITION(FR_LDAP_STATE_ERROR);
				goto again;
			}
			STATE_TRANSITION(FR_LDAP_STATE_START_TLS);
			break;
		}
		FALL_THROUGH;

	/*
	 *	If we're successful in negotiating TLS,
	 *	bind to the server as the credentials
	 *	will now be protected.
	 */
	case FR_LDAP_STATE_START_TLS:
		STATE_TRANSITION(FR_LDAP_STATE_BIND);

		/*
		 *	SASL uses a different (and more complex) codepath
		 */
#ifdef WITH_SASL
		if (c->config->admin_sasl.mech) {
			if (fr_ldap_sasl_bind_async(c,
						    c->config->admin_sasl.mech,
						    c->config->admin_identity,
						    c->config->admin_password,
						    c->config->admin_sasl.proxy,
						    c->config->admin_sasl.realm,
						    NULL, NULL) < 0) {
				STATE_TRANSITION(FR_LDAP_STATE_ERROR);
				goto again;
			}
			break;
		}
#endif

		/*
		 *	Normal binds are just a simple request/response pair
		 */
		if (fr_ldap_bind_async(c,
				       c->config->admin_identity,
				       c->config->admin_password,
				       NULL, NULL) < 0) {
			STATE_TRANSITION(FR_LDAP_STATE_ERROR);
			goto again;
		}
		break;

	/*
	 *	After binding install the mux (write) and
	 *	demux (read) I/O functions.
	 */
	case FR_LDAP_STATE_BIND:
		STATE_TRANSITION(FR_LDAP_STATE_RUN);
	/*
		if (fr_ldap_mux_async(c) < 0) {
			STATE_TRANSITION(FR_LDAP_STATE_ERROR);
			goto again;
		}
	 */
		break;

	/*
	 *	Something went wrong
	 */
	case FR_LDAP_STATE_RUN:		/* There's no next state for run, so this an error */
	case FR_LDAP_STATE_ERROR:
		STATE_TRANSITION(FR_LDAP_STATE_INIT);
		fr_connection_signal_reconnect(c->conn, FR_CONNECTION_FAILED);
		break;
	}

	return c->state;
}

/** Signal that there's been an error on the connection
 *
 */
void fr_ldap_state_error(fr_ldap_connection_t *c)
{
	STATE_TRANSITION(FR_LDAP_STATE_ERROR);
	fr_ldap_state_next(c);
}

