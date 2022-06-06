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
 *
 * @file ldap/conf.c
 * @brief Configuration parsing for LDAP server connections.
 *
 * @copyright 2022 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/ldap/conf.h>

CONF_PARSER const fr_ldap_sasl_mech_static[] = {
	{ FR_CONF_OFFSET("mech", FR_TYPE_STRING | FR_TYPE_NOT_EMPTY, fr_ldap_sasl_t, mech) },
	{ FR_CONF_OFFSET("proxy", FR_TYPE_STRING, fr_ldap_sasl_t, proxy) },
	{ FR_CONF_OFFSET("realm", FR_TYPE_STRING, fr_ldap_sasl_t, realm) },
	CONF_PARSER_TERMINATOR
};

/*
 *	TLS Configuration
 */
CONF_PARSER const fr_ldap_tls_config[] = {
	/*
	 *	Deprecated attributes
	 */
	{ FR_CONF_OFFSET("ca_file", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_ca_file) },

	{ FR_CONF_OFFSET("ca_path", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_ca_path) },

	{ FR_CONF_OFFSET("certificate_file", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_certificate_file) },

	{ FR_CONF_OFFSET("private_key_file", FR_TYPE_FILE_INPUT, fr_ldap_config_t, tls_private_key_file) },

	/*
	 *	LDAP Specific TLS attributes
	 */
	{ FR_CONF_OFFSET("start_tls", FR_TYPE_BOOL, fr_ldap_config_t, start_tls), .dflt = "no" },

	{ FR_CONF_OFFSET("require_cert", FR_TYPE_STRING, fr_ldap_config_t, tls_require_cert_str) },

	{ FR_CONF_OFFSET("tls_min_version", FR_TYPE_STRING, fr_ldap_config_t, tls_min_version_str) },

	CONF_PARSER_TERMINATOR
};

/*
 *	Various options that don't belong in the main configuration.
 *
 *	Note that these overlap a bit with the connection pool code!
 */
CONF_PARSER const fr_ldap_option_config[] = {
	/*
	 *	Pool config items
	 */
	{ FR_CONF_OFFSET("chase_referrals", FR_TYPE_BOOL, fr_ldap_config_t, chase_referrals) },

	{ FR_CONF_OFFSET("use_referral_credentials", FR_TYPE_BOOL, fr_ldap_config_t, use_referral_credentials), .dflt = "no" },

	{ FR_CONF_OFFSET("referral_depth", FR_TYPE_UINT16, fr_ldap_config_t, referral_depth), .dflt = "5" },

	{ FR_CONF_OFFSET("rebind", FR_TYPE_BOOL, fr_ldap_config_t, rebind) },

	{ FR_CONF_OFFSET("sasl_secprops", FR_TYPE_STRING, fr_ldap_config_t, sasl_secprops) },

	/*
	 *	We use this config option to populate libldap's LDAP_OPT_NETWORK_TIMEOUT -
	 *	timeout on network activity - specifically libldap's initial call to "connect"
	 *	Must be non-zero for async connections to start correctly.
	 */
	{ FR_CONF_OFFSET("net_timeout", FR_TYPE_TIME_DELTA, fr_ldap_config_t, net_timeout), .dflt = "10" },

	{ FR_CONF_OFFSET("idle", FR_TYPE_TIME_DELTA, fr_ldap_config_t, keepalive_idle), .dflt = "60" },

	{ FR_CONF_OFFSET("probes", FR_TYPE_UINT32, fr_ldap_config_t, keepalive_probes), .dflt = "3" },

	{ FR_CONF_OFFSET("interval", FR_TYPE_TIME_DELTA, fr_ldap_config_t, keepalive_interval), .dflt = "30" },

	{ FR_CONF_OFFSET("dereference", FR_TYPE_STRING, fr_ldap_config_t, dereference_str) },

	/* allow server unlimited time for search (server-side limit) */
	{ FR_CONF_OFFSET("srv_timelimit", FR_TYPE_TIME_DELTA, fr_ldap_config_t, srv_timelimit), .dflt = "20" },

	/*
	 *	Instance config items
	 */
	/* timeout for search results */
	{ FR_CONF_OFFSET("res_timeout", FR_TYPE_TIME_DELTA, fr_ldap_config_t, res_timeout), .dflt = "20" },

	{ FR_CONF_OFFSET("idle_timeout", FR_TYPE_TIME_DELTA, fr_ldap_config_t, idle_timeout), .dflt = "300" },

	{ FR_CONF_OFFSET("reconnection_delay", FR_TYPE_TIME_DELTA, fr_ldap_config_t, reconnection_delay), .dflt = "10" },

	CONF_PARSER_TERMINATOR
};

