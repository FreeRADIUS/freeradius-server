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

conf_parser_t const fr_ldap_sasl_mech_static[] = {
	{ FR_CONF_OFFSET_FLAGS("mech", CONF_FLAG_NOT_EMPTY, fr_ldap_sasl_t, mech) },
	{ FR_CONF_OFFSET("proxy", fr_ldap_sasl_t, proxy) },
	{ FR_CONF_OFFSET("realm", fr_ldap_sasl_t, realm) },
	CONF_PARSER_TERMINATOR
};

/*
 *	TLS Configuration
 */
conf_parser_t const fr_ldap_tls_config[] = {
	/*
	 *	Deprecated attributes
	 */
	{ FR_CONF_OFFSET_FLAGS("ca_file", CONF_FLAG_FILE_INPUT, fr_ldap_config_t, tls_ca_file) },

	{ FR_CONF_OFFSET_FLAGS("ca_path", CONF_FLAG_FILE_INPUT, fr_ldap_config_t, tls_ca_path) },

	{ FR_CONF_OFFSET_FLAGS("certificate_file", CONF_FLAG_FILE_INPUT, fr_ldap_config_t, tls_certificate_file) },

	{ FR_CONF_OFFSET_FLAGS("private_key_file", CONF_FLAG_FILE_INPUT, fr_ldap_config_t, tls_private_key_file) },

	/*
	 *	LDAP Specific TLS attributes
	 */
	{ FR_CONF_OFFSET("start_tls", fr_ldap_config_t, start_tls), .dflt = "no" },

	{ FR_CONF_OFFSET("require_cert", fr_ldap_config_t, tls_require_cert_str) },

	{ FR_CONF_OFFSET("tls_min_version", fr_ldap_config_t, tls_min_version_str) },

	CONF_PARSER_TERMINATOR
};

/*
 *	Various options that don't belong in the main configuration.
 *
 *	Note that these overlap a bit with the connection pool code!
 */
conf_parser_t const fr_ldap_option_config[] = {
	/*
	 *	Pool config items
	 */
	{ FR_CONF_OFFSET("chase_referrals", fr_ldap_config_t, chase_referrals) },

	{ FR_CONF_OFFSET("use_referral_credentials", fr_ldap_config_t, use_referral_credentials), .dflt = "no" },

	{ FR_CONF_OFFSET("referral_depth", fr_ldap_config_t, referral_depth), .dflt = "5" },

	{ FR_CONF_OFFSET("rebind", fr_ldap_config_t, rebind) },

	{ FR_CONF_OFFSET("sasl_secprops", fr_ldap_config_t, sasl_secprops) },

	/*
	 *	We use this config option to populate libldap's LDAP_OPT_NETWORK_TIMEOUT -
	 *	timeout on network activity - specifically libldap's initial call to "connect"
	 *	Must be non-zero for async connections to start correctly.
	 */
	{ FR_CONF_OFFSET("net_timeout", fr_ldap_config_t, net_timeout), .dflt = "10" },

	{ FR_CONF_OFFSET("idle", fr_ldap_config_t, keepalive_idle), .dflt = "60" },

	{ FR_CONF_OFFSET("probes", fr_ldap_config_t, keepalive_probes), .dflt = "3" },

	{ FR_CONF_OFFSET("interval", fr_ldap_config_t, keepalive_interval), .dflt = "30" },

	{ FR_CONF_OFFSET("dereference", fr_ldap_config_t, dereference_str) },

	/* allow server unlimited time for search (server-side limit) */
	{ FR_CONF_OFFSET("srv_timelimit", fr_ldap_config_t, srv_timelimit), .dflt = "20" },

	/*
	 *	Instance config items
	 */
	/* timeout for search results */
	{ FR_CONF_OFFSET("res_timeout", fr_ldap_config_t, res_timeout), .dflt = "20" },

	{ FR_CONF_OFFSET("idle_timeout", fr_ldap_config_t, idle_timeout), .dflt = "300" },

	{ FR_CONF_OFFSET("reconnection_delay", fr_ldap_config_t, reconnection_delay), .dflt = "10" },

	CONF_PARSER_TERMINATOR
};
