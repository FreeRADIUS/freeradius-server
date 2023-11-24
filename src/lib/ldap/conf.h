#pragma once
/**
 * $Id$
 * @file lib/ldap/conf.h
 * @brief Configuration parsing for LDAP server connections.
 *
 * @copyright 2022 The FreeRADIUS Server Project.
 */

#include <freeradius-devel/ldap/base.h>

extern conf_parser_t const fr_ldap_sasl_mech_static[];
extern conf_parser_t const fr_ldap_tls_config[];
extern conf_parser_t const fr_ldap_option_config[];

/*
 *  Macro for including common LDAP configuration items
 */
#define FR_LDAP_COMMON_CONF(_conf) { FR_CONF_OFFSET("port", _conf, handle_config.port) }, \
	{ FR_CONF_OFFSET("identity", _conf, handle_config.admin_identity) }, \
	{ FR_CONF_OFFSET_FLAGS("password", CONF_FLAG_SECRET, _conf, handle_config.admin_password) }, \
	{ FR_CONF_OFFSET_SUBSECTION("sasl", 0, _conf, handle_config.admin_sasl, fr_ldap_sasl_mech_static) }, \
	{ FR_CONF_OFFSET_SUBSECTION("options", 0, _conf, handle_config, fr_ldap_option_config) }, \
	{ FR_CONF_OFFSET_SUBSECTION("tls", 0, _conf, handle_config, fr_ldap_tls_config) }
