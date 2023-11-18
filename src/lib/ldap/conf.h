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
#define FR_LDAP_COMMON_CONF(_conf) { FR_CONF_OFFSET("port", FR_TYPE_UINT16, 0, _conf, handle_config.port) }, \
	{ FR_CONF_OFFSET("identity", FR_TYPE_STRING, 0, _conf, handle_config.admin_identity) }, \
	{ FR_CONF_OFFSET("password", FR_TYPE_STRING, CONF_FLAG_SECRET, _conf, handle_config.admin_password) }, \
	{ FR_CONF_OFFSET("sasl", 0, CONF_FLAG_SUBSECTION, _conf, handle_config.admin_sasl), .subcs = (void const *) fr_ldap_sasl_mech_static }, \
	{ FR_CONF_OFFSET("options", 0, CONF_FLAG_SUBSECTION, _conf, handle_config), .subcs = (void const *) fr_ldap_option_config }, \
	{ FR_CONF_OFFSET("tls", 0, CONF_FLAG_SUBSECTION, _conf, handle_config), .subcs = (void const *) fr_ldap_tls_config }
