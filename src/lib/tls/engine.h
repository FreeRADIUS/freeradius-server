#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifdef WITH_TLS
/**
 * $Id$
 *
 * @file lib/tls/engine.h
 * @brief Initialise and manage OpenSSL engines
 *
 * @copyright 2021 The FreeRADIUS server project
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(tls_engine_h, "$Id$")

#include <freeradius-devel/util/dlist.h>
#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Engine configuration parameters
 *
 * Used by fr_tls_global_engine_conf_t.
 */
typedef struct {
	fr_dlist_t	entry;			//!< Entry in list of controls.
	char const	*name;			//!< Name of control.
	char const	*value;			//!< Value to pass to control.
} fr_tls_engine_ctrl_t;

typedef fr_dlist_head_t fr_tls_engine_ctrl_list_t;

int fr_tls_engine_init(ENGINE **e_out,
		       char const *id, char const *instance,
		       fr_tls_engine_ctrl_list_t const *pre_ctrls, fr_tls_engine_ctrl_list_t const *post_ctrls);

int fr_tls_engine(ENGINE **e_out, char const *id, char const *instance, bool auto_init);

void fr_tls_engine_load_builtin(void);

void fr_tls_engine_free_all(void);

#ifdef __cplusplus
}
#endif
#endif
