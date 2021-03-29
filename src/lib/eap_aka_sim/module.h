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
 * @file lib/eap_aka_sim/module.h
 * @brief Declarations for the common module functions used by EAP-SIM/AKA submodules
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2016-2019 The FreeRADIUS server project
 * @copyright 2016-2019 Network RADIUS SARL <sales@networkradius.com>
 */
RCSIDH(lib_eap_aka_sim_module_h, "$Id$")

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/eap/types.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	CONF_SECTION    		*virtual_server;		//!< Virtual server.

	/** Whether we should include a bid-down prevention attribute by default
	 *
	 * Only used for EAP-AKA, as a signal that EAP-AKA' was available/enabled
	 * on the server, and if the client supports EAP-AKA', it should continue
	 * with that EAP-Method instead.
	 */
	struct {
		bool				send_at_bidding_prefer_prime;	//!< Include the AT bidding attribute in
										///< challenge requests.
		bool				send_at_bidding_prefer_prime_is_set;	//!< Whether the user specified
											///< a value.
	} aka;

	eap_type_t			type;
} eap_aka_sim_module_conf_t;

/** Structure used to track session state at the module level
 *
 * The process module has a similar structure (eap_aka_sim_module_t) which tracks
 * all of the cryptographic parameters for the session.
 *
 * The structure here stores copies of the cryptographic parameters used for
 * validating incoming packets, and signing outgoing packets, from control attributes
 * provided by the state machine.
 *
 * This separation is to allow the process module to be executed without the
 * submodule, so that the state machine can be tested independently of the
 * encode/decode/crypto code.
 */
typedef struct {
	uint8_t			id;			//!< Last ID used, monotonically increments.

	uint8_t			*response_hmac_extra;	//!< Data to concatenate to response packet
							///< before validating.
	size_t			response_hmac_extra_len;

	fr_aka_sim_ctx_t	ctx;
} eap_aka_sim_mod_session_t;

unlang_action_t		eap_aka_sim_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request);

#ifdef __cplusplus
}
#endif
