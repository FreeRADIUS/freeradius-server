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
 * @file lib/eap_aka_sim/state_machine.h
 * @brief Declarations for EAP-AKA
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2016-2019 The FreeRADIUS server project
 * @copyright 2016-2019 Network RADIUS SARL <sales@networkradius.com>
 */
RCSIDH(lib_eap_aka_sim_state_machine_h, "$Id$")

#include <freeradius-devel/eap_aka_sim/base.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct eap_aka_sim_session_s eap_aka_sim_session_t;

/** The state function which should receive any incoming packets
 *
 */
typedef unlang_action_t (*eap_aka_sim_state_t)(rlm_rcode_t *p_result, module_ctx_t const *mctx,
					       request_t *request, eap_aka_sim_session_t *eap_aka_sim_session);

/** The function to execute after common code has completed
 *
 * Mostly used to set functions to run after pseudonym and session
 * loading/clearing/storing is complete.
 */
typedef unlang_action_t (*eap_aka_sim_next_t)(rlm_rcode_t *p_result, module_ctx_t const *mctx,
					      request_t *request, eap_aka_sim_session_t *eap_aka_sim_session);

struct eap_aka_sim_session_s {
	/*
	 *	State machine management
	 */
	eap_aka_sim_state_t		state;				//!< The process function to run when we
									///< receive the next round of EAP-SIM/AKA/AKA'.

	eap_aka_sim_next_t		next;				//!< Resumption function to call after
									///< executing common code.

	eap_type_t			type;				//!< Either FR_TYPE_AKA, or FR_TYPE_AKA_PRIME.

	bool				challenge_success;		//!< Whether we received the correct
									///< challenge response.
	bool				reauthentication_success;	//!< Whether we got a valid reauthentication
									///< response.

	bool				allow_encrypted;		//!< Whether we can send encrypted
									///< attributes at this phase of the attempt.

	uint16_t			failure_type;			//!< One of the following values:
									///< - FR_NOTIFICATION_VALUE_GENERAL_FAILURE_AFTER_AUTHENTICATION
									///< - FR_NOTIFICATION_VALUE_TEMPORARILY_DENIED
									///< - FR_NOTIFICATION_VALUE_NOT_SUBSCRIBED
									///< - FR_NOTIFICATION_VALUE_GENERAL_FAILURE

	/*
	 *	Identity management
	 */
	char				*pseudonym_sent;		//!< Pseudonym value we sent.
	char				*fastauth_sent;			//!< Fastauth value we sent.

	fr_aka_sim_id_req_type_t	id_req;				//!< The type of identity we're requesting
	fr_aka_sim_id_req_type_t	last_id_req;			//!< The last identity request we sent.

	/*
	 *	Per-session configuration
	 */

	bool				send_result_ind;		//!< Say that we would like to use protected
									///< result indications
									///< (AKA-Notification-Success).

	bool				prev_recv_sync_failure;		//!< We only allow one sync failure per
									///< session for sanity.


	fr_aka_sim_keys_t		keys;				//!< Various EAP-AKA/AKA'/SIMkeys.

	EVP_MD const			*checkcode_md;			//!< Message digest we use to generate the
									///< checkcode. EVP_sha1() for EAP-AKA/SIM,
									///< EVP_sha256() for EAP-AKA'.
	fr_aka_sim_checkcode_t		*checkcode_state;		//!< Digest of all identity packets we've seen.
	uint8_t				checkcode[32];			//!< Checkcode we calculated.
	size_t				checkcode_len;			//!< 0, 20 or 32 bytes.


	uint16_t			kdf;				//!< The key derivation function used to derive
									///< session keys.

	EVP_MD const			*mac_md;			//!< HMAC-MD we use to generate the MAC.
									///< EVP_sha1() for EAP-AKA, EVP_sha256()
									///< for EAP-AKA'.
};

/** Cache sections to call on various protocol events
 *
 */
typedef struct {
	union {
		/** @name EAP-AKA specific sections
		 *
		 * @{
		 */
		 struct {
			CONF_SECTION	*send_aka_identity_request;	//!< Called when we're about to request a
									///< different identity.
			CONF_SECTION	*recv_aka_identity_response;	//!< Called when we receive a new identity.

			CONF_SECTION	*recv_aka_authentication_reject;//!< Called if the supplicant rejects the
									///< authentication attempt.
			CONF_SECTION	*recv_aka_syncronization_failure;//!< Called if the supplicant determines
									///< the AUTN value is invalid.
									///< Usually used for resyncing with the HLR.

			CONF_SECTION	*send_aka_challenge_request;	//!< Called when we're about to send a
									///< a challenge.
			CONF_SECTION	*recv_aka_challenge_response;	//!< Called when we receive a response
									///< to a previous challenge.
		};
		/** @} */

		/** @name EAP-SIM specific sections
		 *
		 * @{
		 */
		struct {
			CONF_SECTION	*send_sim_challenge_request;	//!< Called when we're about to send a
									///< a challenge.
			CONF_SECTION	*recv_sim_challenge_response;	//!< Called when we receive a response
									///< to a previous challenge.

			CONF_SECTION	*send_sim_start_request;	//!< Called when we're about to request a
									///< different identity.
			CONF_SECTION	*recv_sim_start_response;	//!< Called when we receive a new identity.
		};
		/** @} */
	};

	/** @name Common protocol sections for all methods
	 *
	 * @{
	 */
	CONF_SECTION	*send_common_identity_request;			//!< Called when we're about to request a
									///< different identity.
	CONF_SECTION	*recv_common_identity_response;			//!< Called when we receive a new identity.

	CONF_SECTION	*recv_common_client_error;			//!< Called if the supplicant experiences
									///< an error of some kind.

	CONF_SECTION	*send_common_reauthentication_request;		//!< Challenge the supplicant with an MK
									///< from an existing session.

	CONF_SECTION	*recv_common_reauthentication_response; 	//!< Process the reauthentication response
									///< from the supplicant.

	CONF_SECTION	*recv_common_failure_notification_ack;		//!< Called when the supplicant ACKs our
									///< failure notification.

	CONF_SECTION	*send_common_failure_notification;		//!< Called when we're about to send a
									///< failure notification.

	CONF_SECTION	*recv_common_success_notification_ack;		//!< Called when the supplicant ACKs our
									///< success notification.

	CONF_SECTION	*send_common_success_notification;		//!< Called when we're about to send a
									///< success notification.


	CONF_SECTION	*send_eap_success;				//!< Called when we send an EAP-Success message.
	CONF_SECTION	*send_eap_failure;				//!< Called when we send an EAP-Failure message.
	/** @} */

	/** @name Internal sections for caching
	 *
	 * @{
	 */
	CONF_SECTION	*load_pseudonym;				//!< Resolve a pseudonym to a permanent ID.
	CONF_SECTION	*store_pseudonym;				//!< Store a permanent ID to pseudonym mapping.
	CONF_SECTION	*clear_pseudonym;				//!< Clear pseudonym to permanent ID mapping.

	CONF_SECTION	*load_session;					//!< Load cached authentication vectors.
	CONF_SECTION	*store_session;					//!< Store authentication vectors.
	CONF_SECTION	*clear_session;					//!< Clear authentication vectors.
	/** @} */
} eap_aka_sim_actions_t;

typedef struct {
	eap_type_t			type;				//!< The preferred EAP-Type of this instance
									///< of the EAP-SIM/AKA/AKA' state machine.

	char const			*network_name;			//!< Network ID as described by RFC 5448.
	fr_aka_sim_id_req_type_t	request_identity;		//!< Whether we always request the identity of
									///< the subscriber.
	size_t				ephemeral_id_length;		//!< The length of any identities we're
									///< generating.

	bool				protected_success;		//!< Send a success notification as well as
									///< and EAP-Success packet.

	bool				strip_permanent_identity_hint;	//!< Control whether the hint byte is stripped
									///< when populating Permanent-Identity.

	EVP_MD const			*hmac_md;			//!< The hmac used for validating packets.
									///< EVP_sha1() for EAP-AKA, EVP_sha256()
									///< for EAP-AKA'.

	EVP_MD const			*checkcode_md;			//!< The hmac used for validating packets
									///< checkcodes.

	eap_aka_sim_actions_t		actions;			//!< Pre-compiled virtual server sections.
} eap_aka_sim_process_conf_t;

unlang_action_t eap_aka_sim_state_machine_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request);

#ifdef __cplusplus
}
#endif

