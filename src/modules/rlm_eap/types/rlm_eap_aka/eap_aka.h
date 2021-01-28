/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file rlm_eap_aka/eap_aka.h
 * @brief Declarations for EAP-AKA
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Network RADIUS SARL (sales@networkradius.com)
 */
RCSIDH(rlm_eap_aka_eap_aka_h, "$Id$")

#include <freeradius-devel/sim/base.h>

/** Server states
 *
 * In server_start, we send a EAP-AKA Start message.
 */
typedef enum {
	EAP_AKA_SERVER_IDENTITY = 0,					//!< Attempting to discover permanent
									///< identity of the supplicant.
	EAP_AKA_SERVER_CHALLENGE,					//!< We've challenged the supplicant.
	EAP_AKA_SERVER_SUCCESS_NOTIFICATION,				//!< Send success notification.
	EAP_AKA_SERVER_SUCCESS,						//!< Authentication completed successfully.
	EAP_AKA_SERVER_FAILURE_NOTIFICATION,				//!< Send failure notification.
	EAP_AKA_SERVER_FAILURE,						//!< Send an EAP-Failure.
	EAP_AKA_SERVER_MAX_STATES
} eap_aka_server_state_t;

/** Cache sections to call on various protocol events
 *
 */
typedef struct {
	CONF_SECTION			*recv_eap_identity_response;	//!< The initial state, entered into
									///< after we receive an EAP-Identity-Response.
									///< The result of this section determines
									///< whether we send a:
									///< - AKA-Identity-Request - i.e. requesting
									///<   a different ID.
									///< - Challenge-Request - Containing the
									///<   necessary vectors for full
									///<   authentication.
									///< - Fast-Reauth-Request - Containing the
									///<   vectors for fast re-authentication.

	CONF_SECTION			*send_identity_request;		//!< Called when we're about to request a
									///< different identity.
	CONF_SECTION			*recv_identity_response;	//!< Called when we receive a new identity.

	CONF_SECTION			*send_challenge_request;	//!< Called when we're about to send a
									///< a challenge.
	CONF_SECTION			*recv_challenge_response;	//!< Called when we receive a response
									///< to a previous challenge.

	CONF_SECTION			*send_fast_reauth_request;	//!< Called when we're about to send a
									///< Fast-Reauth-Request.
	CONF_SECTION			*recv_fast_reauth_response;	//!< Called when we receive a response
									///< to a previous Fast-Reauth-Request.

	CONF_SECTION			*recv_client_error;		//!< Called if the supplicant experiences
									///< an error of some kind.
	CONF_SECTION			*recv_authentication_reject;	//!< Called if the supplicant rejects the
									///< authentication attempt.
	CONF_SECTION			*recv_syncronization_failure;	//!< Called if the supplicant determines
									///< the AUTN value is invalid.
									///< Usually used for resyncing with the HLR.

	CONF_SECTION			*send_failure_notification;	//!< Called when we're about to send a
									///< EAP-AKA failure notification.
	CONF_SECTION			*send_success_notification;	//!< Called when we're about to send a
									///< EAP-AKA success notification.
	CONF_SECTION			*recv_failure_notification_ack;	//!< Called when the supplicant ACKs our
									///< failure notification.
	CONF_SECTION			*recv_success_notification_ack;	//!< Called when the supplicant ACKs our
									///< success notification.

	CONF_SECTION			*send_eap_success;		//!< Called when we send an EAP-Success message.
	CONF_SECTION			*send_eap_failure;		//!< Called when we send an EAP-Failure message.

	CONF_SECTION			*load_session;			//!< Load cached authentication vectors.
	CONF_SECTION			*store_session;			//!< Store authentication vectors.
	CONF_SECTION			*clear_session;			//!< Clear authentication vectors.
} eap_aka_actions_t;

typedef struct {
	eap_aka_server_state_t		state;				//!< Current session state.
	bool				allow_encrypted;		//!< Whether we can send encrypted attributes.
	bool				challenge_success;		//!< Whether we received the correct
									///< challenge response.

	fr_sim_id_req_type_t		id_req;				//!< The type of identity we're requesting
									///< or previously requested.
	fr_sim_keys_t			keys;				//!< Various EAP-AKA keys.

	eap_type_t			type;				//!< Either FR_TYPE_AKA, or FR_TYPE_AKA_PRIME.
	uint16_t			kdf;				//!< The key derivation function used to derive
									///< session keys.

	/*
	 *	Per-session configuration
	 */
	uint32_t       			request_identity;		//!< Always send an identity request before a
									///< challenge.
	bool				send_result_ind;		//!< Say that we would like to use protected
									///< result indications
									///< (AKA-Notification-Success).
	bool				send_at_bidding;		//!< Indicate that we prefer EAP-AKA' and
									///< include an AT_BIDDING attribute.

	EVP_MD const			*checkcode_md;			//!< Message digest we use to generate the
									///< checkcode. EVP_sha1() for EAP-AKA,
									///< EVP_sha256() for EAP-AKA'.
	fr_sim_checkcode_t		*checkcode_state;		//!< Digest of all identity packets we've seen.
	uint8_t				checkcode[32];			//!< Checkcode we calculated.
	size_t				checkcode_len;			//!< 0, 20 or 32 bytes.

	EVP_MD const			*mac_md;			//!< HMAC-MD we use to generate the MAC.
									///< EVP_sha1() for EAP-AKA, EVP_sha256()
									///< for EAP-AKA'.

	int  				aka_id;				//!< Packet ID. (replay protection).
} eap_aka_session_t;

typedef struct {
	char const			*network_name;			//!< Network ID as described by RFC 5448.
	request_identity       		request_identity;		//!< Whether we always request the identity of
									///< the subscriber.
	char const			*virtual_server;		//!< Virtual server for HLR integration.
	bool				protected_success;

	eap_aka_actions_t		actions;			//!< Pre-compiled virtual server sections.
} rlm_eap_aka_t;
