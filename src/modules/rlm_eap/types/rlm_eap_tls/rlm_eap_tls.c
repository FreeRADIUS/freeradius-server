/*
 * rlm_eap_tls.c  contains the interfaces that are called from eap
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
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 * Copyright 2006  The FreeRADIUS server project
 *
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>

#ifdef HAVE_OPENSSL_RAND_H
#include <openssl/rand.h>
#endif

#ifdef HAVE_OPENSSL_EVP_H
#include <openssl/evp.h>
#endif

#include "rlm_eap_tls.h"
#include "config.h"

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/*
 *	Detach the EAP-TLS module.
 */
static int eaptls_detach(void *arg)
{
	return 0;
}


/*
 *	Attach the EAP-TLS module.
 */
static int eaptls_attach(CONF_SECTION *cs, void **instance)
{
	fr_tls_server_conf_t	 *inst;

	/*
	 *	Parse the config file & get all the configured values
	 */
	inst = tls_server_conf_parse(cs);
	if (!inst) {
		radlog(L_ERR, "rlm_eap_tls: Failed initializing SSL context");
		return -1;
	}

	/*
	 *	The EAP RFC's say 1020, but we're less picky.
	 */
	if (inst->fragment_size < 100) {
		radlog(L_ERR, "rlm_eap_tls: Fragment size is too small.");
		eaptls_detach(inst);
		return -1;
	}

	/*
	 *	The maximum size for a RADIUS packet is 4096,
	 *	minus the header (20), Message-Authenticator (18),
	 *	and State (18), etc. results in about 4000 bytes of data
	 *	that can be devoted *solely* to EAP.
	 */
	if (inst->fragment_size > 4000) {
		radlog(L_ERR, "rlm_eap_tls: Fragment size is too large.");
		eaptls_detach(inst);
		return -1;
	}

	/*
	 *	Account for the EAP header (4), and the EAP-TLS header
	 *	(6), as per Section 4.2 of RFC 2716.  What's left is
	 *	the maximum amount of data we read from a TLS buffer.
	 */
	inst->fragment_size -= 10;

	*instance = inst;

	return 0;
}


/*
 *	Send an initial eap-tls request to the peer.
 *
 *	Frame eap reply packet.
 *	len = header + type + tls_typedata
 *	tls_typedata = flags(Start (S) bit set, and no data)
 *
 *	Once having received the peer's Identity, the EAP server MUST
 *	respond with an EAP-TLS/Start packet, which is an
 *	EAP-Request packet with EAP-Type=EAP-TLS, the Start (S) bit
 *	set, and no data.  The EAP-TLS conversation will then begin,
 *	with the peer sending an EAP-Response packet with
 *	EAP-Type = EAP-TLS.  The data field of that packet will
 *	be the TLS data.
 *
 *	Fragment length is Framed-MTU - 4.
 *
 *	http://mail.frascone.com/pipermail/public/eap/2003-July/001426.html
 */
static int eaptls_initiate(void *type_arg, EAP_HANDLER *handler)
{
	int		status;
	tls_session_t	*ssn;
	fr_tls_server_conf_t	*inst;
	VALUE_PAIR	*vp;
	int		client_cert = TRUE;
	int		verify_mode = 0;
	REQUEST		*request = handler->request;

	inst = type_arg;

	handler->tls = TRUE;
	handler->finished = FALSE;

	/*
	 *	If we're TTLS or PEAP, then do NOT require a client
	 *	certificate.
	 *
	 *	FIXME: This should be more configurable.
	 */
	if (handler->eap_type != PW_EAP_TLS) {
		vp = pairfind(handler->request->config_items,
			      PW_EAP_TLS_REQUIRE_CLIENT_CERT, 0);
		if (!vp) {
			client_cert = FALSE;
		} else {
			client_cert = vp->vp_integer;
		}
	}

	/*
	 *	Every new session is started only from EAP-TLS-START.
	 *	Before Sending EAP-TLS-START, open a new SSL session.
	 *	Create all the required data structures & store them
	 *	in Opaque.  So that we can use these data structures
	 *	when we get the response
	 */
	ssn = tls_new_session(inst, request, client_cert);
	if (!ssn) {
		return 0;
	}

	/*
	 *	Verify the peer certificate, if asked.
	 */
	if (client_cert) {
		RDEBUG2("Requiring client certificate");
		verify_mode = SSL_VERIFY_PEER;
		verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		verify_mode |= SSL_VERIFY_CLIENT_ONCE;
	}
	SSL_set_verify(ssn->ssl, verify_mode, cbtls_verify);

	/*
	 *	Create a structure for all the items required to be
	 *	verified for each client and set that as opaque data
	 *	structure.
	 *
	 *	NOTE: If we want to set each item sepearately then
	 *	this index should be global.
	 */
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_HANDLER, (void *)handler);
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_CONF, (void *)inst);
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_CERTS, (void *)&(handler->certs));
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_IDENTITY, (void *)&(handler->identity));
#ifdef HAVE_OPENSSL_OCSP_H
	SSL_set_ex_data(ssn->ssl, FR_TLS_EX_INDEX_STORE, (void *)inst->ocsp_store);
#endif

	handler->opaque = ((void *)ssn);
	handler->free_opaque = session_free;

	/*
	 *	Set up type-specific information.
	 */
	switch (handler->eap_type) {
	case PW_EAP_TLS:
	default:
		ssn->prf_label = "client EAP encryption";
		break;

	case PW_EAP_TTLS:
		ssn->prf_label = "ttls keying material";
		break;

		/*
		 *	PEAP-specific breakage.
		 */
	case PW_EAP_PEAP:
		/*
		 *	As it is a poorly designed protocol, PEAP uses
		 *	bits in the TLS header to indicate PEAP
		 *	version numbers.  For now, we only support
		 *	PEAP version 0, so it doesn't matter too much.
		 *	However, if we support later versions of PEAP,
		 *	we will need this flag to indicate which
		 *	version we're currently dealing with.
		 */
		ssn->peap_flag = 0x00;

		/*
		 *	PEAP version 0 requires 'include_length = no',
		 *	so rather than hoping the user figures it out,
		 *	we force it here.
		 */
		ssn->length_flag = 0;

		ssn->prf_label = "client EAP encryption";
		break;
	}

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	status = eaptls_start(handler->eap_ds, ssn->peap_flag);
	RDEBUG2("Start returned %d", status);
	if (status == 0)
		return 0;

	/*
	 *	The next stage to process the packet.
	 */
	handler->stage = AUTHENTICATE;

	return 1;
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static int eaptls_authenticate(UNUSED void *arg, EAP_HANDLER *handler)
{
	fr_tls_status_t	status;
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;
	REQUEST *request = handler->request;
	fr_tls_server_conf_t *conf;

	RDEBUG2("Authenticate");

	status = eaptls_process(handler);
	RDEBUG2("eaptls_process returned %d\n", status);
	switch (status) {
		/*
		 *	EAP-TLS handshake was successful, return an
		 *	EAP-TLS-Success packet here.
		 *
		 *	If a virtual server was configured, check that
		 *	it accepts the certificates, too.
		 */
	case FR_TLS_SUCCESS:
		conf = SSL_get_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_CONF);
		if (conf && conf->virtual_server) {
			VALUE_PAIR *vp;
			REQUEST *fake;

			/* create a fake request */
			fake = request_alloc_fake(request);
			rad_assert(fake->packet->vps == NULL);

			fake->packet->vps = paircopy(request->packet->vps);

			/* set the virtual server to use */
			if ((vp = pairfind(request->config_items,
					   PW_VIRTUAL_SERVER, 0)) != NULL) {
				fake->server = vp->vp_strvalue;
			} else {
				fake->server = conf->virtual_server;
			}

			RDEBUG("Processing EAP-TLS Certificate check:");
			debug_pair_list(fake->packet->vps);

			RDEBUG("server %s {", fake->server);

			rad_authenticate(fake);

			RDEBUG("} # server %s", fake->server);

			/* copy the reply vps back to our reply */
			pairadd(&request->reply->vps, fake->reply->vps);
			fake->reply->vps = NULL;

			/* reject if virtual server didn't return accept */
			if (fake->reply->code != PW_AUTHENTICATION_ACK) {
				RDEBUG2("Certifictes were rejected by the virtual server");
				request_free(&fake);
				eaptls_fail(handler, 0);
				return 0;
			}

			request_free(&fake);
			/* success */
		}
		break;

		/*
		 *	The TLS code is still working on the TLS
		 *	exchange, and it's a valid TLS request.
		 *	do nothing.
		 */
	case FR_TLS_HANDLED:
		return 1;

		/*
		 *	Handshake is done, proceed with decoding tunneled
		 *	data.
		 */
	case FR_TLS_OK:
		RDEBUG2("Received unexpected tunneled data after successful handshake.");
#ifndef NDEBUG
		if ((debug_flag > 2) && fr_log_fp) {
			unsigned int i;
			unsigned int data_len;
			unsigned char buffer[1024];

			data_len = (tls_session->record_minus)(&tls_session->dirty_in,
						buffer, sizeof(buffer));
			log_debug("  Tunneled data (%u bytes)\n", data_len);
			for (i = 0; i < data_len; i++) {
				if ((i & 0x0f) == 0x00) fprintf(fr_log_fp, "  %x: ", i);
				if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");

				fprintf(fr_log_fp, "%02x ", buffer[i]);
			}
			fprintf(fr_log_fp, "\n");
		}
#endif

		eaptls_fail(handler, 0);
		return 0;
		break;

		/*
		 *	Anything else: fail.
		 *
		 *	Also, remove the session from the cache so that
		 *	the client can't re-use it.
		 */
	default:
		tls_fail(tls_session);

		return 0;
	}

	/*
	 *	Success: Automatically return MPPE keys.
	 */
	return eaptls_success(handler, 0);
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_tls = {
	"eap_tls",
	eaptls_attach,			/* attach */
	eaptls_initiate,		/* Start the initial request */
	NULL,				/* authorization */
	eaptls_authenticate,		/* authentication */
	eaptls_detach			/* detach */
};
