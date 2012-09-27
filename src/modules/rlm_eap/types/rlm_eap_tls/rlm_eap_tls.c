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
	rlm_eap_tls_t *inst = (rlm_eap_tls_t *) arg;

	free(inst);

	return 0;
}


/*
 *	Attach the EAP-TLS module.
 */
static int eaptls_attach(CONF_SECTION *cs, void **instance)
{
	rlm_eap_tls_t		*inst;

	/*
	 *	Parse the config file & get all the configured values
	 */
	inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		radlog(L_ERR, "rlm_eap_tls: out of memory");
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	if (cf_section_parse(cs, inst, module_config) < 0) {
		eaptls_detach(inst);
		return -1;
	}

	inst->tls_conf = eaptls_conf_parse(cs, "tls");

	if (!inst->tls_conf) {
		radlog(L_ERR, "rlm_eap_tls: Failed initializing SSL context");
		eaptls_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}


/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static int eaptls_initiate(void *type_arg, EAP_HANDLER *handler)
{
	int		status;
	tls_session_t	*ssn;
	rlm_eap_tls_t	*inst;
	REQUEST		*request = handler->request;

	inst = type_arg;

	handler->tls = TRUE;
	handler->finished = FALSE;

	/*
	 *	EAP-TLS always requires a client certificate.
	 */
	ssn = eaptls_session(inst->tls_conf, handler, TRUE);
	if (!ssn) {
		return 0;
	}

	handler->opaque = ((void *)ssn);
	handler->free_opaque = session_free;

	/*
	 *	Set up type-specific information.
	 */
	ssn->prf_label = "client EAP encryption";

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	status = eaptls_start(handler->eap_ds, ssn->peap_flag);
	RDEBUG2("Start returned %d", status);
	if (status == 0) {
		return 0;
	}

	/*
	 *	The next stage to process the packet.
	 */
	handler->stage = AUTHENTICATE;

	return 1;
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static int eaptls_authenticate(void *type_arg, EAP_HANDLER *handler)
{
	fr_tls_status_t	status;
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;
	REQUEST *request = handler->request;
	rlm_eap_tls_t *inst;

	inst = type_arg;

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
		if (inst->virtual_server) {
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
				fake->server = inst->virtual_server;
			}

			RDEBUG("Processing EAP-TLS Certificate check:");
			debug_pair_list(fake->packet->vps);

			RDEBUG("server %s {", fake->server);

			rad_virtual_server(fake);

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
