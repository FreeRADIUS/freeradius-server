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

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef HAVE_OPENSSL_RAND_H
#include <openssl/rand.h>
#endif

#ifdef HAVE_OPENSSL_EVP_H
#include <openssl/evp.h>
#endif

#include "rlm_eap_tls.h"

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

static CONF_PARSER module_config[] = {
	{ "tls", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_tls_t, tls_conf_name), NULL },
	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_tls_t, virtual_server), NULL },
	CONF_PARSER_TERMINATOR
};


/*
 *	Attach the EAP-TLS module.
 */
static int mod_instantiate(CONF_SECTION *cs, void **instance)
{
	rlm_eap_tls_t		*inst;

	/*
	 *	Parse the config file & get all the configured values
	 */
	*instance = inst = talloc_zero(cs, rlm_eap_tls_t);
	if (!inst) return -1;

	if (cf_section_parse(cs, inst, module_config) < 0) {
		return -1;
	}

	inst->tls_conf = eaptls_conf_parse(cs, "tls");

	if (!inst->tls_conf) {
		ERROR("rlm_eap_tls: Failed initializing SSL context");
		return -1;
	}

	return 0;
}


/*
 *	Send an initial eap-tls request to the peer, using the libeap functions.
 */
static int mod_session_init(void *type_arg, eap_handler_t *handler)
{
	int		status;
	tls_session_t	*ssn;
	rlm_eap_tls_t	*inst;
	REQUEST		*request = handler->request;

	inst = type_arg;

	handler->tls = true;

	/*
	 *	EAP-TLS always requires a client certificate.
	 */
	ssn = eaptls_session(handler, inst->tls_conf, true);
	if (!ssn) {
		return 0;
	}

	handler->opaque = ((void *)ssn);

	/*
	 *	Set up type-specific information.
	 */
	ssn->prf_label = "client EAP encryption";

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	status = eaptls_start(handler->eap_ds, ssn->peap_flag);
	if ((status == FR_TLS_INVALID) || (status == FR_TLS_FAIL)) {
		REDEBUG("[eaptls start] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	} else {
		RDEBUG2("[eaptls start] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	}
	if (status == 0) return 0;

	/*
	 *	The next stage to process the packet.
	 */
	handler->stage = PROCESS;

	return 1;
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static int CC_HINT(nonnull) mod_process(void *type_arg, eap_handler_t *handler)
{
	fr_tls_status_t	status;
	int ret;
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;
	REQUEST *request = handler->request;
	rlm_eap_tls_t *inst;

	inst = type_arg;

	status = eaptls_process(handler);
	if ((status == FR_TLS_INVALID) || (status == FR_TLS_FAIL)) {
		REDEBUG("[eaptls process] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	} else {
		RDEBUG2("[eaptls process] = %s", fr_int2str(fr_tls_status_table, status, "<INVALID>"));
	}


	/*
	 *	Make request available to any SSL callbacks
	 */
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, request);
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
			rad_assert(!fake->packet->vps);

			fake->packet->vps = fr_pair_list_copy(fake->packet, request->packet->vps);

			/* set the virtual server to use */
			if ((vp = fr_pair_find_by_num(request->config, PW_VIRTUAL_SERVER, 0, TAG_ANY)) != NULL) {
				fake->server = vp->vp_strvalue;
			} else {
				fake->server = inst->virtual_server;
			}

			RDEBUG2("Validating certificate");
			rad_virtual_server(fake);

			/* copy the reply vps back to our reply */
			fr_pair_list_mcopy_by_num(request->reply, &request->reply->vps,
				  &fake->reply->vps, 0, 0, TAG_ANY);

			/* reject if virtual server didn't return accept */
			if (fake->reply->code != PW_CODE_ACCESS_ACCEPT) {
				RDEBUG2("Certificate rejected by the virtual server");
				talloc_free(fake);
				eaptls_fail(handler, 0);
				ret = 0;
				goto done;
			}

			talloc_free(fake);
			/* success */
		}
		break;

		/*
		 *	The TLS code is still working on the TLS
		 *	exchange, and it's a valid TLS request.
		 *	do nothing.
		 */
	case FR_TLS_HANDLED:
		ret = 1;
		goto done;

		/*
		 *	Handshake is done, proceed with decoding tunneled
		 *	data.
		 */
	case FR_TLS_OK:
		RDEBUG2("Received unexpected tunneled data after successful handshake");
#ifndef NDEBUG
		if ((rad_debug_lvl > 2) && fr_log_fp) {
			unsigned int i;
			unsigned int data_len;
			unsigned char buffer[1024];

			data_len = (tls_session->record_minus)(&tls_session->dirty_in,
						buffer, sizeof(buffer));
			DEBUG("  Tunneled data (%u bytes)", data_len);
			for (i = 0; i < data_len; i++) {
				if ((i & 0x0f) == 0x00) fprintf(fr_log_fp, "  %x: ", i);
				if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");

				fprintf(fr_log_fp, "%02x ", buffer[i]);
			}
			fprintf(fr_log_fp, "\n");
		}
#endif

		eaptls_fail(handler, 0);
		ret = 0;
		goto done;

		/*
		 *	Anything else: fail.
		 *
		 *	Also, remove the session from the cache so that
		 *	the client can't re-use it.
		 */
	default:
		tls_fail(tls_session);

		ret = 0;
		goto done;
	}

	/*
	 *	Success: Automatically return MPPE keys.
	 */
	ret = eaptls_success(handler, 0);

done:
	SSL_set_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_REQUEST, NULL);

	return ret;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_module_t rlm_eap_tls;
rlm_eap_module_t rlm_eap_tls = {
	.name		= "eap_tls",
	.instantiate	= mod_instantiate,	/* Create new submodule instance */
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process		/* Process next round of EAP method */
};
