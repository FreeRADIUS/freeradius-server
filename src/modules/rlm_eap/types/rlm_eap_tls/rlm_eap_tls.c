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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */

#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>
#include "eap_tls.h"

static CONF_PARSER module_config[] = {
	{ "rsa_key_exchange", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, rsa_key), NULL, "no" },
	{ "dh_key_exchange", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, dh_key), NULL, "yes" },
	{ "rsa_key_length", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, rsa_key_length), NULL, "512" },
	{ "dh_key_length", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, dh_key_length), NULL, "512" },
	{ "verify_depth", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, verify_depth), NULL, "0" },
	{ "CA_path", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, ca_path), NULL, NULL },
	{ "pem_file_type", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, file_type), NULL, "yes" },
	{ "private_key_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, private_key_file), NULL, NULL },
	{ "certificate_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, certificate_file), NULL, NULL },
	{ "CA_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, ca_file), NULL, NULL },
	{ "private_key_password", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, private_key_password), NULL, NULL },
	{ "dh_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, dh_file), NULL, NULL },
	{ "random_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, random_file), NULL, NULL },
	{ "fragment_size", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, fragment_size), NULL, "1024" },
	{ "include_length", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, include_length), NULL, "yes" },

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};


static int eaptls_detach(void *arg)
{
	EAP_TLS_CONF	 *conf;
	eap_tls_t 	 *inst;

	inst = (eap_tls_t *) arg;
	conf = inst->conf;

	if (conf) {
		if (conf->dh_file) free(conf->dh_file);
		conf->dh_file = NULL;
		if (conf->certificate_file) free(conf->certificate_file);
		conf->certificate_file = NULL;
		if (conf->private_key_file) free(conf->private_key_file);
		conf->private_key_file = NULL;
		if (conf->private_key_password) free(conf->private_key_password);
		conf->private_key_password = NULL;
		if (conf->random_file) free(conf->random_file);
		conf->random_file = NULL;
		
		free(inst->conf);
		inst->conf = NULL;
	}

	if (inst->ctx) SSL_CTX_free(inst->ctx);
	inst->ctx = NULL;

	free(inst);

	return 0;
}

static int eaptls_attach(CONF_SECTION *cs, void **instance)
{
	SSL_CTX		 *ctx;
	EAP_TLS_CONF	 *conf;
	eap_tls_t 	 *inst;

	/* Store all these values in the data structure for later references */
	inst = (eap_tls_t *)malloc(sizeof(*inst));
	if (!inst) {
		radlog(L_ERR, "rlm_eap_tls: out of memory");
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/* Parse the config file & get all the configured values */
	conf = (EAP_TLS_CONF *)malloc(sizeof(*conf));
	if (conf == NULL) {
		radlog(L_ERR, "rlm_eap_tls: out of memory");
		return -1;
	}
	memset(conf, 0, sizeof(*conf));

	inst->conf = conf;
	if (cf_section_parse(cs, conf, module_config) < 0) {
		eaptls_detach(inst);
		return -1;
	}


	/* Initialize TLS */
	ctx = init_tls_ctx(conf);
	if (ctx == NULL) {
		eaptls_detach(inst);
		return -1;
	}
	inst->ctx = ctx;

	if (load_dh_params(ctx, conf->dh_file) < 0) {
		eaptls_detach(inst);
		return -1;
	}
	if (generate_eph_rsa_key(ctx) < 0) {
		eaptls_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}


/*
 * send an initial eap-tls request
 * ie access challenge to the user/peer.

 * Frame eap reply packet.
 * len = header + type + tls_typedata
 * tls_typedata = flags(Start (S) bit set, and no data)

 * Once having received the peer's Identity, the EAP server MUST respond
 * with an EAP-TLS/Start packet, which is an EAP-Request packet with
 * EAP-Type=EAP-TLS, the Start (S) bit set, and no data.  The EAP-TLS
 * conversation will then begin, with the peer sending an EAP-Response
 * packet with EAP-Type=EAP-TLS.  The data field of that packet will
 */
static int eaptls_initiate(void *type_arg, EAP_HANDLER *handler)
{
	int status;
	tls_session_t *ssn;
	eap_tls_t    *eaptls;

	eaptls = (eap_tls_t *)type_arg;

	/*
	 * Every new session is started only from EAP-TLS-START
	 * Before Sending EAP-TLS-START, Open a new SSL session
	 * Create all the required data structures & store them in Opaque.
	 * So that we can use these data structures when we get the response
	 */
	ssn = new_tls_session(eaptls);

	/*
	 * Create a structure for all the items required to 
	 * be verified for each client and set that
	 * as opaque data structure.
	 *
	 * NOTE: If we want to set each item sepearately then
	 * this index should be global.
	 */
	SSL_set_ex_data(ssn->ssl, 0, (void *)handler->identity);

	ssn->offset = eaptls->conf->fragment_size;
	ssn->length_flag = eaptls->conf->include_length;

	handler->opaque = ((void *)ssn);
	handler->free_opaque = session_free;

	DEBUG2("  rlm_eap_tls: Initiate");

	/*
	 * TLS session initialization is over
	 * Now handle TLS related hanshaking or Data
	 */
	status = eaptls_start(handler->eap_ds);
	DEBUG2("  rlm_eap_tls: Start returned %d", status);
	if (status == 0)
		return 0;

	/*
	 *	The next stage to process the packet.
	 */
	handler->stage = AUTHENTICATE;

	return 1;
}

/*
 * In the actual authentication first verify the packet and then create the data structure
 */
/*
 * To process the TLS,
 *  INCOMING DATA:
 * 	1. EAP-TLS should get the compelete TLS data from the peer.
 * 	2. Store that data in a data structure with any other required info
 *	3. Hand this data structure to the TLS module.
 *	4. TLS module will perform its operations on the data and hands back to EAP-TLS
 *  OUTGOING DATA:
 * 	1. EAP-TLS if necessary will fragment it and send it to the destination.
 *
 * During EAP-TLS initialization, TLS Context object will be initialized and stored.
 * For every new authentication requests, TLS will open a new session object and that
 * session object should be *maintained* even after the session is completed, for
 * session resumption. (Probably later as a feature, as we donot know who maintains these
 * session objects ie, SSL_CTX (internally) or TLS module(explicitly). If TLS module, then
 * how to let SSL API know about these sessions.)
 */
static int eaptls_authenticate(void *arg, EAP_HANDLER *handler)
{
	//tls_session_t *tls_session;
	EAPTLS_PACKET	*tlspacket;
	eaptls_status_t	status;

	DEBUG2("  rlm_eap_tls: Authenticate");

	/* This case is when SSL generates Alert then we 
	 * send that alert to the client and then send the EAP-Failure
	 */
	status = eaptls_verify(handler->eap_ds, handler->prev_eapds);
	if (status == EAPTLS_INVALID)
		return 0;

	/* In case of EAPTLS_ACK, we need to send the next fragment
	 * or send success or failure
	 */
	if (status == EAPTLS_ACK) {
		if (eaptls_ack_handler(handler) != EAPTLS_NOOP)
			return 1;
		else
			return 0;
	}

	if ((tlspacket = eaptls_extract(handler->eap_ds, status)) == NULL)
		return 0;

	eaptls_operation(tlspacket, status, handler);

	eaptls_free(&tlspacket);
	return 1;
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
