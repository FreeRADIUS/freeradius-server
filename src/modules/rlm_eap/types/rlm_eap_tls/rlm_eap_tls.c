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
	{ "private_key_file", PW_TYPE_STRING_PTR, offsetof(EAP_TLS_CONF, private_key_file), NULL, "priv_key.pem" },
	{ "certificate_file", PW_TYPE_STRING_PTR, offsetof(EAP_TLS_CONF, certificate_file), NULL, "certificate.pem" },
	{ "CA_file", PW_TYPE_STRING_PTR, offsetof(EAP_TLS_CONF, ca_file), NULL, "ca_list.pem" },
	{ "private_key_password", PW_TYPE_STRING_PTR, offsetof(EAP_TLS_CONF, private_key_password), NULL, "pass" },
	{ "dh_file", PW_TYPE_STRING_PTR, offsetof(EAP_TLS_CONF, dh_file), NULL, "dh.pem" },
	{ "random_file", PW_TYPE_STRING_PTR, offsetof(EAP_TLS_CONF, random_file), NULL, "random.pem" },
	{ "fragment_size", PW_TYPE_INTEGER, offsetof(EAP_TLS_CONF, fragment_size), NULL, 0 },

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};


static int eaptls_attach(CONF_SECTION *cs, void **arg)
{
	SSL_CTX		 *ctx;
	EAP_TLS_CONF	 *conf;
	eap_tls_t 	 **eaptls;

	eaptls = (eap_tls_t **)arg;

	/* Parse the config file & get all the configured values */
	conf = (EAP_TLS_CONF *)malloc(sizeof(EAP_TLS_CONF));
	if (conf == NULL) {
                radlog(L_ERR, "rlm_eap_tls: out of memory");
                return -1;
        }
        if (cf_section_parse(cs, conf, module_config) < 0) {
                free(conf);
                return -1;
        }


	/* Initialize TLS */
	ctx = init_tls_ctx(conf);
	load_dh_params(ctx, conf->dh_file);
	generate_eph_rsa_key(ctx);

	/* Store all these values in the data structure for later references */
        *eaptls = (eap_tls_t *)malloc(sizeof(eap_tls_t));
        if (*eaptls == NULL) {
                radlog(L_ERR, "rlm_eap_tls: out of memory");

                free(conf->dh_file);
                free(conf->certificate_file);
                free(conf->private_key_file);
                free(conf->private_key_password);
                free(conf);
                return -1;
        }

	radlog(L_ERR, "rlm_eap_tls: conf N ctx stored ");
	(*eaptls)->conf = conf;
	(*eaptls)->ctx = ctx;

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
	printf(" private_key_file --- %s\n", eaptls->conf->private_key_file);
	printf(" certificate_file --- %s\n", eaptls->conf->certificate_file);
	printf(" CA_file --- %s\n", eaptls->conf->ca_file);
	printf(" private_key_password --- %s\n", eaptls->conf->private_key_password);
	printf(" dh_file --- %s\n", eaptls->conf->dh_file);
	printf(" random_file --- %s\n", eaptls->conf->random_file);
	printf(" fragment_size --- %d\n", eaptls->conf->fragment_size);
	*/

	/*
	 * Every new session is started only from EAP-TLS-START
	 * Before Sending EAP-TLS-START, Open a new SSL session
	 * Create all the required data structures & store them in Opaque.
	 * So that we can use these data structures when we get the response
	 */
	ssn = new_tls_session(eaptls);
	/*
	 * TLS session initialization is over
	 * Now handle TLS related hanshaking or Data
	 */
	ssn->offset = eaptls->conf->fragment_size;
	handler->opaque = ((void *)ssn);
	handler->free_opaque = session_free;
	status = eaptls_start(handler->eap_ds);
	if (status == 0)
		return 0;

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

	/* This case is when SSL generates Alert then we 
	 * send that alert to the client and then send the EAP-Failure
	 */

	status = eaptls_verify(handler->eap_ds, handler->prev_eapds);
	if (status == EAPTLS_INVALID)
		return 0;

	if (status == EAPTLS_ACK) {
		if (eaptls_ack_handler(handler) != EAPTLS_NOOP)
			return 1;
	}

	if ((tlspacket = eaptls_extract(handler->eap_ds, status)) == NULL)
		return 0;

	eaptls_operation(tlspacket, status, handler);

	return 1;
}

static int eaptls_detach(void **arg)
{
	EAP_TLS_CONF	 *conf;
	eap_tls_t 	 **eaptls;

	eaptls = (eap_tls_t **)arg;
	conf = (*eaptls)->conf;

	free(conf->dh_file);
       	conf->dh_file = NULL;
	free(conf->certificate_file);
       	conf->certificate_file = NULL;
	free(conf->private_key_file);
       	conf->private_key_file = NULL;
	free(conf->private_key_password);
       	conf->private_key_password = NULL;
	free(conf->random_file);
       	conf->random_file = NULL;

	free((*eaptls)->conf);
	(*eaptls)->conf = NULL;

	SSL_CTX_free((*eaptls)->ctx);
	(*eaptls)->ctx = NULL;
	*eaptls = NULL;

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_tls = {
	"eap_tls",
	eaptls_attach,			/* attach */
	eaptls_initiate,			/* Start the initial request, after Identity */
	eaptls_authenticate,		/* authentication */
	eaptls_detach			/* detach */
};
