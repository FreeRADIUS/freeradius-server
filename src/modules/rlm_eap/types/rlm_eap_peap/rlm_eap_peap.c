/*
 * rlm_eap_peap.c  contains the interfaces that are called from eap
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
 * Copyright 2003 Alan DeKok <aland@freeradius.org>
 */

#include "autoconf.h"
#include "eap_tls.h"
#include "eap_peap.h"

typedef struct rlm_eap_peap_t {
	/*
	 *	Default tunneled EAP type
	 */
	char	*default_eap_type_name;
	int	default_eap_type;

	/*
	 *	Use the reply attributes from the tunneled session in
	 *	the non-tunneled reply to the client.
	 */
	int	use_tunneled_reply;

	/*
	 *	Use SOME of the request attributes from outside of the
	 *	tunneled session in the tunneled request
	 */
	int	copy_request_to_tunnel;

	/*
	 *	Proxy tunneled session as EAP, or as de-capsulated
	 *	protocol.
	 */
	int	proxy_tunneled_request_as_eap;
} rlm_eap_peap_t;


static CONF_PARSER module_config[] = {
	{ "default_eap_type", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_peap_t, default_eap_type_name), NULL, "mschapv2" },

	{ "copy_request_to_tunnel", PW_TYPE_BOOLEAN,
	  offsetof(rlm_eap_peap_t, copy_request_to_tunnel), NULL, "no" },

	{ "use_tunneled_reply", PW_TYPE_BOOLEAN,
	  offsetof(rlm_eap_peap_t, use_tunneled_reply), NULL, "no" },

	{ "proxy_tunneled_request_as_eap", PW_TYPE_BOOLEAN,
	  offsetof(rlm_eap_peap_t, proxy_tunneled_request_as_eap), NULL, "yes" },

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

/*
 *	Detach the module.
 */
static int eappeap_detach(void *arg)
{
	rlm_eap_peap_t *inst = (rlm_eap_peap_t *) arg;

	if (inst->default_eap_type_name) free(inst->default_eap_type_name);

	free(inst);

	return 0;
}

/*
 *	Attach the module.
 */
static int eappeap_attach(CONF_SECTION *cs, void **instance)
{
	rlm_eap_peap_t *inst;

	inst = malloc(sizeof(*inst));
	if (!inst) {
		radlog(L_ERR, "rlm_eap_peap: out of memory");
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *	Parse the configuration attributes.
	 */
	if (cf_section_parse(cs, inst, module_config) < 0) {
		eappeap_detach(inst);
		return -1;
	}

	/*
	 *	Convert the name to an integer, to make it easier to
	 *	handle.
	 */
	inst->default_eap_type = eaptype_name2type(inst->default_eap_type_name);
	if (inst->default_eap_type < 0) {
		radlog(L_ERR, "rlm_eap_peap: Unknown EAP type %s",
		       inst->default_eap_type_name);
		eappeap_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}

/*
 *	Free the PEAP per-session data
 */
static void peap_free(void *p)
{
	peap_tunnel_t *t = (peap_tunnel_t *) p;

	if (!t) return;

	pairfree(&t->username);
	pairfree(&t->state);
	pairfree(&t->accept_vps);

	free(t);
}


/*
 *	Free the PEAP per-session data
 */
static peap_tunnel_t *peap_alloc(rlm_eap_peap_t *inst)
{
	peap_tunnel_t *t;

	t = rad_malloc(sizeof(*t));
	memset(t, 0, sizeof(*t));

	t->default_eap_type = inst->default_eap_type;
	t->copy_request_to_tunnel = inst->copy_request_to_tunnel;
	t->use_tunneled_reply = inst->use_tunneled_reply;
	t->proxy_tunneled_request_as_eap = inst->proxy_tunneled_request_as_eap;

	return t;
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static int eappeap_authenticate(void *arg, EAP_HANDLER *handler)
{
	int rcode;
	eaptls_status_t status;
	rlm_eap_peap_t *inst = (rlm_eap_peap_t *) arg;
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;

	DEBUG2("  rlm_eap_peap: Authenticate");

	status = eaptls_process(handler);
	DEBUG2("  eaptls_process returned %d\n", status);
	switch (status) {
		/*
		 *	EAP-TLS handshake was successful, tell the
		 *	client to keep talking.
		 *
		 *	If this was EAP-TLS, we would just return
		 *	an EAP-TLS-Success packet here.
		 */
	case EAPTLS_SUCCESS:
		{
			eap_packet_t eap_packet;

			eap_packet.code = PW_EAP_REQUEST;
			eap_packet.id = handler->eap_ds->response->id + 1;
			eap_packet.length[0] = 0;
			eap_packet.length[1] = EAP_HEADER_LEN + 1;
			eap_packet.data[0] = PW_EAP_IDENTITY;

			record_plus(&tls_session->clean_in,
				    &eap_packet, sizeof(eap_packet));

			tls_handshake_send(tls_session);
			record_init(&tls_session->clean_in);
		}
		eaptls_request(handler->eap_ds, tls_session);
		DEBUG2("  rlm_eap_peap: EAPTLS_SUCCESS");
		return 1;

		/*
		 *	The TLS code is still working on the TLS
		 *	exchange, and it's a valid TLS request.
		 *	do nothing.
		 */
	case EAPTLS_HANDLED:
		DEBUG2("  rlm_eap_peap: EAPTLS_HANDLED");
		return 1;

		/*
		 *	Handshake is done, proceed with decoding tunneled
		 *	data.
		 */
	case EAPTLS_OK:
		DEBUG2("  rlm_eap_peap: EAPTLS_OK");
		break;

		/*
		 *	Anything else: fail.
		 */
	default:
		DEBUG2("  rlm_eap_peap: EAPTLS_OTHERS");
		return 0;
	}

	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	DEBUG2("  rlm_eap_peap: Session established.  Decoding tunneled attributes.");

	/*
	 *	We may need PEAP data associated with the session, so
	 *	allocate it here, if it wasn't already alloacted.
	 */
	if (!tls_session->opaque) {
		tls_session->opaque = peap_alloc(inst);
		tls_session->free_opaque = peap_free;
	}

	/*
	 *	Process the PEAP portion of the request.
	 */
	rcode = eappeap_process(handler, tls_session);
	switch (rcode) {
	case RLM_MODULE_REJECT:
		eaptls_fail(handler->eap_ds, 0);
		return 0;

	case RLM_MODULE_HANDLED:
		eaptls_request(handler->eap_ds, tls_session);
		return 1;

	case RLM_MODULE_OK:
		eaptls_success(handler->eap_ds, 0);

		/*
		 *	Move the saved VP's from the Access-Accept to
		 *	our Access-Accept.
		 */
		if (((peap_tunnel_t *) tls_session->opaque)->accept_vps) {
			DEBUG2("  Using saved attributes from the original Access-Accept");
		}
		pairadd(&handler->request->reply->vps,
			((peap_tunnel_t *) tls_session->opaque)->accept_vps);
		((peap_tunnel_t *) tls_session->opaque)->accept_vps = NULL;

		eaptls_gen_mppe_keys(&handler->request->reply->vps,
				     tls_session->ssl,
				     "client EAP encryption");

		return 1;

		/*
		 *	No response packet, MUST be proxying it.
		 *	The main EAP module will take care of discovering
		 *	that the request now has a "proxy" packet, and
		 *	will proxy it, rather than returning an EAP packet.
		 */
	case RLM_MODULE_UPDATED:
		rad_assert(handler->request->proxy != NULL);
		return 1;
		break;

	default:
		break;
	}

	eaptls_fail(handler->eap_ds, 0);
	return 0;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_peap = {
	"eap_peap",
	eappeap_attach,			/* attach */
	/*
	 *	Note! There is NO eappeap_initate() function, as the
	 *	main EAP module takes care of calling
	 *	eaptls_initiate().
	 *
	 *	This is because PEAP is a protocol on top of TLS, so
	 *	before we need to do PEAP, we've got to initiate a TLS
	 *	session.
	 */
	NULL,				/* Start the initial request */
	NULL,				/* authorization */
	eappeap_authenticate,		/* authentication */
	eappeap_detach			/* detach */
};
