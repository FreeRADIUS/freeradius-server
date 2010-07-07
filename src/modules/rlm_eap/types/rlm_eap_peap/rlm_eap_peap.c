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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2003 Alan DeKok <aland@freeradius.org>
 * Copyright 2006 The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
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

#ifdef WITH_PROXY
	/*
	 *	Proxy tunneled session as EAP, or as de-capsulated
	 *	protocol.
	 */
	int	proxy_tunneled_request_as_eap;
#endif

	/*
	 *	Virtual server for inner tunnel session.
	 */
  	char	*virtual_server;
} rlm_eap_peap_t;


static CONF_PARSER module_config[] = {
	{ "default_eap_type", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_peap_t, default_eap_type_name), NULL, "mschapv2" },

	{ "copy_request_to_tunnel", PW_TYPE_BOOLEAN,
	  offsetof(rlm_eap_peap_t, copy_request_to_tunnel), NULL, "no" },

	{ "use_tunneled_reply", PW_TYPE_BOOLEAN,
	  offsetof(rlm_eap_peap_t, use_tunneled_reply), NULL, "no" },

#ifdef WITH_PROXY
	{ "proxy_tunneled_request_as_eap", PW_TYPE_BOOLEAN,
	  offsetof(rlm_eap_peap_t, proxy_tunneled_request_as_eap), NULL, "yes" },
#endif

	{ "virtual_server", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_peap_t, virtual_server), NULL, NULL },

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

/*
 *	Detach the module.
 */
static int eappeap_detach(void *arg)
{
	rlm_eap_peap_t *inst = (rlm_eap_peap_t *) arg;


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
#ifdef WITH_PROXY
	t->proxy_tunneled_request_as_eap = inst->proxy_tunneled_request_as_eap;
#endif
	t->virtual_server = inst->virtual_server;
	t->session_resumption_state = PEAP_RESUMPTION_MAYBE;

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
	peap_tunnel_t *peap = tls_session->opaque;
	REQUEST *request = handler->request;

	/*
	 *	Session resumption requires the storage of data, so
	 *	allocate it if it doesn't already exist.
	 */
	if (!tls_session->opaque) {
		peap = tls_session->opaque = peap_alloc(inst);
		tls_session->free_opaque = peap_free;
	}

	status = eaptls_process(handler);
	RDEBUG2("eaptls_process returned %d\n", status);
	switch (status) {
		/*
		 *	EAP-TLS handshake was successful, tell the
		 *	client to keep talking.
		 *
		 *	If this was EAP-TLS, we would just return
		 *	an EAP-TLS-Success packet here.
		 */
	case EAPTLS_SUCCESS:
		RDEBUG2("EAPTLS_SUCCESS");
		peap->status = PEAP_STATUS_TUNNEL_ESTABLISHED;
		break;

		/*
		 *	The TLS code is still working on the TLS
		 *	exchange, and it's a valid TLS request.
		 *	do nothing.
		 */
	case EAPTLS_HANDLED:
	  /*
	   *	FIXME: If the SSL session is established, grab the state
	   *	and EAP id from the inner tunnel, and update it with
	   *	the expected EAP id!
	   */
		RDEBUG2("EAPTLS_HANDLED");
		return 1;

		/*
		 *	Handshake is done, proceed with decoding tunneled
		 *	data.
		 */
	case EAPTLS_OK:
		RDEBUG2("EAPTLS_OK");
		break;

		/*
		 *	Anything else: fail.
		 */
	default:
		RDEBUG2("EAPTLS_OTHERS");
		return 0;
	}

	/*
	 *	Session is established, proceed with decoding
	 *	tunneled data.
	 */
	RDEBUG2("Session established.  Decoding tunneled attributes.");

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
		eaptls_fail(handler, 0);
		return 0;

	case RLM_MODULE_HANDLED:
		eaptls_request(handler->eap_ds, tls_session);
		return 1;

	case RLM_MODULE_OK:
		/*
		 *	Move the saved VP's from the Access-Accept to
		 *	our Access-Accept.
		 */
		peap = tls_session->opaque;
		if (peap->accept_vps) {
			RDEBUG2("Using saved attributes from the original Access-Accept");
			debug_pair_list(peap->accept_vps);
			pairadd(&handler->request->reply->vps, peap->accept_vps);
			peap->accept_vps = NULL;
		}

		/*
		 *	Success: Automatically return MPPE keys.
		 */
		return eaptls_success(handler, 0);

		/*
		 *	No response packet, MUST be proxying it.
		 *	The main EAP module will take care of discovering
		 *	that the request now has a "proxy" packet, and
		 *	will proxy it, rather than returning an EAP packet.
		 */
	case RLM_MODULE_UPDATED:
#ifdef WITH_PROXY
		rad_assert(handler->request->proxy != NULL);
#endif
		return 1;
		break;

	default:
		break;
	}

	eaptls_fail(handler, 0);
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
