/*
 *  rlm_eap_ikev2.c - Handles that are called from eap
 *
 *  This file is part of rlm_eap_ikev2 freeRADIUS module which implements
 *  EAP-IKEv2 protocol functionality.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Copyright (C) 2005-2006 Krzysztof Rzecki <krzysztof.rzecki@ccns.pl>
 *  Copyright (C) 2005-2006 Rafal Mijal <rafal.mijal@ccns.pl>
 *  Copyright (C) 2005-2006 Piotr Marnik <piotr.marnik@ccns.pl>
 *  Copyright (C) 2005-2006 Pawel Matejski <pawel.matejski@ccns.pl>
 *  Copyright 1999-2007 The FreeRADIUS server project
 *
 */

#include <freeradius-devel/radiusd.h>
#include "eap.h"

#include <assert.h>
#include <freeradius-devel/rad_assert.h>

#include "logging_impl.h"
#include <EAPIKEv2/connector.h>
#include "ike_conf.h"

typedef enum {
	PW_IKEV2_CHALLENGE = 1,
	PW_IKEV2_RESPONSE,
	PW_IKEV2_SUCCESS,
	PW_IKEV2_FAILURE,
	PW_IKEV2_MAX_CODES
} pw_ikev2_code;

#define IKEV2_HEADER_LEN	4
#define IKEV2_MPPE_KEY_LEN     32

typedef struct rlm_eap_ikev2 {
	char const	*tls_ca_file;			//!< Sets the full path to a CA certificate (used to validate
							//!< the certificate the server presents).

	char const	*tls_private_key_file;		//!< Sets the path to the private key for our public
							//!< certificate.
	char const	*tls_private_key_password;	//!< Sets the path to the private key for our public
							//!< certificate.

	char const	*tls_certificate_file;		//!< Sets the path to the public certificate file we present
							//!< to the servers.
	char const	*tls_crl;

	char const	*id;
	uint32_t	max_fragment_size;
	uint32_t	dh_counter_max;

	char const 	*default_auth_type;
	char const	*users_file_name;
	char const	*server_auth_type;
	char const	*server_id_type;
	bool		send_cert_request;

	uint32_t	fast_expire;

	bool		enable_fast_dhex;
	bool		enable_fast_reconnect;
} rlm_eap_ikev2_t;

CONF_PARSER module_config[] = {
	{ "ca_file", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ikev2_t, tls_ca_file), NULL  },
	{ "private_key_file", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ikev2_t, tls_private_key_file), NULL  },
	{ "private_key_password", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ikev2_t, tls_private_key_password), NULL  },
	{ "certificate_file", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ikev2_t, tls_certificate_file), NULL  },
	{ "crl_file", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ikev2_t, tls_crl), NULL  },

	{ "id", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ikev2_t, id), NULL  },
	{ "fragment_size", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_eap_ikev2_t, max_fragment_size), IKEv2_DEFAULT_MAX_FRAGMENT_SIZE_STR },
	{ "dh_counter_max", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_eap_ikev2_t, dh_counter_max), IKEv2_DEFAULT_DH_COUNTER_MAX_STR },
	{ "default_authtype", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ikev2_t, default_auth_type), "both" },
	{ "usersfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_eap_ikev2_t, users_file_name),"${confdir}/users" },
	{ "server_authtype", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ikev2_t, server_auth_type), "secret" },
	{ "idtype", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_ikev2_t, server_id_type), IKEv2_DEFAULT_IDTYPE_STR },
	{ "certreq", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_ikev2_t, send_cert_request), "no" },
	{ "fast_timer_expire", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_eap_ikev2_t, fast_expire), "900" },

	{ "fast_dh_exchange", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_ikev2_t, enable_fast_dhex), "no" },
	{ "enable_fast_reauth", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_ikev2_t, enable_fast_reconnect), "yes" },
	CONF_PARSER_TERMINATOR
};

static int set_mppe_keys(eap_handler_t *handler)
{
	uint8_t const *p;
	struct IKEv2Session *session;

	session = ((struct IKEv2Data*)handler->opaque)->session;

	if (session->eapKeyData==NULL){
		INFO(IKEv2_LOG_PREFIX "Key session not available!!!");
		return 1;
	}

	p = session->eapKeyData;
	eap_add_reply(handler->request, "MS-MPPE-Recv-Key", p, IKEV2_MPPE_KEY_LEN);
	p += IKEV2_MPPE_KEY_LEN;
	eap_add_reply(handler->request, "MS-MPPE-Send-Key", p, IKEV2_MPPE_KEY_LEN);
	return 0;
}

/** Compose Radius like message from table of output bytes
 *
 */
static int compose_rad_message(uint8_t *out,u_int32_t olen, EAP_DS *eap_ds) {
	int len;

	eap_ds->request->type.num = PW_EAP_IKEV2;
	eap_ds->request->code = ((struct EAPHeader *)out)->Code;

	if (eap_ds->request->code > PW_EAP_REQUEST || (olen <= 4)) {
	    eap_ds->request->type.data = NULL;
	    eap_ds->request->type.length = 0;

	    return 0;
	}

	len = ntohs(((struct EAPHeader *)out)->Length);

	eap_ds->request->type.data = talloc_array(eap_ds->request, uint8_t, len);
	if (!eap_ds->request->type.data) return 1;

	memcpy(eap_ds->request->type.data, out + 5, len - 5);
	eap_ds->request->type.length = len - 5;

	return 0;
}

/** Free memory after EAP-IKEv2 module usage
 *
 */
static int mod_detach(void *instance)
{
	struct ikev2_ctx *data = (struct ikev2_ctx *) instance;

	if (data) {
		Free_ikev2_ctx(data);
		data = NULL;
	}
	return 0;
}

/** Free memory after finished IKEv2 session
 *
 */
static void ikev2_free_opaque(void *opaque)
{

	int fast_deleted;
	struct IKEv2Data *ikev2_data=(struct IKEv2Data*)opaque;

	DEBUG(IKEv2_LOG_PREFIX "Free session data");

	if (ikev2_data->session) {
		if (ikev2_data->session->Status != IKEv2_SST_ESTABLISHED) {
			DEBUG(IKEv2_LOG_PREFIX "Unfinished IKEv2 session - cleanup!!!");
			IKEv2EndSession(ikev2_data->i2, ikev2_data->session);
			ikev2_data->session = NULL;
		} else {
			DEBUG(IKEv2_LOG_PREFIX "Unfinished IKEv2 session - keep it!!!");
			ikev2_data->session = NULL;
		}
	}

	fast_deleted = FreeSessionIfExpired(ikev2_data->i2, time(NULL));
	if (fast_deleted) {
		DEBUG(IKEv2_LOG_PREFIX "Deleted %d expired IKEv2 sessions", fast_deleted);
	}

	free(ikev2_data);
}

/** Configure EAP-ikev2 handler
 *
 */
static int mod_instantiate(CONF_SECTION *conf, void **instance)
{
	int ret;

	struct ikev2_ctx *i2;
	rlm_eap_ikev2_t *inst;

	char *server_auth_type, *default_auth_type, *users_file_name;

	ikev2_set_log_callback(vxlogf);

	inst = talloc_zero(conf, rlm_eap_ikev2_t);
	if (cf_section_parse(conf, &inst, module_config) < 0) return -1;

	i2 = Create_ikev2_ctx();
	if (!i2) return -1;
	*instance = i2;

	/*
	 *	Map our config structure onto the IKEv2 context
	 */
	memcpy(&i2->trusted, &inst->tls_ca_file, sizeof(i2->trusted));
	memcpy(&i2->pkfile, &inst->tls_private_key_file, sizeof(i2->pkfile));
	memcpy(&i2->pkfile_pwd, &inst->tls_private_key_password, sizeof(i2->pkfile_pwd));
	memcpy(&i2->certfile, &inst->tls_certificate_file, sizeof(i2->certfile));
	memcpy(&i2->id, &inst->id, sizeof(i2->id));
	i2->max_fragment_size = inst->max_fragment_size;
	i2->DHCounterMax = inst->dh_counter_max;
	i2->sendCertReq = (uint8_t) inst->send_cert_request;
	i2->fastExpire = inst->fast_expire;
	i2->enableFastDHEx = inst->enable_fast_dhex;
	i2->enableFastReconnect = inst->enable_fast_reconnect;

	memcpy(&server_auth_type, &inst->server_auth_type, sizeof(server_auth_type));
	memcpy(&default_auth_type, &inst->default_auth_type, sizeof(default_auth_type));
	memcpy(&users_file_name, &inst->users_file_name, sizeof(users_file_name));
	hexalize(&i2->id, &i2->idlen);

	i2->authtype = rad_get_authtype(server_auth_type);
	if (!i2->id) {
		ERROR(IKEv2_LOG_PREFIX "'id' configuration option is required!!!");
		return -1;
	}

	switch (i2->authtype) {
	default:
	case IKEv2_AUTH_SK:
		break;

	case IKEv2_AUTH_CERT:
		if (!i2->certfile || !i2->pkfile) {
			ERROR(IKEv2_LOG_PREFIX "'certificate_file' and 'private_key_file' items are required "
			      "for 'cert' auth type");
			return -1;
		}

		if (!file_exists(i2->certfile)) {
			ERROR(IKEv2_LOG_PREFIX "Can not open 'certificate_file' %s", i2->certfile);
			return -1;
		}

		if (!file_exists(i2->pkfile)) {
			ERROR(IKEv2_LOG_PREFIX "Can not open 'private_key_file' %s",i2->pkfile);
			return -1;
		}
		break;
	}

	if (!i2->trusted) {
		AUTH(IKEv2_LOG_PREFIX "'ca_file' item not set, client cert based authentication will fail");
	} else {
		if (!file_exists(i2->trusted)) {
			ERROR(IKEv2_LOG_PREFIX "Can not open 'ca_file' %s", i2->trusted);
			return -1;
		}
	}

	if (i2->crl_file) {
		if (!file_exists(i2->crl_file)) {
			ERROR(IKEv2_LOG_PREFIX "Can not open 'crl_file' %s", i2->crl_file);
			return -1;
		}
	}

	i2->idtype = IdTypeFromName(inst->server_id_type);
	if (i2->idtype <= 0) {
		ERROR(IKEv2_LOG_PREFIX "Unsupported 'idtype': %s", inst->server_id_type);
		return -1;
	}

	if (rad_load_proposals(i2, conf)) {
		ERROR(IKEv2_LOG_PREFIX "Failed to load proposals");
		return -1;
	}

	ret = rad_load_credentials(instance, i2, users_file_name, default_auth_type);
	if (ret == -1) {
		ERROR(IKEv2_LOG_PREFIX "Error while loading users credentials");
		return -1;
	}

	i2->x509_store = NULL;
	if(CertInit(i2)){
		ERROR(IKEv2_LOG_PREFIX "Error while loading certs/crl");
		return -1;
	}

	return 0;
}

/** Initiate the EAP-ikev2 session by sending a challenge to the peer.
 *
 */
static int mod_session_init(void *instance, eap_handler_t *handler)
{
	INFO(IKEv2_LOG_PREFIX "Initiate connection!");

	struct IKEv2Data *ikev2_data;
	struct ikev2_ctx *i2=(struct ikev2_ctx*)instance;

	uint8_t *sikemsg = NULL;
	u_int32_t slen = 0;

	uint8_t *out = NULL;
	u_int32_t olen = 0;

	struct IKEv2Session *session;
	handler->free_opaque = ikev2_free_opaque;

	/* try get respondent FASTID */
	uint8_t const *eap_username;

	eap_username = handler->request->username->vp_octets;
	session = FindSessionByFastid(i2, (char const *)eap_username);
	if (!session) {
		if (IKEv2BeginSession( i2, &session, IKEv2_STY_INITIATOR ) != IKEv2_RET_OK) {
			ERROR(IKEv2_LOG_PREFIX "Can't initialize IKEv2 session");
			return 1;
		}
	} else {
		DEBUG(IKEv2_LOG_PREFIX "Fast reconnect procedure start");
	}
	session->timestamp=time(NULL);

	ikev2_data = IKEv2Data_new(i2,session);
	handler->opaque = ikev2_data;

	if (IKEv2ProcessMsg(i2, NULL , &sikemsg, &slen, session) != IKEv2_RET_OK) {
		ERROR(IKEv2_LOG_PREFIX "Error while processing IKEv2 message");
		return 1;
	}

	if (slen != 0) {
		session->eapMsgID++;
		olen = CreateIKEv2Message(i2, sikemsg, slen, false, 0, session, &out );
		if (session->fragdata) {
	    		session->sendfrag = true;
	    	}
    	}

	if ((olen > 0) && (out!=NULL)) {
		if (compose_rad_message(out, olen, handler->eap_ds)) {
			free(out);
			return 0;
		}
		free(out);
	}

	/*
	 *	We don't need to authorize the user at this point.
	 *
	 *	We also don't need to keep the challenge, as it's
	 *	stored in 'handler->eap_ds', which will be given back
	 *	to us...
	 */
	handler->stage = PROCESS;
	return 1;
}

/** Authenticate a previously sent challenge
 *
 */
static int mod_process(void *instance, eap_handler_t *handler)
{
	uint8_t *in;
	uint8_t *out = NULL;

	uint8_t *ikemsg;
	u_int32_t len;

	uint8_t *sikemsg = NULL;   //out message
	u_int32_t slen = 0;

	u_int32_t olen = 0;
	struct ikev2_ctx *i2 = (struct ikev2_ctx*)instance;
	struct EAPHeader *hdr;

	struct IKEv2Data *ikev2_data;
	struct IKEv2Session *session;

	INFO(IKEv2_LOG_PREFIX "authenticate" );

	rad_assert(handler->request != NULL);
	rad_assert(handler->stage == PROCESS);

	EAP_DS *eap_ds=handler->eap_ds;
	if (!eap_ds ||
	    !eap_ds->response ||
	    (eap_ds->response->code != PW_IKEV2_RESPONSE) ||
	    eap_ds->response->type.num != PW_EAP_IKEV2 ||
	    !eap_ds->response->type.data) {
		ERROR(IKEv2_LOG_PREFIX "corrupted data");
		return -1;
	}

	in = talloc_array(eap_ds, uint8_t, eap_ds->response->length);
	if (in){
		ERROR(IKEv2_LOG_PREFIX "alloc error");
		return -1;
	}

	rad_assert(in != NULL);
	hdr = (struct EAPHeader *)in;

	hdr->Code = eap_ds->response->code;
	hdr->Id = eap_ds->response->id;
	hdr->Length = htons(eap_ds->response->length);
	hdr->Type = eap_ds->response->type.num;
	memcpy(in + 5, eap_ds->response->type.data, eap_ds->response->length - 5);

	ikev2_data = (struct IKEv2Data*)handler->opaque;
	session = ikev2_data->session;
	session->timestamp = time(NULL);

	if (!session->fragdata) session->sendfrag = false;

	if (session->sendfrag && !ParseFragmentAck(in, session)){
		session->eapMsgID = eap_ds->response->id + 1;

		olen = CreateIKEv2Message(i2, NULL, 0, false, hdr->Id, session, (uint8_t **)&out);
		talloc_free(in);

		if (compose_rad_message(out,olen,handler->eap_ds)) {
			free(out);
			return 0;
		}

		free(out);
		return 1;
	}

	session->eapMsgID = eap_ds->response->id + 1;

	if (ParseIKEv2Message(in, &ikemsg, &len, session)){
		if (ikemsg != NULL) free(ikemsg);

		handler->eap_ds->request->code=PW_EAP_FAILURE;
		INFO(IKEv2_LOG_PREFIX "Discarded packet");

		return 1;
	}

	/* Send fragment ack */
	if (!ikemsg || !len) {
		if (session->SK_ready) session->include_integ = 1;

		olen = CreateFragmentAck(in, &out, session); // confirm fragment
		TALLOC_FREE(in);

		if (compose_rad_message(out,olen,handler->eap_ds)) {
			free(out);
			return 0;
		}

		free(out);
		return 1;
	}
	TALLOC_FREE(in);

	if (IKEv2ProcessMsg(i2, ikemsg, &sikemsg, &slen, session) != IKEv2_RET_OK) {
		INFO(IKEv2_LOG_PREFIX "EAP_STATE_DISCARD");
		//session->State = EAP_STATE_DISCARD;
		free(out);
		return 1;
	}

	free(ikemsg);

	/* If there is there is something to send */
	if (slen != 0){
		olen = CreateIKEv2Message(i2, sikemsg, slen, false, 0, session, &out);
		if (session->fragdata) session->sendfrag = true;
	} else {
		if (session->Status == IKEv2_SST_FAILED ) {
			INFO(IKEv2_LOG_PREFIX "FAILED");
			olen = CreateResultMessage( false, session, &out );
		}

		if(session->Status == IKEv2_SST_ESTABLISHED) {
			INFO(IKEv2_LOG_PREFIX "SUCCESS");
			olen = CreateResultMessage(true, session, &out);
			session->fFastReconnect = i2->enableFastReconnect;

			GenEapKeys(session ,EAP_IKEv2_KEY_LEN);
			set_mppe_keys(handler);
		}

		// keep sessions in memory, only reference cleared
		ikev2_data->session = NULL;
	}
	if ((olen > 0) && (out != NULL)){
		if (compose_rad_message(out, olen, handler->eap_ds)){
			free(out);
			return 0;
		}
	}

	free(out);
	return 1;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_module_t rlm_eap_ikev2;
rlm_eap_module_t rlm_eap_ikev2 = {
	.name		= "eap_ikev2",
	.instantiate	= mod_instantiate,	/* Create new submodule instance */
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process,		/* Process next round of EAP method */
	.detach		= mod_detach		/* detach */
};
