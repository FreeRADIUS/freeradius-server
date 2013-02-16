/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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
 * @file rlm_eap2.c
 * @brief Uses hostapd library to support some methods not provided by rlm_eap.
 *
 * @copyright 2007  Alan DeKok <aland@deployingradius.com>
 */
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

/*
 *	Hostap includes.
 */
#include <utils/includes.h>

#include <utils/common.h>
#include <eap_server/eap.h>
#include <crypto/tls.h>


struct eap_server_ctx {
	struct eap_eapol_interface *eap_if;
	struct eap_sm *eap;
	void *tls_ctx;
};

#define EAP_STATE_LEN (AUTH_VECTOR_LEN)
typedef struct EAP_HANDLER {
	struct EAP_HANDLER *prev, *next;
	uint8_t		state[EAP_STATE_LEN];
	fr_ipaddr_t	src_ipaddr;

	time_t		timestamp;

	REQUEST		*request;
	struct rlm_eap_t *inst;

	struct eapol_callbacks eap_cb;
	struct eap_config eap_conf;
	struct eap_server_ctx server_ctx;
} EAP_HANDLER;

typedef struct rlm_eap_t {
	rbtree_t	*session_tree;
	EAP_HANDLER	*session_head, *session_tail;

	/*
	 *	Configuration items.
	 */
	int		timer_limit;
	int		cisco_accounting_username_bug;

	struct tls_connection_params tparams;

	/*
	 *	For EAP-FAST
	 */
	char		*pac_opaque_encr_key; 
	char		*eap_fast_a_id; 
	char		*eap_fast_a_id_info; 
	int		eap_fast_prov; 
	int		pac_key_lifetime; 
	int		pac_key_refresh_time; 
	int		backend_auth; 

	int		num_types;
	EapType		methods[EAP_MAX_METHODS];
	int		vendors[EAP_MAX_METHODS];

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t	session_mutex;
#endif

	fr_randctx	rand_pool;
	void *tls_ctx;
} rlm_eap_t;


static void eap_handler_free(EAP_HANDLER *handler)
{
	eap_server_sm_deinit(handler->server_ctx.eap);
	free(handler);
}

static void eaplist_free(rlm_eap_t *inst)
{
	EAP_HANDLER *node, *next;

       	for (node = inst->session_head; node != NULL; node = next) {
		next = node->next;
		eap_handler_free(node);
	}

	inst->session_head = inst->session_tail = NULL;
}

/*
 *	Return a 32-bit random number.
 */
static uint32_t eap_rand(fr_randctx *ctx)
{
	uint32_t num;

	num = ctx->randrsl[ctx->randcnt++];
	if (ctx->randcnt == 256) {
		ctx->randcnt = 0;
		fr_isaac(ctx);
	}

	return num;
}

/*
 *	Add a handler to the set of active sessions.
 *
 *	Since we're adding it to the list, we guess that this means
 *	the packet needs a State attribute.  So add one.
 */
static int eaplist_add(rlm_eap_t *inst, EAP_HANDLER *handler)
{
	int		i, status;
	uint32_t	lvalue;
	VALUE_PAIR	*state;

	rad_assert(handler != NULL);
	rad_assert(handler->request != NULL);

	/*
	 *	Generate State, since we've been asked to add it to
	 *	the list.
	 */
	state = pairmake("State", "0x00", T_OP_EQ);
	if (!state) return 0;
	pairadd(&(handler->request->reply->vps), state);
	state->length = EAP_STATE_LEN;

	/*
	 *	The time at which this request was made was the time
	 *	at which it was received by the RADIUS server.
	 */
	handler->timestamp = handler->request->timestamp;

	handler->src_ipaddr = handler->request->packet->src_ipaddr;

	/*
	 *	We don't need this any more.
	 */
	handler->request = NULL;

	/*
	 *	Playing with a data structure shared among threads
	 *	means that we need a lock, to avoid conflict.
	 */
	pthread_mutex_lock(&(inst->session_mutex));

	/*
	 *	Create a completely random state.
	 */
	for (i = 0; i < 4; i++) {
		lvalue = eap_rand(&inst->rand_pool);
		memcpy(state->vp_octets + i * 4, &lvalue, sizeof(lvalue));
	}
	memcpy(handler->state, state->vp_strvalue, sizeof(handler->state));

	/*
	 *	Big-time failure.
	 */
	status = rbtree_insert(inst->session_tree, handler);

	if (status) {
		EAP_HANDLER *prev;

		prev = inst->session_tail;
		if (prev) {
			prev->next = handler;
			handler->prev = prev;
			handler->next = NULL;
			inst->session_tail = handler;
		} else {
			inst->session_head = inst->session_tail = handler;
			handler->next = handler->prev = NULL;
		}
	}

	/*
	 *	Now that we've finished mucking with the list,
	 *	unlock it.
	 */
	pthread_mutex_unlock(&(inst->session_mutex));

	if (!status) {
		radlog(L_ERR, "rlm_eap2: Failed to remember handler!");
		eap_handler_free(handler);
		return 0;
	}

	return 1;
}

/*
 *	Find a a previous EAP-Request sent by us, which matches
 *	the current EAP-Response.
 *
 *	Then, release the handle from the list, and return it to
 *	the caller.
 *
 *	Also since we fill the eap_ds with the present EAP-Response we
 *	got to free the prev_eapds & move the eap_ds to prev_eapds
 */
static EAP_HANDLER *eaplist_find(rlm_eap_t *inst, REQUEST *request)
{
	int		i;
	VALUE_PAIR	*state;
	rbnode_t	*node;
	EAP_HANDLER	*handler, myHandler;

	/*
	 *	We key the sessions off of the 'state' attribute, so it
	 *	must exist.
	 */
	state = pairfind(request->packet->vps, PW_STATE, 0, TAG_ANY);
	if (!state ||
	    (state->length != EAP_STATE_LEN)) {
		return NULL;
	}

	myHandler.src_ipaddr = request->packet->src_ipaddr;
	memcpy(myHandler.state, state->vp_strvalue, sizeof(myHandler.state));

	/*
	 *	Playing with a data structure shared among threads
	 *	means that we need a lock, to avoid conflict.
	 */
	pthread_mutex_lock(&(inst->session_mutex));

	/*
	 *	Check the first few handlers in the list, and delete
	 *	them if they're too old.  We don't need to check them
	 *	all, as incoming requests will quickly cause older
	 *	handlers to be deleted.
	 *
	 */
	for (i = 0; i < 2; i++) {
		handler = inst->session_head;
		if (handler &&
		    ((request->timestamp - handler->timestamp) > inst->timer_limit)) {
			node = rbtree_find(inst->session_tree, handler);
			rad_assert(node != NULL);
			rbtree_delete(inst->session_tree, node);

			/*
			 *	handler == inst->session_head
			 */
			inst->session_head = handler->next;
			if (handler->next) {
				handler->next->prev = NULL;
			} else {
				inst->session_head = NULL;
			}
			eap_handler_free(handler);
		}
	}

	handler = NULL;
	node = rbtree_find(inst->session_tree, &myHandler);
	if (node) {
		handler = rbtree_node2data(inst->session_tree, node);

		/*
		 *	Delete old handler from the tree.
		 */
		rbtree_delete(inst->session_tree, node);
		
		/*
		 *	And unsplice it from the linked list.
		 */
		if (handler->prev) {
			handler->prev->next = handler->next;
		} else {
			inst->session_head = handler->next;
		}
		if (handler->next) {
			handler->next->prev = handler->prev;
		} else {
			inst->session_tail = handler->prev;
		}
		handler->prev = handler->next = NULL;
	}

	pthread_mutex_unlock(&(inst->session_mutex));

	/*
	 *	Not found.
	 */
	if (!node) {
		RDEBUG2("Request not found in the list");
		return NULL;
	}

	/*
	 *	Found, but state verification failed.
	 */
	if (!handler) {
		radlog(L_ERR, "rlm_eap2: State verification failed.");
		return NULL;
	}

	RDEBUG2("Request found, released from the list");

	return handler;
}


/*
 * delete all the allocated space by eap module
 */
static int eap_detach(void *instance)
{
	rlm_eap_t *inst;

	inst = (rlm_eap_t *)instance;

	rbtree_free(inst->session_tree);
	inst->session_tree = NULL;
	eaplist_free(inst);
	eap_server_unregister_methods();
	tls_deinit(inst->tls_ctx);

	pthread_mutex_destroy(&(inst->session_mutex));

	free(inst);

	return 0;
}


/*
 *	Compare two handlers.
 */
static int eap_handler_cmp(const void *a, const void *b)
{
	int rcode;
	const EAP_HANDLER *one = a;
	const EAP_HANDLER *two = b;

	rcode = fr_ipaddr_cmp(&one->src_ipaddr, &two->src_ipaddr);
	if (rcode != 0) return rcode;

	return memcmp(one->state, two->state, sizeof(one->state));
}


static int server_get_eap_user(void *ctx, const u8 *identity,
			       size_t identity_len, int phase2,
			       struct eap_user *user)
{
	int i;
	VALUE_PAIR *vp;
	EAP_HANDLER *handler = ctx;
	REQUEST *request = handler->request;

	os_memset(user, 0, sizeof(*user));

	/*
	 *	FIXME: Run through "authorise" again to look up
	 *	password for the given identity
	 */
	identity = identity;	/* -Wunused */
	identity_len = identity_len; /* -Wunused */

	/*
	 *	Do this always, just in case.
	 */
	vp = pairfind(request->config_items, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY);
	if (vp) {
		user->password = (u8 *) os_strdup(vp->vp_strvalue);
		user->password_len = vp->length;
	}
	if (!vp) vp = pairfind(request->config_items, PW_NT_PASSWORD, 0, TAG_ANY);
	if (vp) {
		user->password = (u8 *) malloc(vp->length);
		memcpy(user->password, vp->vp_octets, vp->length);
		user->password_len = vp->length;
	}

	if (!phase2) {
		for (i = 0; i < handler->inst->num_types; i++) {
			user->methods[i].vendor = handler->inst->vendors[i];
			user->methods[i].method = handler->inst->methods[i];
		}
		return 0;
	}

	/*
	 *	FIXME: run tunneled sessions through the tunneled portion...
	 */

	/*
	 *	FIXME: Selectively control tunneled EAP types.
	 */
	user->methods[0].vendor = EAP_VENDOR_IETF;
	user->methods[0].method = EAP_TYPE_MD5;
	user->methods[1].vendor = EAP_VENDOR_IETF;
	user->methods[1].method = EAP_TYPE_MSCHAPV2;

	/*
	 *	No password configured...
	 */

       	return 0;
}


static const char * server_get_eap_req_id_text(void *ctx, size_t *len)
{
	ctx = ctx;		/* -Wunused */
	*len = 0;
	return NULL;
}


static CONF_PARSER tls_config[] = {
	/*
	 *	TLS parameters.
	 */
	{ "ca_cert", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_t, tparams.ca_cert),
	  NULL, "${confdir}/certs/ca.pem" },
	{ "server_cert", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_t, tparams.client_cert),
	  NULL, "${confdir}/certs/server.pem" },
	{ "private_key_file", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_t, tparams.private_key),
	  NULL, "${confdir}/certs/server.pem" },
	{ "private_key_password", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_t, tparams.private_key_passwd),
	  NULL, "whatever" },

	{ "dh_file", PW_TYPE_STRING_PTR, 
	  offsetof(rlm_eap_t, tparams.dh_file), NULL, "whatever" }, 

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

static CONF_PARSER fast_config[] = { 
	{ "pac_opaque_encr_key", PW_TYPE_STRING_PTR, 
	  offsetof(rlm_eap_t, pac_opaque_encr_key), NULL, NULL }, 
	{ "eap_fast_a_id", PW_TYPE_STRING_PTR, 
	  offsetof(rlm_eap_t, eap_fast_a_id), NULL, NULL }, 
	{ "eap_fast_a_id_info", PW_TYPE_STRING_PTR, 
	  offsetof(rlm_eap_t, eap_fast_a_id_info), NULL, NULL }, 
	{ "eap_fast_prov", PW_TYPE_INTEGER, 
	  offsetof(rlm_eap_t, eap_fast_prov), NULL, "3"}, 
	{ "pac_key_lifetime", PW_TYPE_INTEGER, 
	  offsetof(rlm_eap_t, pac_key_lifetime), NULL, "604800"}, 
	{ "pac_key_refresh_time", PW_TYPE_INTEGER, 
	  offsetof(rlm_eap_t, pac_key_refresh_time), NULL, "86400"}, 
	{ NULL, -1, 0, NULL, NULL } /* end the list */ 
}; 

static const CONF_PARSER module_config[] = {
	{ "timer_expire", PW_TYPE_INTEGER,
	  offsetof(rlm_eap_t, timer_limit), NULL, "60"},
	{ "cisco_accounting_username_bug", PW_TYPE_BOOLEAN,
	  offsetof(rlm_eap_t, cisco_accounting_username_bug), NULL, "no" },

	{ "backend_auth", PW_TYPE_BOOLEAN, 
	  offsetof(rlm_eap_t, backend_auth), NULL, "yes" }, 

	{ "tls", PW_TYPE_SUBSECTION, 0, NULL, (const void *) tls_config },

	{ "fast", PW_TYPE_SUBSECTION, 0, NULL, (const void *) fast_config }, 

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};


static int eap_example_server_init_tls(rlm_eap_t *inst)
{
	struct tls_config tconf;

	os_memset(&tconf, 0, sizeof(tconf));
	inst->tls_ctx = tls_init(&tconf);
	if (inst->tls_ctx == NULL)
		return -1;

	if (tls_global_set_params(inst->tls_ctx, &inst->tparams)) {
		radlog(L_ERR, "rlm_eap2: Failed to set TLS parameters");
		return -1;
	}

	if (tls_global_set_verify(inst->tls_ctx, 0)) {
		radlog(L_ERR, "rlm_eap2: Failed to set check_crl");
		return -1;
	}

	return 0;
}


/*
 * read the config section and load all the eap authentication types present.
 */
static int eap_instantiate(CONF_SECTION *cs, void **instance)
{
	int i, num_types;
	int		has_tls, do_tls;
	rlm_eap_t	*inst;
	CONF_SECTION	*scs;

	inst = (rlm_eap_t *) malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));
	if (cf_section_parse(cs, inst, module_config) < 0) {
		eap_detach(inst);
		return -1;
	}

	/*
	 *	Create our own random pool.
	 */
	for (i = 0; i < 256; i++) {
		inst->rand_pool.randrsl[i] = fr_rand();
	}
	fr_randinit(&inst->rand_pool, 1);

	/*
	 *	List of sessions are set to NULL by the memset
	 *	of 'inst', above.
	 */

	/*
	 *	Lookup sessions in the tree.  We don't free them in
	 *	the tree, as that's taken care of elsewhere...
	 */
	inst->session_tree = rbtree_create(eap_handler_cmp, NULL, 0);
	if (!inst->session_tree) {
		radlog(L_ERR|L_CONS, "rlm_eap2: Cannot initialize tree");
		eap_detach(inst);
		return -1;
	}

	/*
	 *	This registers ALL available methods.
	 *
	 *	FIXME: we probably want to selectively register
	 *	some methods.
	 */
	if (eap_server_register_methods() < 0) {
		eap_detach(inst);
		return -1;
	}

	/* Load all the configured EAP-Types */
	num_types = 0;
	has_tls = do_tls = 0;
	for (scs=cf_subsection_find_next(cs, NULL, NULL);
		scs != NULL;
		scs=cf_subsection_find_next(cs, scs, NULL)) {
		const char	*auth_type;
		char		buffer[64], *p;

		auth_type = cf_section_name1(scs);

		if (!auth_type)  continue;

		if (num_types >= EAP_MAX_METHODS) {
			radlog(L_INFO, "WARNING: Ignoring EAP type %s: too many types defined", auth_type);
			continue;
		}

		/*
		 *	Hostapd doesn't do case-insensitive comparisons.
		 *	So we mash everything to uppercase for it.
		 */
		strlcpy(buffer, auth_type, sizeof(buffer));

		for (p = buffer; *p; p++) {
			if (!islower((int)*p)) continue;
			*p = toupper((int)*p);
		}

		inst->methods[num_types] = eap_server_get_type(buffer,
							       &inst->vendors[num_types]);
		if (inst->methods[num_types] == EAP_TYPE_NONE) {
			radlog(L_ERR|L_CONS, "rlm_eap2: Unknown EAP type %s",
			       auth_type);
			eap_detach(inst);
			return -1;
		}

		switch (inst->methods[num_types]) {
		case EAP_TYPE_TLS:
			has_tls = TRUE;
			/* FALL-THROUGH */

		case EAP_TYPE_TTLS:
		case EAP_TYPE_PEAP:
		case EAP_TYPE_FAST:
			do_tls = TRUE;
			break;

		default:
			break;
		}

		num_types++;	/* successfully loaded one more types */
	}
	inst->num_types = num_types;

	if (do_tls && !has_tls) {
		radlog(L_ERR|L_CONS, "rlm_eap2: TLS has not been configured.  Cannot do methods that need TLS.");
		eap_detach(inst);
		return -1;
	}

	if (do_tls) {
		/*
		 *	Initialize TLS.
		 */
		if (eap_example_server_init_tls(inst) < 0) {
			radlog(L_ERR|L_CONS, "rlm_eap2: Cannot initialize TLS");
			eap_detach(inst);
			return -1;
		}
	}

	pthread_mutex_init(&(inst->session_mutex), NULL);

	*instance = inst;
	return 0;
}


static int eap_req2vp(EAP_HANDLER *handler)
{
	int		encoded, total, size;
	const uint8_t	*ptr;
	VALUE_PAIR	*head = NULL;
	VALUE_PAIR	**tail = &head;
	VALUE_PAIR	*vp;

	ptr = wpabuf_head(handler->server_ctx.eap_if->eapReqData);
	encoded = total = wpabuf_len(handler->server_ctx.eap_if->eapReqData);

	do {
		size = total;
		if (size > 253) size = 253;

		vp = paircreate(PW_EAP_MESSAGE, 0);
		if (!vp) {
			pairfree(&head);
			return -1;
		}
		memcpy(vp->vp_octets, ptr, size);
		vp->length = size;

		*tail = vp;
		tail = &(vp->next);

		ptr += size;
		total -= size;
	} while (total > 0);

	pairdelete(&handler->request->reply->vps, PW_EAP_MESSAGE, TAG_ANY);
	pairadd(&handler->request->reply->vps, head);

	return encoded;
}

static int eap_example_server_step(EAP_HANDLER *handler)
{
	int res, process = 0;
	REQUEST *request = handler->request;

	res = eap_server_sm_step(handler->server_ctx.eap);

	if (handler->server_ctx.eap_if->eapReq) {
		DEBUG("==> Request");
		process = 1;
		handler->server_ctx.eap_if->eapReq = 0;
	}

	if (handler->server_ctx.eap_if->eapSuccess) {
		DEBUG("==> Success");
		process = 1;
		res = 0;

		if (handler->server_ctx.eap_if->eapKeyAvailable) {
			int length = handler->server_ctx.eap_if->eapKeyDataLen;
			VALUE_PAIR *vp;

			if (length > 64) {
				length = 32;
			} else {
				length /= 2;
				/*
				 *	FIXME: Length is zero?
				 */
			}

			vp = radius_pairmake(request, &request->reply->vps,
					     "MS-MPPE-Recv-Key", "", T_OP_EQ);
			if (vp) {
				memcpy(vp->vp_octets,
				       handler->server_ctx.eap_if->eapKeyData,
				       length);
				vp->length = length;
			}
			
			vp = radius_pairmake(request, &request->reply->vps,
					     "MS-MPPE-Send-Key", "", T_OP_EQ);
			if (vp) {
				memcpy(vp->vp_octets,
				       handler->server_ctx.eap_if->eapKeyData + length,
				       length);
				vp->length = length;
			}
		}
	}

	if (handler->server_ctx.eap_if->eapFail) {
		DEBUG("==> Fail");
		process = 1;
	}

	if (process) {
		if (wpabuf_head(handler->server_ctx.eap_if->eapReqData)) {
			if (!eap_req2vp(handler)) return -1;
		} else {
			return -1;
		}
	}

	return res;
}


/*
 * Handles multiple EAP-Message attrs
 * ie concatenates all to get the complete EAP packet.
 *
 * NOTE: Sometimes Framed-MTU might contain the length of EAP-Message,
 *      refer fragmentation in rfc2869.
 */
static int eap_vp2data(VALUE_PAIR *vps, void **data, int *data_len)
{
	VALUE_PAIR *first, *vp;
	unsigned char *ptr;
	uint16_t len;
	int total_len;

	/*
	 *	Get only EAP-Message attribute list
	 */
	first = pairfind(vps, PW_EAP_MESSAGE, 0, TAG_ANY);
	if (first == NULL) {
		radlog(L_ERR, "rlm_eap2: EAP-Message not found");
		return -1;
	}

	/*
	 *	Sanity check the length before doing anything.
	 */
	if (first->length < 4) {
		radlog(L_ERR, "rlm_eap2: EAP packet is too short.");
		return -1;
	}

	/*
	 *	Get the Actual length from the EAP packet
	 *	First EAP-Message contains the EAP packet header
	 */
	memcpy(&len, first->vp_strvalue + 2, sizeof(len));
	len = ntohs(len);

	/*
	 *	Take out even more weird things.
	 */
	if (len < 4) {
		radlog(L_ERR, "rlm_eap2: EAP packet has invalid length.");
		return -1;
	}

	/*
	 *	Sanity check the length, BEFORE malloc'ing memory.
	 */
	total_len = 0;
	for (vp = first; vp; vp = pairfind(vp->next, PW_EAP_MESSAGE, 0, TAG_ANY)) {
		total_len += vp->length;

		if (total_len > len) {
			radlog(L_ERR, "rlm_eap2: Malformed EAP packet.  Length in packet header does not match actual length");
			return -1;
		}
	}

	/*
	 *	If the length is SMALLER, die, too.
	 */
	if (total_len < len) {
		radlog(L_ERR, "rlm_eap2: Malformed EAP packet.  Length in packet header does not match actual length");
		return -1;
	}

	/*
	 *	Now that we know the lengths are OK, allocate memory.
	 */
	*data = malloc(len);
	if (!*data) {
		radlog(L_ERR, "rlm_eap2: out of memory");
		return -1;
	}
	*data_len = len;

	/*
	 *	Copy the data from EAP-Message's over to our EAP packet.
	 */
	ptr = *data;

	/* RADIUS ensures order of attrs, so just concatenate all */
	for (vp = first; vp; vp = pairfind(vp->next, PW_EAP_MESSAGE, 0, TAG_ANY)) {
		memcpy(ptr, vp->vp_strvalue, vp->length);
		ptr += vp->length;
	}

	return 0;
}

/*
 *	FIXME: Add an "authorize" section which sets Auth-Type = EAP2
 *	FIXME: Also in "authorize", set User-Name if not already set.
 */


/*
 *	Do EAP.
 */
static rlm_rcode_t eap_authenticate(void *instance, REQUEST *request)
{
	rlm_eap_t	*inst;
	EAP_HANDLER	*handler;
	void		*data;
	int		data_len;
	rlm_rcode_t	rcode;
	VALUE_PAIR	*vp;

	inst = (rlm_eap_t *) instance;

	vp = pairfind(request->packet->vps, PW_EAP_MESSAGE, 0, TAG_ANY);
	if (!vp) {
		RDEBUG("No EAP-Message.  Not doing EAP.");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Get the eap packet  to start with
	 */
	data = NULL;
	data_len = 0;
	if (eap_vp2data(request->packet->vps, &data, &data_len) < 0) {
		radlog(L_ERR, "rlm_eap2: Malformed EAP Message");
		return RLM_MODULE_FAIL;
	}

	vp = pairfind(request->packet->vps, PW_STATE, 0, TAG_ANY);
	if (vp) {
		handler = eaplist_find(inst, request);
		if (!handler) {
			RDEBUG("No handler found");
			return RLM_MODULE_FAIL;
		}
	} else {
		handler = malloc(sizeof(*handler));
		if (!handler) return RLM_MODULE_FAIL;

		memset(handler, 0, sizeof(*handler));

		handler->inst = inst;
		handler->eap_cb.get_eap_user = server_get_eap_user;
		handler->eap_cb.get_eap_req_id_text = server_get_eap_req_id_text;

		handler->eap_conf.eap_server = 1;
		handler->eap_conf.ssl_ctx = inst->tls_ctx;

		/*
		 *	Copy EAP-FAST parameters.
		 */
		handler->eap_conf.pac_opaque_encr_key = inst->pac_opaque_encr_key; 
		handler->eap_conf.eap_fast_a_id = inst->eap_fast_a_id; 
		handler->eap_conf.eap_fast_a_id_len = strlen(inst->eap_fast_a_id); 
		handler->eap_conf.eap_fast_a_id_info = inst->eap_fast_a_id_info; 
		handler->eap_conf.eap_fast_prov = inst->eap_fast_prov; 
		handler->eap_conf.pac_key_lifetime = inst->pac_key_lifetime; 
		handler->eap_conf.pac_key_refresh_time = inst->pac_key_refresh_time; 
		handler->eap_conf.backend_auth = inst->backend_auth; 
		
		handler->server_ctx.eap = eap_server_sm_init(handler,
							     &handler->eap_cb,
							     &handler->eap_conf);
		if (handler->server_ctx.eap == NULL) {
			free(handler);
			return RLM_MODULE_FAIL;
		}
		
		handler->server_ctx.eap_if = eap_get_interface(handler->server_ctx.eap);
		
		/* Enable "port" and request EAP to start authentication. */
		handler->server_ctx.eap_if->portEnabled = TRUE;
		handler->server_ctx.eap_if->eapRestart = TRUE;
	}

	handler->request = request;
	wpabuf_free(handler->server_ctx.eap_if->eapRespData);
	handler->server_ctx.eap_if->eapRespData = wpabuf_alloc_copy(data, data_len);
	if (handler->server_ctx.eap_if->eapRespData) {
		handler->server_ctx.eap_if->eapResp = TRUE;
	}
	
	if (eap_example_server_step(handler) < 0) {
		RDEBUG("Failed in EAP library");
		goto fail;
	}

	if (handler->server_ctx.eap_if->eapSuccess) {
		request->reply->code = PW_AUTHENTICATION_ACK;
		rcode = RLM_MODULE_OK;

	} else if (handler->server_ctx.eap_if->eapFail) {
	fail:
		request->reply->code = PW_AUTHENTICATION_REJECT;
		rcode = RLM_MODULE_REJECT;

	} else {
		request->reply->code = PW_ACCESS_CHALLENGE;
		rcode = RLM_MODULE_HANDLED;
	}

	if (handler->server_ctx.eap_if->eapFail ||
	    handler->server_ctx.eap_if->eapSuccess) {
		RDEBUG2("Freeing handler");
		/* handler is not required any more, free it now */
		eap_handler_free(handler);
		handler = NULL;
	} else {
		eaplist_add(inst, handler);
	}

	/*
	 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
	 *	says that we MUST include a User-Name attribute in the
	 *	Access-Accept.
	 */
	if ((request->reply->code == PW_AUTHENTICATION_ACK) &&
	    request->username) {
		/*
		 *	Doesn't exist, add it in.
		 */
		vp = pairfind(request->reply->vps, PW_USER_NAME, 0, TAG_ANY);
		if (!vp) {
			vp = pairmake("User-Name", request->username->vp_strvalue,
				      T_OP_EQ);
			rad_assert(vp != NULL);
			pairadd(&(request->reply->vps), vp);
		}

		/*
		 *	Cisco AP1230 has a bug and needs a zero
		 *	terminated string in Access-Accept.
		 */
		if ((inst->cisco_accounting_username_bug) &&
		    (vp->length < (int) sizeof(vp->vp_strvalue))) {
			vp->vp_strvalue[vp->length] = '\0';
			vp->length++;
		}
	}

	vp = pairfind(request->reply->vps, PW_MESSAGE_AUTHENTICATOR, 0, TAG_ANY);
	if (!vp) {
		vp = paircreate(PW_MESSAGE_AUTHENTICATOR, 0);
		memset(vp->vp_strvalue, 0, AUTH_VECTOR_LEN);
		vp->length = AUTH_VECTOR_LEN;
		pairadd(&(request->reply->vps), vp);
	}
	return rcode;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
module_t rlm_eap2 = {
	RLM_MODULE_INIT,
	"eap2",
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	eap_instantiate,		/* instantiation */
	eap_detach,			/* detach */
	{
		eap_authenticate,	/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
