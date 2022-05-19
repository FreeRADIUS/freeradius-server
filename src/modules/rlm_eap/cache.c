/*
 * cache.c Caching of EAP state
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
 * Copyright 2022  The FreeRADIUS server project
 * Copyright 2022  Akamai/Inverse
 */

#include "rlm_eap.h"
#include <json-c/json.h>

int eap_cache_add_vp(REQUEST *fake);

#define CACHE_SAVE (1)
#define CACHE_LOAD (2)
#define CACHE_CLEAR (3)
#define CACHE_REFRESH (4)

REQUEST * eap_cache_init_fake_request(rlm_eap_t *inst) {
	REQUEST	*fake;
	fake = request_alloc(NULL);
	fake->packet = rad_alloc(fake, false);
	fake->reply = rad_alloc(fake, false);
	fake->server = inst->cache_virtual_server;
	return fake;
}

static json_object *eap_packet_t_to_obj(eap_packet_t *pkt) {
	char buff[2048];
	struct json_object *obj, *val;
	MEM(obj = json_object_new_object());

	MEM(val = json_object_new_int(pkt->code));
	json_object_object_add(obj, "code", val);

	MEM(val = json_object_new_int(pkt->id));
	json_object_object_add(obj, "id", val);

	if (pkt->packet) {
		fr_bin2hex(buff, pkt->packet, pkt->length);
		MEM(val = json_object_new_string(buff));
		json_object_object_add(obj, "packet", val);
	}

	if (pkt->type.data) {
		fr_bin2hex(buff, pkt->type.data, pkt->type.length);
		MEM(val = json_object_new_string(buff));
		json_object_object_add(obj, "type_data", val);
	}

	MEM(val = json_object_new_int(pkt->type.num));
	json_object_object_add(obj, "typenum", val);

	return obj;
}

static json_object *eap_ds_to_obj(EAP_DS * ds) {
	struct json_object *obj, *val;
	MEM(obj = json_object_new_object());

	MEM(val = eap_packet_t_to_obj(ds->response));
	json_object_object_add(obj, "response", val);

	MEM(val = eap_packet_t_to_obj(ds->request));
	json_object_object_add(obj, "request", val);

	MEM(val = json_object_new_int(ds->set_request_id));
	json_object_object_add(obj, "set_request_id", val);
	return obj;
}

static int serialized_handler(REQUEST *request, REQUEST * fake, UNUSED rlm_eap_t *inst, eap_handler_t *handler) {
	char buff[64];
	VALUE_PAIR *vp = NULL;
	const char *json_str;
	size_t len;
	struct json_object *obj, *val;
	MEM(obj = json_object_new_object());
	len = fr_bin2hex(buff, handler->state, EAP_STATE_LEN);
	MEM(val = json_object_new_string_len(buff, len));
	json_object_object_add(obj, "state", val);
	
	memset(buff, 0, sizeof(buff));
	fr_ntop(buff, sizeof(buff), &handler->src_ipaddr); 
	MEM(val = json_object_new_string(buff));
	json_object_object_add(obj, "src_ipaddr", val);

	MEM(val = json_object_new_int64(handler->eap_id));
	json_object_object_add(obj, "eap_id", val);

	MEM(val = json_object_new_int64(handler->type));
	json_object_object_add(obj, "type", val);

	MEM(val = json_object_new_int64(handler->timestamp));
	json_object_object_add(obj, "timestamp", val);

	MEM(val = json_object_new_string(handler->identity));
	json_object_object_add(obj, "identity", val);

	MEM(val = json_object_new_int(handler->status));
	json_object_object_add(obj, "status", val);

	MEM(val = json_object_new_int(handler->trips));
	json_object_object_add(obj, "trips", val);

	MEM(val = json_object_new_int(handler->stage));
	json_object_object_add(obj, "stage", val);

	MEM(val = json_object_new_boolean(handler->tls));
	json_object_object_add(obj, "tls", val);

	MEM(val = json_object_new_boolean(handler->started));
	json_object_object_add(obj, "started", val);

	MEM(val = json_object_new_boolean(handler->finished));
	json_object_object_add(obj, "finished", val);

	if (handler->prev_eapds) {
		json_object_object_add(obj, "prev_eapds", eap_ds_to_obj(handler->prev_eapds));
	}

	if (handler->eap_ds) {
		json_object_object_add(obj, "eap_ds", eap_ds_to_obj(handler->eap_ds));
	}

	json_str = json_object_to_json_string_length(obj, 0, &len);
	vp = fr_pair_afrom_num(fake->reply, PW_EAP_SERIALIZED_HANDLER, 0);
	if (!vp) goto error;
	RDEBUG("Serializing: %s\n", json_str);
	fr_pair_value_memcpy(vp, (const uint8_t *) json_str, len);
	fr_pair_add(&(fake->reply->vps), vp);
	json_object_put(obj);
	return 1;

error:
	json_object_put(obj);
	return 0;
}

static int obj_to_eap_packet_t(json_object *obj, eap_packet_t *pkt) {
	json_object *val;
	const char* str;
	size_t len;
	if (!json_object_object_get_ex(obj, "code", &val)) {
		return 0;
	}
	
	pkt->code = json_object_get_int64(val);

	if (!json_object_object_get_ex(obj, "id", &val)) {
		return 0;
	}

	pkt->id = json_object_get_int64(val);

	if (json_object_object_get_ex(obj, "packet", &val)) {
		str = json_object_get_string(val);	
		len = json_object_get_string_len(val);	
		pkt->packet = talloc_size(pkt, len/2);
		fr_hex2bin(pkt->packet, len/2, str, len);
		pkt->length = len / 2;
	}

	if (json_object_object_get_ex(obj, "type_data", &val)) {
		str = json_object_get_string(val);	
		len = json_object_get_string_len(val);	
		pkt->type.data = talloc_size(pkt, len/2);
		fr_hex2bin(pkt->type.data, len/2, str, len);
		pkt->type.length = len / 2;
	}


	if (!json_object_object_get_ex(obj, "typenum", &val)) {
		return 0;
	}
	
	pkt->type.num = json_object_get_int64(val);
	return 1;
}

static int deserialize_eap_ds(EAP_DS *eap_ds, json_object *obj) {
	json_object *val;
	if (!json_object_object_get_ex(obj, "set_request_id", &val)) {
		return 0;
	}
	
	eap_ds->set_request_id = json_object_get_int64(val);

	if (json_object_object_get_ex(obj, "response", &val)) {
		if (!obj_to_eap_packet_t(val, eap_ds->response)) {
			return 0;
		}
	}

	if (json_object_object_get_ex(obj, "request", &val)) {
		if (!obj_to_eap_packet_t(val, eap_ds->request)) {
			return 0;
		}
	}
	return 1;
}

static int deserialized_handler(REQUEST * request, REQUEST * fake, UNUSED rlm_eap_t *inst, eap_handler_t *handler) {
	VALUE_PAIR *vp = NULL;
	json_object *obj, *val;
	const char* str;
	size_t len;
	enum json_tokener_error err;
	vp = fr_pair_find_by_num(fake->reply->vps, PW_EAP_SERIALIZED_HANDLER, 0, TAG_ANY);
	if (!vp) {
		RERROR("Cannot find EAP-Serialized-Handler");
		return 0;
	}
	json_tokener* token;
	MEM(token = json_tokener_new());
	RDEBUG("Deserializing: %*s\n",  vp->vp_length, vp->vp_octets);
	obj = json_tokener_parse_ex(token, (const char*) vp->vp_octets, vp->vp_length);
	err = json_tokener_get_error(token);
	if (err != json_tokener_success) {
		RERROR("Error EAP-Serialized-Handler: %s %d", json_tokener_error_desc(err), err);
error:
		json_tokener_free(token);
		return 0;
	}

	if (!json_object_object_get_ex(obj, "state", &val)) {
		RERROR("Cannot find state");
		goto error;
	}

	str = json_object_get_string(val);	
	len = json_object_get_string_len(val);	
	fr_hex2bin(handler->state, EAP_STATE_LEN, str, len);

	if (!json_object_object_get_ex(obj, "src_ipaddr", &val)) {
		RERROR("Cannot find src_ipaddr");
		goto error;
	}

	str = json_object_get_string(val);	
	len = json_object_get_string_len(val);	
	fr_pton(&handler->src_ipaddr, str, len, AF_UNSPEC, false);

	if (json_object_object_get_ex(obj, "prev_eapds", &val)) {
		handler->prev_eapds = eap_ds_alloc(handler);
		if (!deserialize_eap_ds(handler->prev_eapds, val)) {
			RERROR("Cannot find prev_eapds");
			goto error;
		}
	}

	if (json_object_object_get_ex(obj, "eap_ds", &val)) {
		handler->eap_ds = eap_ds_alloc(handler);
		if (!deserialize_eap_ds(handler->eap_ds, val)) {
			RERROR("Cannot find eap_ds");
			goto error;
		}
	}

	if (!json_object_object_get_ex(obj, "identity", &val)) {
		RERROR("Cannot find identity");
		goto error;
	}

	str = json_object_get_string(val);	
	handler->identity = talloc_strdup(handler, str);

#define SET_INT(f) do {\
	if (!json_object_object_get_ex(obj, #f, &val)) {\
		RERROR("Cannot find " #f);\
		goto error;\
	}\
	handler->f = json_object_get_int64(val);\
	RDEBUG("Setting " #f "with %ld ", handler->f);\
} while(0)

#define SET_BOOL(f) do {\
	if (!json_object_object_get_ex(obj, #f, &val)) {\
		RERROR("Cannot find " #f);\
		goto error;\
	}\
	\
	handler->f = json_object_get_boolean(val);\
} while(0)

	SET_INT(eap_id);
	SET_INT(type);
	SET_INT(timestamp);
	SET_INT(status);
	SET_INT(stage);
	SET_INT(trips);
	SET_BOOL(tls);
	SET_BOOL(started);
	SET_BOOL(finished);

	handler->status = json_object_get_int64(obj);
	json_tokener_free(token);
	return 1;
}

static int add_state(REQUEST * fake, eap_handler_t *handler) {
	VALUE_PAIR *vp = NULL;
	vp = fr_pair_afrom_num(fake->reply, PW_STATE, 0);
	if (!vp) return 0;
	fr_pair_value_memcpy(vp, handler->state, EAP_STATE_LEN);
	fr_pair_add(&fake->reply->vps, vp);
	return 1;
}

int eap_cache_save(REQUEST *request, rlm_eap_t *inst, eap_handler_t *handler) {
	REQUEST * fake = eap_cache_init_fake_request(inst);
	if (!fake) return 0;

	if (!add_state(fake, handler)) goto error;

	if (!serialized_handler(request, fake, inst, handler)) {
		goto error;
	}

	if (!inst->methods[handler->type]->type->serialize(inst, fake, handler)) {
		goto error;
	}

	(void) process_post_auth(CACHE_SAVE, fake);
	talloc_free(fake);
	return 1;

error:
	talloc_free(fake);
	return -1;
}

int eap_cache_enabled(rlm_eap_t *inst, int type) {
	eap_module_t *module = inst->methods[type];
	return inst->cache_virtual_server != NULL && module != NULL && module->type->deserialize != NULL && module->type->serialize != NULL;
}

eap_handler_t* eap_cache_find(rlm_eap_t *inst, eap_handler_t *handler) {
	REQUEST *request = eap_cache_init_fake_request(inst);
	eap_handler_t *new_handler;
	if (!request) return 0;
	if (!add_state(request, handler)) goto error;
	(void) process_post_auth(CACHE_LOAD, request);

	new_handler = eap_handler_alloc(inst);
	if (!deserialized_handler(request, request, inst, new_handler)) {
		RERROR("Failed to deserialize request");
		goto error;
	}
	
	if (!inst->methods[new_handler->type]->type->deserialize(inst, request, new_handler)) {
		goto error;
	}

	return new_handler;
error:
	if (new_handler)
		talloc_free(new_handler);
	talloc_free(request);
	return NULL;
}
