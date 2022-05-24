#ifndef __RLM_EAP_SERIALIZE___H
#define __RLM_EAP_SERIALIZE___H

#define MOD_SERIALIZE_FIX_LENGTH(l) static int mod_serialize(UNUSED void *instance, REQUEST *fake, eap_handler_t *handler) {\
	VALUE_PAIR *vp;\
	vp = fr_pair_afrom_num(fake->reply, PW_EAP_SERIALIZED_OPAQUE, 0);\
	fr_pair_value_memcpy(vp, handler->opaque, l);\
	fr_pair_add(&fake->reply->vps, vp);\
	return 1;\
}

#define MOD_DESERIALIZE_FIX_LENGTH(l) static int mod_deserialize(UNUSED void *instance, REQUEST *fake, eap_handler_t *handler) {\
	VALUE_PAIR *vp;\
	uint8_t * p;\
	vp = fr_pair_find_by_num(fake->reply->vps, PW_EAP_SERIALIZED_OPAQUE, 0, TAG_ANY);\
	if (!vp) return 0;\
    if ( vp->vp_length != l) return 0;\
	p = talloc_memdup(handler, vp->vp_octets, vp->vp_length);\
	if (!p) return 0;\
	handler->opaque = p;\
	return 1;\
}

#endif
