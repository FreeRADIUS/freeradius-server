/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_mruby.c
 * @brief Translates requests between the server an an mruby interpreter.
 *
 * @copyright 2016 Herwin Weststrate (freeradius@herwinw.nl)
 * @copyright 2016 The FreeRADIUS server project
 */

#include "rlm_mruby.h"

typedef struct mruby_pair_s mruby_pair_t;
struct mruby_pair_s {
	rlm_mruby_t const	*inst;		//!< Module instance.  Needed for access to classes
	request_t		*request;	//!< Current request
	fr_dict_attr_t const	*da;		//!< Dictionary attribute for this pair.
	fr_pair_t		*vp;		//!< Real pair if it exists.
	unsigned int		idx;		//!< Instance index.
	mruby_pair_t		*parent;	//!< Parent pair.
};

static mrb_value mruby_request_frconfig(mrb_state *mrb, mrb_value self)
{
	return mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, "@frconfig"));
}

static mrb_value mruby_request_request(mrb_state *mrb, mrb_value self)
{
	return mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, "@request"));
}

static mrb_value mruby_request_reply(mrb_state *mrb, mrb_value self)
{
	return mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, "@reply"));
}

static mrb_value mruby_request_control(mrb_state *mrb, mrb_value self)
{
	return mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, "@control"));
}

static mrb_value mruby_request_session_state(mrb_state *mrb, mrb_value self)
{
	return mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, "@session_state"));
}

struct RClass *mruby_request_class(mrb_state *mrb, struct RClass *parent)
{
	struct RClass *request;

	request = mrb_define_class_under(mrb, parent, "Request", mrb->object_class);

	/* FIXME: Use attr_reader (if available) */
	mrb_define_method(mrb, request, "frconfig", mruby_request_frconfig, MRB_ARGS_NONE());
	mrb_define_method(mrb, request, "request", mruby_request_request, MRB_ARGS_NONE());
	mrb_define_method(mrb, request, "reply", mruby_request_reply, MRB_ARGS_NONE());
	mrb_define_method(mrb, request, "control", mruby_request_control, MRB_ARGS_NONE());
	mrb_define_method(mrb, request, "session_state", mruby_request_session_state, MRB_ARGS_NONE());

	return request;
}

/*
 *	Structures used to identify C data types in mruby pointers
 */
static const struct mrb_data_type mruby_inst_type = {
	.struct_name = "Inst",
	.dfree = NULL
};

static const struct mrb_data_type mruby_request_type = {
	.struct_name = "Request",
	.dfree = NULL
};

static const struct mrb_data_type mruby_dict_attr_type = {
	.struct_name = "DictAttr",
	.dfree = NULL
};

static const struct mrb_data_type mruby_value_pair_type = {
	.struct_name = "ValuePair",
	.dfree = NULL
};

static const struct mrb_data_type mruby_ruby_pair_type = {
	.struct_name = "RubyPair",
	.dfree = NULL
};

/*
 *	Helper functions to return C data type pointers as mruby values
 */
mrb_value mruby_inst_object(mrb_state *mrb, struct RClass *klass, rlm_mruby_t const *inst)
{
	return mrb_obj_value(Data_Wrap_Struct(mrb, klass, &mruby_inst_type, UNCONST(void *, inst)));
}

mrb_value mruby_request_object(mrb_state *mrb, struct RClass *klass, request_t *request)
{
	return mrb_obj_value(Data_Wrap_Struct(mrb, klass, &mruby_request_type, (void *)request));
}

mrb_value mruby_dict_attr_object(mrb_state *mrb, struct RClass *klass, fr_dict_attr_t const *da)
{
	return mrb_obj_value(Data_Wrap_Struct(mrb, klass, &mruby_dict_attr_type, UNCONST(void *,da)));
}

mrb_value mruby_value_pair_object(mrb_state *mrb, struct RClass *klass, fr_pair_t *vp)
{
	return mrb_obj_value(Data_Wrap_Struct(mrb, klass, &mruby_value_pair_type, (void *)vp));
}

static mrb_value mruby_ruby_pair_object(mrb_state *mrb, struct RClass *klass, mruby_pair_t *pair)
{
	return mrb_obj_value(Data_Wrap_Struct(mrb, klass, &mruby_ruby_pair_type, (void *)pair));
}

/** Associate C structure with Ruby object representing a pair
 *
 * Will be called with 5 or 6 arguments
 *  - a pointer to the module instance
 *  - a pointer to the request
 *  - a pointer to the dictionary attribute for the pair
 *  - the instance number of the pair
 *  - a pointer to the real pair (if it exists)
 *  - (optional) the parent pair C structure
 */
static mrb_value mruby_pair_init(mrb_state *mrb, mrb_value self)
{
	mruby_pair_t		*pair, *parent = NULL;
	rlm_mruby_t const	*inst;
	request_t		*request;
	fr_dict_attr_t const	*da;
	mrb_int			idx;
	fr_pair_t		*vp;

	mrb_get_args(mrb, "dddid|d",
		     &inst, &mruby_inst_type,
		     &request, &mruby_request_type,
		     &da, &mruby_dict_attr_type,
		     &idx,
		     &vp, &mruby_value_pair_type,
		     &parent, &mruby_ruby_pair_type);

	/*
	 *	Apparently `initialize` can be called more than once in some
	 *	scenarios, so it is best practice to clear up any old data first
	 */
	pair = (mruby_pair_t *)DATA_PTR(self);
	if (pair) talloc_free(pair);

	/*
	 *	The C data is talloced off frame ctx so we free correctly.
	 */
	pair = talloc(unlang_interpret_frame_talloc_ctx(request), mruby_pair_t);
	mrb_data_init(self, pair, &mruby_value_pair_type);

	*pair = (mruby_pair_t) {
		.inst = inst,
		.request = request,
		.da = da,
		.idx = idx,
		.vp = vp,
		.parent = parent
	};

	return self;
}

/** Fetch the list of children of a list
 *
 */
static mrb_value mruby_pair_list_keys(mrb_state *mrb, mrb_value self)
{
	mruby_pair_t	*pair;
	mrb_value	keys, key;
	fr_pair_t	*vp = NULL;

	pair = (mruby_pair_t *)DATA_PTR(self);
	if (!pair) mrb_raise(mrb, E_RUNTIME_ERROR, "Failed to retrieve C data");

	keys = mrb_ary_new(mrb);
	for (vp = fr_pair_list_head(&pair->vp->vp_group); vp; vp = fr_pair_list_next(&pair->vp->vp_group, vp)) {
		key = mrb_str_new(mrb, vp->da->name, strlen(vp->da->name));
		mrb_ary_push(mrb, keys, key);
	}
	return keys;
}

/** Convert a pair value to a suitable mruby value type
 *
 */
static mrb_value mruby_pair_value_to_ruby(mrb_state *mrb, request_t *request, fr_pair_t *vp)
{
	switch(vp->vp_type){
	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		return mrb_str_new(mrb, vp->vp_ptr, vp->vp_length);

	case FR_TYPE_BOOL:
		return vp->vp_bool ? mrb_obj_value(mrb->true_class) : mrb_obj_value(mrb->false_class);

	case FR_TYPE_UINT8:
		return mrb_int_value(mrb, vp->vp_uint8);
	case FR_TYPE_UINT16:
		return mrb_int_value(mrb, vp->vp_uint16);
	case FR_TYPE_UINT32:
		return mrb_int_value(mrb, vp->vp_uint32);
	case FR_TYPE_UINT64:
		return mrb_int_value(mrb, vp->vp_uint64);
	case FR_TYPE_INT8:
		return mrb_int_value(mrb, vp->vp_int8);
	case FR_TYPE_INT16:
		return mrb_int_value(mrb, vp->vp_int16);
	case FR_TYPE_INT32:
		return mrb_int_value(mrb, vp->vp_int32);
	case FR_TYPE_INT64:
		return mrb_int_value(mrb, vp->vp_int64);
	case FR_TYPE_SIZE:
		return mrb_int_value(mrb, vp->vp_size);

	case FR_TYPE_FLOAT32:
		return mrb_float_value(mrb, vp->vp_float32);
	case FR_TYPE_FLOAT64:
		return mrb_float_value(mrb, vp->vp_float64);

	case FR_TYPE_ETHERNET:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_IFID:
	case FR_TYPE_TIME_DELTA:
	case FR_TYPE_DATE:
	{
		char		*in;
		size_t		len;
		mrb_value	value;

		len = fr_value_box_aprint(request, &in, &vp->data, NULL);
		value = mrb_str_new(mrb, in, len);
		talloc_free(in);
		return value;
	}

	default:
		fr_assert(0);
		break;
	}
}

/** Get a pair value from mruby
 *
 * The mruby method can take an optional argument to specify the instance number
 */
static mrb_value mruby_value_pair_get(mrb_state *mrb, mrb_value self)
{
	mruby_pair_t	*pair;
	request_t	*request;
	mrb_int		idx = 0;
	fr_pair_t	*vp = NULL;

	pair = (mruby_pair_t *)DATA_PTR(self);
	if (!pair) mrb_raise(mrb, E_RUNTIME_ERROR, "Failed to retrieve C data");
	request = pair->request;

	if (mrb_get_argc(mrb) > 0) {
		if (mrb_get_args(mrb, "|i", &idx) < 1) mrb_raise(mrb, E_ARGUMENT_ERROR, "Invalid argument");
	}

	if (idx == pair->idx) vp = pair->vp;
	if (!vp && pair->parent && pair->parent->vp) vp = fr_pair_find_by_da_idx(&pair->parent->vp->vp_group, pair->da, idx);

	if (!vp) return mrb_nil_value();

	return mruby_pair_value_to_ruby(mrb, request, vp);
}

struct RClass *mruby_pair_list_class(mrb_state *mrb, struct RClass *parent)
{
	struct RClass *pair_list;

	pair_list = mrb_define_class_under(mrb, parent, "PairList", mrb->object_class);
	MRB_SET_INSTANCE_TT(pair_list, MRB_TT_DATA);

	mrb_define_method(mrb, pair_list, "initialize", mruby_pair_init, MRB_ARGS_ARG(5,1));
	mrb_define_method(mrb, pair_list, "keys", mruby_pair_list_keys, MRB_ARGS_REQ(0));
	return pair_list;
}

struct RClass *mruby_pair_class(mrb_state *mrb, struct RClass *parent)
{
	struct RClass *pair;

	pair = mrb_define_class_under(mrb, parent, "Pair", mrb->object_class);
	MRB_SET_INSTANCE_TT(pair, MRB_TT_DATA);

	mrb_define_method(mrb, pair, "initialize", mruby_pair_init, MRB_ARGS_ARG(5,1));
	mrb_define_method(mrb, pair, "get", mruby_value_pair_get, MRB_ARGS_OPT(1));

	return pair;
}
