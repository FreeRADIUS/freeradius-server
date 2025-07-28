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

	case FR_TYPE_ATTR:
	case FR_TYPE_NON_LEAF:
		REDEBUG("Cannot convert %s to ruby type", fr_type_to_str(vp->vp_type));
		break;
	}

	return mrb_nil_value();
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

/** Build parent structural pairs needed when a leaf node is set
 *
 */
static void mruby_pair_parent_build(mrb_state *mrb, mruby_pair_t *pair)
{
	mruby_pair_t	*parent = pair->parent;
	if (!parent->vp) mruby_pair_parent_build(mrb, parent);

	if (pair->idx > 0) {
		unsigned int count = fr_pair_count_by_da(&parent->vp->vp_group, pair->da);
		if (count < pair->idx) mrb_raisef(mrb, E_ARGUMENT_ERROR,
						  "Attempt to set instance %d when only %d exist", pair->idx, count);
	}

	if (fr_pair_append_by_da(parent->vp, &pair->vp, &parent->vp->vp_group, pair->da) < 0) {
		mrb_raisef(mrb, E_RUNTIME_ERROR, "Failed adding %s", pair->da->name);
	}
}

/** Convert a ruby value to a fr_pair_t value
 *
 */
static void mruby_roby_to_pair_value(mrb_state *mrb, mrb_value *value, fr_pair_t *vp)
{
	switch (vp->vp_type) {
	case FR_TYPE_STRING:
		*value = mrb_obj_as_string(mrb, *value);
		fr_pair_value_clear(vp);
		fr_pair_value_bstrndup(vp, RSTRING_PTR(*value), RSTRING_LEN(*value), true);
		break;

	case FR_TYPE_OCTETS:
		*value = mrb_obj_as_string(mrb, *value);
		fr_pair_value_clear(vp);
		fr_pair_value_memdup(vp, (uint8_t *)RSTRING_PTR(*value), RSTRING_LEN(*value), true);
		break;

#define RUBYSETINT(_size)	case FR_TYPE_INT ## _size: \
	if (mrb_type(*value) != MRB_TT_INTEGER) mrb_raise(mrb, E_ARGUMENT_ERROR, "Integer value required"); \
	vp->vp_int ## _size = mrb_integer(*value); \
	break;
	RUBYSETINT(8)
	RUBYSETINT(16)
	RUBYSETINT(32)
	RUBYSETINT(64)

#define RUBYSETUINT(_size)	case FR_TYPE_UINT ## _size: \
	if (mrb_type(*value) != MRB_TT_INTEGER) mrb_raise(mrb, E_ARGUMENT_ERROR, "Integer value required"); \
	vp->vp_uint ## _size = mrb_integer(*value); \
	break;
	RUBYSETUINT(8)
	RUBYSETUINT(16)
	RUBYSETUINT(32)
	RUBYSETUINT(64)

#define RUBYSETFLOAT(_size)	case FR_TYPE_FLOAT ## _size: \
	switch (mrb_type(*value)) { \
	case MRB_TT_FLOAT: \
		vp->vp_float ## _size = mrb_float(*value); \
		break; \
	case MRB_TT_INTEGER: \
		vp->vp_float ## _size = mrb_integer(*value); \
		break; \
	default: \
		mrb_raise(mrb, E_ARGUMENT_ERROR, "Float or integer value required"); \
	} \
	break;
	RUBYSETFLOAT(32)
	RUBYSETFLOAT(64)

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
		*value = mrb_obj_as_string(mrb, *value);
		if (fr_pair_value_from_str(vp, RSTRING_PTR(*value), RSTRING_LEN(*value), NULL, false) < 0) {
			mrb_raise(mrb, E_RUNTIME_ERROR, "Failed populating pair");
		}
		break;

	default:
		fr_assert(0);
		break;
	}
}

/** Set a value pair from mruby
 *
 * The ruby method expects one or two arguments
 *   - the value to assign to the pair
 *   - (optional) instance number
 */
static mrb_value mruby_value_pair_set(mrb_state *mrb, mrb_value self)
{
	mruby_pair_t	*pair;
	mrb_value	value;
	mrb_int		idx = 0;
	fr_pair_t	*vp = NULL;
	request_t	*request;

	pair = (mruby_pair_t *)DATA_PTR(self);
	if (!pair) mrb_raise(mrb, E_RUNTIME_ERROR, "Failed to retrieve C data");

	request = pair->request;
	/*
	 *	We use "o" (object) for the first argument type so we can
	 *	accept strings and numbers, according to the pair type.
	 */
	mrb_get_args(mrb, "o|i", &value, &idx);

	if (!pair->parent->vp) mruby_pair_parent_build(mrb, pair->parent);

	if (idx == pair->idx) vp = pair->vp;
	if (!vp) vp = fr_pair_find_by_da_idx(&pair->parent->vp->vp_group, pair->da, idx);
	if (!vp) {
		if (idx > 0) {
			unsigned int count = fr_pair_count_by_da(&pair->parent->vp->vp_group, pair->da);
			if (count < idx) mrb_raisef(mrb, E_ARGUMENT_ERROR,
						    "Attempt to set instance %d when only %d exist", idx, count);
		}

		if (fr_pair_append_by_da(pair->parent->vp, &vp, &pair->parent->vp->vp_group, pair->da) < 0) {
			mrb_raisef(mrb, E_RUNTIME_ERROR, "Failed adding %s", pair->da->name);
		}
	}

	mruby_roby_to_pair_value(mrb, &value, vp);

	RDEBUG2("%pP", vp);
	return mrb_nil_value();
}

/** Append an instance of a value pair from mruby
 *
 * The ruby method expects one argument - the value to assign to the pair
 */
static mrb_value mruby_value_pair_append(mrb_state *mrb, mrb_value self)
{
	mruby_pair_t	*pair;
	mrb_value	value;
	fr_pair_t	*vp = NULL;
	request_t	*request;

	pair = (mruby_pair_t *)DATA_PTR(self);
	if (!pair) mrb_raise(mrb, E_RUNTIME_ERROR, "Failed to retrieve C data");

	request = pair->request;

	mrb_get_args(mrb, "o", &value);

	if (!pair->parent->vp) mruby_pair_parent_build(mrb, pair->parent);

	if (fr_pair_append_by_da(pair->parent->vp, &vp, &pair->parent->vp->vp_group, pair->da) < 0) {
		mrb_raisef(mrb, E_RUNTIME_ERROR, "Failed adding %s", pair->da->name);
	}

	mruby_roby_to_pair_value(mrb, &value, vp);

	RDEBUG2("%pP", vp);
	return mrb_nil_value();
}

/** Delete a value pair from mruby
 *
 * The ruby method expects an optional argument - the instance number
 */
static mrb_value mruby_value_pair_del(mrb_state *mrb, mrb_value self)
{
	mruby_pair_t	*pair;
	mrb_int		idx = 0;
	fr_pair_t	*vp = NULL;

	pair = (mruby_pair_t *)DATA_PTR(self);
	if (!pair) mrb_raise(mrb, E_RUNTIME_ERROR, "Failed to retrieve C data");

	mrb_get_args(mrb, "|i", &idx);

	if (!pair->parent->vp) return mrb_nil_value();

	if (idx == pair->idx) vp = pair->vp;
	if (!vp) vp = fr_pair_find_by_da_idx(&pair->parent->vp->vp_group, pair->da, idx);
	if (!vp) return mrb_nil_value();

	fr_pair_delete(&pair->parent->vp->vp_group, vp);
	if (idx == pair->idx) pair->vp = NULL;
	return mrb_nil_value();
}

/** Implement mruby method_missing functionality to find child pairs
 *
 */
static mrb_value mruby_pair_list_missing(mrb_state *mrb, mrb_value self)
{
	mruby_pair_t		*pair;
	request_t		*request;
	mrb_sym			attr;
	mrb_value		*args = NULL, mruby_pair, pair_args[6], argv;
	mrb_int			argc = 0, len;
	int			i;
	size_t			idx = 0, child_idx = 0;
	char			*attr_name, *child_attr_name = NULL;
	fr_dict_attr_t const	*da, *child_da;
	fr_pair_t		*vp = NULL;

	pair = (mruby_pair_t *)DATA_PTR(self);
	if (!pair) mrb_raise(mrb, E_RUNTIME_ERROR, "Failed to retrieve C data");
	request = pair->request;

	if (fr_type_is_leaf(pair->da->type)) mrb_raisef(mrb, E_RUNTIME_ERROR, "%s is a leaf attribute so has no children",
							pair->da->name);
	mrb_get_args(mrb, "n|*!", &attr, &args, &argc);

	if (argc > 3) mrb_raise(mrb, E_ARGUMENT_ERROR, "Maximum three arguments allowed");

	/*
	 *	Parse any provided arguments.  We allow
	 *	 * int			- instance of attribute
	 *	 * str			- child attribute name
	 *	 * int, str		- instance of parent and child attribute name
	 *	 * str, int		- child attribute and its instance
	 *	 * int, str, int	- instance of parent, child attribute name and instance
	 *
	 *	This is to allow for attribute names which begin with a number (e.g. 3GPP2 VSA) which is not
	 *	allowed in mruby method names.
	 *
	 *	p.request.vendor_specific("3gpp2") gets the pair request.Vendor-Specific.3GPP2
	 */
	for (i = 0; i < argc; i++) {
		argv = args[i];
		switch (mrb_type(argv)) {
		case MRB_TT_INTEGER:
			if (i == 0) {
				idx = mrb_integer(argv);
			} else {
				if (!child_attr_name) mrb_raise(mrb, E_ARGUMENT_ERROR, "Child attribute instance must follow attribute name");
				child_idx = mrb_integer(argv);
			}
			break;

		case MRB_TT_STRING:
			if (child_attr_name) mrb_raise(mrb, E_ARGUMENT_ERROR, "Only one child attribute name allowed");
			child_attr_name = mrb_str_to_cstr(mrb, argv);
			break;

		default:
			mrb_raise(mrb, E_ARGUMENT_ERROR, "Arguments can only be integer (attribute instance), or string (attribute name)");
		}
	}

	attr_name = talloc_strdup(request, mrb_sym_name_len(mrb, attr, &len));
	for (i = 0; i < len; i++) {
		if (attr_name[i] == '_') attr_name[i] = '-';
	}

	da = fr_dict_attr_by_name(NULL, pair->da, attr_name);

	/*
	 *	Allow fallback to internal attributes if the parent is a group or dictionary root.
	 */
	if (!da && (fr_type_is_group(pair->da->type) || pair->da->flags.is_root)) {
		da = fr_dict_attr_by_name(NULL, fr_dict_root(fr_dict_internal()), attr_name);
	}

	if (!da) mrb_raisef(mrb, E_ARGUMENT_ERROR, "Unknown or invalid attriubte name \"%s\"", attr_name);

	if (pair->vp) vp = fr_pair_find_by_da_idx(&pair->vp->vp_group, da, idx);

	pair_args[0] = mruby_inst_object(mrb, pair->inst->mruby_ptr, pair->inst);
	pair_args[1] = mruby_request_object(mrb, pair->inst->mruby_ptr, request);
	pair_args[2] = mruby_dict_attr_object(mrb, pair->inst->mruby_ptr, da);
	pair_args[3] = mrb_int_value(mrb, idx);
	pair_args[4] = mruby_value_pair_object(mrb, pair->inst->mruby_ptr, vp);
	pair_args[5] = mruby_ruby_pair_object(mrb, pair->inst->mruby_ptr, pair);

	mruby_pair = mrb_obj_new(mrb, fr_type_is_leaf(da->type) ? pair->inst->mruby_pair : pair->inst->mruby_pair_list,
				 6, pair_args);

	/*
	 *	No child attr name in the arguments, so return the pair
	 */
	if (!child_attr_name) return mruby_pair;

	for (i = 0; i < (int)strlen(child_attr_name); i++) {
		if (child_attr_name[i] == '_') child_attr_name[i] = '-';
	}

	child_da = fr_dict_attr_by_name(NULL, da, child_attr_name);

	if (!child_da && fr_type_is_group(da->type)) {
		child_da = fr_dict_attr_by_name(NULL, fr_dict_root(fr_dict_internal()), attr_name);
	}

	if (!child_da) mrb_raisef(mrb, E_ARGUMENT_ERROR, "Unknown or invalid attriubte name \"%s\"", attr_name);

	if (vp) vp = fr_pair_find_by_da_idx(&vp->vp_group, child_da, child_idx);

	pair = (mruby_pair_t *)DATA_PTR(mruby_pair);
	pair_args[2] = mruby_dict_attr_object(mrb, pair->inst->mruby_ptr, child_da);
	pair_args[3] = mrb_boxing_int_value(mrb, child_idx);
	pair_args[4] = mruby_value_pair_object(mrb, pair->inst->mruby_ptr, vp);
	pair_args[5] = mruby_ruby_pair_object(mrb, pair->inst->mruby_ptr, pair);

	mruby_pair = mrb_obj_new(mrb, fr_type_is_leaf(da->type) ? pair->inst->mruby_pair : pair->inst->mruby_pair_list, 6, pair_args);

	return mruby_pair;
}

struct RClass *mruby_pair_list_class(mrb_state *mrb, struct RClass *parent)
{
	struct RClass *pair_list;

	pair_list = mrb_define_class_under(mrb, parent, "PairList", mrb->object_class);
	MRB_SET_INSTANCE_TT(pair_list, MRB_TT_DATA);

	mrb_define_method(mrb, pair_list, "initialize", mruby_pair_init, MRB_ARGS_ARG(5,1));
	mrb_define_method(mrb, pair_list, "keys", mruby_pair_list_keys, MRB_ARGS_REQ(0));
	mrb_define_method(mrb, pair_list, "method_missing", mruby_pair_list_missing, MRB_ARGS_OPT(1));

	return pair_list;
}

struct RClass *mruby_pair_class(mrb_state *mrb, struct RClass *parent)
{
	struct RClass *pair;

	pair = mrb_define_class_under(mrb, parent, "Pair", mrb->object_class);
	MRB_SET_INSTANCE_TT(pair, MRB_TT_DATA);

	mrb_define_method(mrb, pair, "initialize", mruby_pair_init, MRB_ARGS_ARG(5,1));
	mrb_define_method(mrb, pair, "get", mruby_value_pair_get, MRB_ARGS_OPT(1));
	mrb_define_method(mrb, pair, "set", mruby_value_pair_set, MRB_ARGS_ARG(1,1));
	mrb_define_method(mrb, pair, "del", mruby_value_pair_del, MRB_ARGS_OPT(1));
	mrb_define_method(mrb, pair, "append", mruby_value_pair_append, MRB_ARGS_REQ(1));

	return pair;
}
