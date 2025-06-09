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

struct RClass *mruby_pair_list_class(mrb_state *mrb, struct RClass *parent)
{
	struct RClass *pair_list;

	pair_list = mrb_define_class_under(mrb, parent, "PairList", mrb->object_class);
	MRB_SET_INSTANCE_TT(pair_list, MRB_TT_DATA);

	mrb_define_method(mrb, pair_list, "initialize", mruby_pair_init, MRB_ARGS_ARG(5,1));
	return pair_list;
}

