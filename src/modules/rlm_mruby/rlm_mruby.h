#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file rlm_mruby.h
 * @brief Translates requests between the server an an mruby interpreter.
 *
 * @copyright 2016 Herwin Weststrate (freeradius@herwinw.nl)
 * @copyright 2016 The FreeRADIUS server project
 */

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(documentation)
#include <mruby.h>
#include <mruby/compile.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/numeric.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/data.h>
DIAG_ON(documentation)
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)
#include <freeradius-devel/server/base.h>

typedef struct {
	char const *filename;
	char const *module_name;

	fr_rb_tree_t	funcs;			//!< Tree of function calls found by call_env parser.
	bool		funcs_init;		//!< Has the tree been initialised.

	mrb_state *mrb;

	struct RClass *mruby_module;
	struct RClass *mruby_request;
	mrb_value mrubyconf_hash;
} rlm_mruby_t;

struct RClass *mruby_request_class(mrb_state *mrb, struct RClass *parent);
mrb_value mruby_inst_object(mrb_state *mrb, struct RClass *klass, rlm_mruby_t const *inst);
mrb_value mruby_request_object(mrb_state *mrb, struct RClass *klass, request_t *request);
mrb_value mruby_value_pair_object(mrb_state *mrb, struct RClass *klass, fr_pair_t *vp);
mrb_value mruby_dict_attr_object(mrb_state *mrb, struct RClass *klass, fr_dict_attr_t const *da);
