/*
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
 */

/**
 * $Id$
 *
 * @file unlang/subrequest.c
 * @brief Unlang "subrequest" and "detach" keyword evaluation.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/server/state.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/unlang/action.h>
#include "unlang_priv.h"
#include "interpret_priv.h"
#include "subrequest_priv.h"
#include "child_request_priv.h"

/** Send a signal from parent request to subrequest
 *
 */
static void unlang_subrequest_signal(
#ifndef NDEBUG
				     UNUSED
#endif
				     request_t *request, unlang_stack_frame_t *frame, fr_signal_t action)
{
	unlang_child_request_t		*cr = talloc_get_type_abort(frame->state, unlang_child_request_t);
	request_t			*child = talloc_get_type_abort(cr->request, request_t);

	switch (cr->state) {
	case CHILD_DETACHED:
		RDEBUG3("subrequest detached during its execution - Not sending signal to child");
		return;

	case CHILD_CANCELLED:
		RDEBUG3("subrequest is cancelled - Not sending signal to child");
		return;

	case CHILD_RUNNABLE:
		fr_assert_msg(!unlang_request_is_scheduled(request), "Parent cannot be runnable if child has not completed");
		break;

	default:
		break;
	}

	/*
	 *	Parent should never receive a detach
	 *	signal whilst the child is running.
	 *
	 *	Only the child receives a detach
	 *	signal when the detach keyword is used.
	 */
	fr_assert(action != FR_SIGNAL_DETACH);

	/*
	 *	If the server is stopped, inside a breakpoint,
	 *	whilst processing a child, on resumption both
	 *	requests (parent and child) may need to be
	 *	cancelled as they've both hit max request_time.
	 *
	 *	Sometimes the child will run to completion before
	 *	the cancellation is processed, but the parent
	 *	will still be cancelled.
	 *
	 *	When the parent is cancelled this function is
	 *	executed, which will signal an already stopped
	 *	child to cancel itself.
	 *
	 *	This triggers asserts in the time tracking code.
	 *
	 *	...so we check to see if the child is done before
	 *	sending a signal.
	 */
	if (unlang_request_is_done(child)) return;

	/*
	 *	Forward other signals to the child
	 */
	unlang_interpret_signal(child, action);
}

/** Parent being resumed after a child completes
 *
 */
static unlang_action_t unlang_subrequest_parent_resume(UNUSED unlang_result_t *p_result, request_t *request,
						       unlang_stack_frame_t *frame)
{
	unlang_group_t				*g = unlang_generic_to_group(frame->instruction);
	unlang_child_request_t			*cr = talloc_get_type_abort(frame->state, unlang_child_request_t);
	request_t				*child = cr->request;
	unlang_subrequest_t			*gext;

	/*
	 *	Child detached
	 */
	if (cr->state == CHILD_DETACHED) {
		RDEBUG3("subrequest detached during its execution - Not updating rcode or reply attributes");

		/*
		 *	If the child detached the subrequest section
		 *	should become entirely transparent, and
		 *	should not update the section rcode.
		 */
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	RDEBUG3("subrequest completeed with rcode %s",
		fr_table_str_by_value(mod_rcode_table, cr->result.rcode, "<invalid>"));

	/*
	 *	If there's a no destination tmpl, we're done.
	 */
	if (!child->reply) {
		unlang_subrequest_detach_and_free(&child);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Otherwise... copy reply attributes into the
	 *	specified destination.
	 */
	gext = unlang_group_to_subrequest(g);
	if (gext->dst) {
		fr_pair_t		*vp = NULL;
		tmpl_dcursor_ctx_t	cc;
		fr_dcursor_t		cursor;

		/*
		 *	Use callback to build missing destination container.
		 */
		vp = tmpl_dcursor_build_init(NULL, request, &cc, &cursor, request, gext->dst, tmpl_dcursor_pair_build, NULL);
		if (!vp) {
			RPDEBUG("Discarding subrequest attributes - Failed allocating groups");
			tmpl_dcursor_clear(&cc);
			return UNLANG_ACTION_FAIL;
		}

		MEM(fr_pair_list_copy(vp, &vp->vp_group, &child->reply_pairs) >= 0);

		tmpl_dcursor_clear(&cc);
	}

	unlang_subrequest_detach_and_free(&child);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Allocates a new subrequest and initialises it
 *
 */
static unlang_action_t unlang_subrequest_init(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_child_request_t	*cr = talloc_get_type_abort(frame->state, unlang_child_request_t);
	request_t		*child;
	fr_pair_t		*vp;

	unlang_group_t		*g;
	unlang_subrequest_t	*gext;

	/*
	 *	This should only be set for manually pushed subrequests
	 */
	fr_assert(!cr->config.free_child);

	/*
	 *	Initialize the state
	 */
	g = unlang_generic_to_group(frame->instruction);
	if (unlang_list_empty(&g->children)) RETURN_UNLANG_NOOP;

	gext = unlang_group_to_subrequest(g);
	child = unlang_io_subrequest_alloc(request, gext->dict, UNLANG_DETACHABLE);
	if (!child) {
	fail:
		talloc_free(child);
		return UNLANG_ACTION_FAIL;
	}
	/*
	 *	Set the packet type.
	 */
	MEM(vp = fr_pair_afrom_da(child->request_ctx, gext->attr_packet_type));
	if (gext->type_enum) {
		child->packet->code = vp->vp_uint32 = gext->type_enum->value->vb_uint32;
	} else {
		fr_dict_enum_value_t const	*type_enum;
		fr_pair_t		*attr;

		if (tmpl_find_vp(&attr, request, gext->vpt) < 0) {
			RDEBUG("Failed finding attribute %s", gext->vpt->name);
			goto fail;
		}

		if (tmpl_attr_tail_da(gext->vpt)->type == FR_TYPE_STRING) {
			type_enum = fr_dict_enum_by_name(gext->attr_packet_type, attr->vp_strvalue, attr->vp_length);
			if (!type_enum) {
				RDEBUG("Unknown Packet-Type %pV", &attr->data);
				goto fail;
			}

			child->packet->code = vp->vp_uint32 = type_enum->value->vb_uint32;
		} else {
			fr_value_box_t box;

			fr_value_box_init(&box, FR_TYPE_UINT32, NULL, false);
			if (fr_value_box_cast(request, &box, FR_TYPE_UINT32, NULL, &attr->data) < 0) {
				RDEBUG("Failed casting value from %pV to data type uint32", &attr->data);
				goto fail;
			}

			/*
			 *	Check that the value is known to the server.
			 *
			 *	If it isn't known, then there's no
			 *	"recv foo" section for it and we can't
			 *	do anything with this packet.
			 */
			type_enum = fr_dict_enum_by_value(gext->attr_packet_type, &box);
			if (!type_enum) {
				RDEBUG("Invalid value %pV for Packet-Type", &box);
				goto fail;
			}

			child->packet->code = vp->vp_uint32 = box.vb_uint32;
		}

	}
	fr_pair_append(&child->request_pairs, vp);

	if ((gext->src) && (tmpl_copy_pair_children(child->request_ctx, &child->request_pairs, request, gext->src) < -1)) {
		RPEDEBUG("Failed copying source attributes into subrequest");
		goto fail;
	}

	/*
	 *	Setup the child so it'll inform us when
	 *	it resumes, or if it detaches.
	 *
	 *	frame->instruction should be consistent
	 *	as it's allocated by the unlang compiler.
	 */
	if (unlang_child_request_init(cr, cr, child, p_result, NULL, frame->instruction, false) < 0) goto fail;

	/*
	 *	Push the first instruction the child's
	 *	going to run.
	 */
	if (unlang_interpret_push(NULL, child, unlang_list_head(&g->children),
				  FRAME_CONF(RLM_MODULE_NOT_SET, UNLANG_SUB_FRAME),
				  UNLANG_NEXT_SIBLING) < 0) goto fail;

	/*
	 *	Finally, setup the function that will be
	 *	called when the child indicates the
	 *	parent should be resumed.
	 */
	frame_repeat(frame, unlang_subrequest_parent_resume);

	/*
	 *	This is a common function, either pushed
	 *	onto the parent's stack, or called directly
	 *	from the subrequest instruction..
	 */
	return unlang_subrequest_child_run(p_result, request, frame);	/* returns UNLANG_ACTION_YIELD */
}

/** Free a child request, detaching it from its parent and freeing allocated memory
 *
 * @param[in] child to free.
 */
void unlang_subrequest_detach_and_free(request_t **child)
{
	request_detach(*child);
	talloc_free(*child);
	*child = NULL;
}

/** Allocate a subrequest to run through a virtual server at some point in the future
 *
 * @param[in] parent		to hang sub request off of.
 * @param[in] namespace		the child will operate in.
 * @return
 *	- A new child request.
 *	- NULL on failure.
 */
request_t *unlang_subrequest_alloc(request_t *parent, fr_dict_t const *namespace)
{
	return unlang_io_subrequest_alloc(parent, namespace, UNLANG_NORMAL_CHILD);
}


/** Function to run in the context of the parent on resumption
 *
 * @note Only executes if unlang_subrequest_child_push was called, not with the normal subrequest keyword.
 */
static unlang_action_t unlang_subrequest_child_done(unlang_result_t *p_result, UNUSED request_t *request,
						    unlang_stack_frame_t *frame)
{
	unlang_child_request_t		*cr = talloc_get_type_abort(frame->state, unlang_child_request_t);

	/*
	 *	Default to NOOP
	 */
	if (cr->result.rcode == RLM_MODULE_NOT_SET) {
		cr->result.rcode = RLM_MODULE_NOOP;
		if (cr->p_result) {
			*cr->p_result = cr->result;
		} else {
			*p_result = cr->result;
		}
	}

	/*
	 *	We can free the child here as we're its parent
	 */
	if (cr->config.free_child) {
		if (request_is_detachable(cr->request)) {
			unlang_subrequest_detach_and_free(&cr->request);
		} else {
			TALLOC_FREE(cr->request);
		}
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Function called by the unlang interpreter, or manually to start the child running
 *
 * The reason why we do this on the unlang stack is so that _this_ frame
 * is marked as resumable in the parent, not whatever frame was previously
 * being processed by the interpreter when the parent was called.
 *
 * i.e. after calling unlang_subrequest_child_push, the code in the parent
 * can call UNLANG_ACTION_PUSHED_CHILD, which will result in _this_ frame
 * being executed, and _this_ frame can yield.
 *
 * @note Called from the parent to start a child running.
 */
unlang_action_t unlang_subrequest_child_run(UNUSED unlang_result_t *p_result, UNUSED request_t *request,
					    unlang_stack_frame_t *frame)
{
	unlang_child_request_t		*cr = talloc_get_type_abort(frame->state, unlang_child_request_t);
	request_t			*child = cr->request;

	/*
	 *	No parent means this is a pre-detached child
	 *	so the parent should continue executing.
	 */
	if (!child || !child->parent) return UNLANG_ACTION_CALCULATE_RESULT;


	/*
	 *	Ensure we restore the session state information
	 *      into the child.
	 */
	if (cr->config.session_unique_ptr) fr_state_restore_from_parent(child,
								     cr->config.session_unique_ptr,
								     cr->num);
	/*
	 *	Ensures the child is setup correctly and adds
	 *	it into the runnable queue of whatever owns
	 *	the interpreter.
	 */
	interpret_child_init(child);

	/*
	 *	This function is being called by something
	 *	other than the subrequest keyword.
	 *
	 *	Set a different resumption function that
	 *	just writes the final rcode out.
	 */
	if (frame->process == unlang_subrequest_child_run) {
		frame_repeat(frame, unlang_subrequest_child_done);
	}

	cr->state = CHILD_RUNNABLE;

	return UNLANG_ACTION_YIELD;
}

/** Push a pre-existing child back onto the stack as a subrequest
 *
 * The child *MUST* have been allocated with unlang_io_subrequest_alloc, or something
 * that calls it.
 *
 * After the child is no longer required it *MUST* be freed with #unlang_subrequest_detach_and_free.
 * It's not enough to free it with talloc_free.
 *
 * This function should be called _before_ pushing any additional frames onto the child's
 * stack for it to execute.
 *
 * The parent should return UNLANG_ACTION_PUSHED_CHILD, when it's done setting up the
 * child request.  It should NOT return UNLANG_ACTION_YIELD.
 *
 * @param[in] p_result			Where to write the result of the subrequest.
 * @param[in] child			to push.
 * @param[in] unique_session_ptr	Unique identifier for child's session data.
 * @param[in] free_child		automatically free the child when it's finished executing.
 *					This is useful if extracting the result from the child is
 *					done using the child's stack, and so the parent never needs
 *					to access it.
 * @param[in] top_frame			Set to UNLANG_TOP_FRAME if the interpreter should return.
 *					Set to UNLANG_SUB_FRAME if the interprer should continue.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */

int unlang_subrequest_child_push(unlang_result_t *p_result, request_t *child, void const *unique_session_ptr, bool free_child, bool top_frame)
{
	unlang_child_request_t	*cr;
	unlang_stack_frame_t	*frame;

	static unlang_t subrequest_instruction = {
		.type = UNLANG_TYPE_SUBREQUEST,
		.name = "subrequest",
		.debug_name = "subrequest",
		.actions = DEFAULT_MOD_ACTIONS,
	};

	fr_assert_msg(free_child || child->parent, "Child's request pointer must not be NULL when calling subrequest_child_push");

	if (!fr_cond_assert_msg(stack_depth_current(child) == 0,
				"Child stack depth must be 0 (not %d), when calling subrequest_child_push",
				stack_depth_current(child))) return -1;

	/*
	 *	Push a new subrequest frame onto the stack
	 *	of the parent.
	 *
	 *	This allocates memory for the frame state
	 *	which we fill in below.
	 *
	 *	This frame executes once the subrequest has
	 *	completed.
	 */
	if (unlang_interpret_push(NULL, child->parent, &subrequest_instruction,
				  FRAME_CONF(RLM_MODULE_NOT_SET, top_frame), UNLANG_NEXT_STOP) < 0) {
		return -1;
	}

	frame = frame_current(child->parent);
	frame->process = unlang_subrequest_child_run;

	/*
	 *	Setup the state for the subrequest
	 */
	cr = talloc_get_type_abort(frame_current(child->parent)->state, unlang_child_request_t);

	/*
	 *	Initialise our frame state, and push the first
	 *	instruction onto the child's stack.
	 *
	 *	This instruction will mark the parent as runnable
	 *	when it executed.
	 */
	if (unlang_child_request_init(cr, cr, child, p_result, NULL, unique_session_ptr, free_child) < 0) {
		unwind_set(frame);
		return -1;
	}

	return 0;
}

/** Add a child request to the runnable queue
 *
 * @param[in] request		to add to the runnable queue.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int unlang_subrequest_child_push_and_detach(request_t *request)
{
	/*
	 *	Ensures the child is setup correctly and adds
	 *	it into the runnable queue of whatever owns
	 *	the interpreter.
	 */
	interpret_child_init(request);

	if (request_detach(request) < 0) {
		RPEDEBUG("Failed detaching request");
		return -1;
	}

	return 0;
}

static unlang_t *unlang_compile_subrequest(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION			*cs = cf_item_to_section(ci);
	char const			*name2;

	unlang_t			*c;

	unlang_group_t			*g;
	unlang_subrequest_t		*gext;

	unlang_compile_ctx_t		unlang_ctx2;

	tmpl_rules_t			t_rules;
	fr_dict_autoload_talloc_t	*dict_ref = NULL;

	fr_dict_t const			*dict;
	fr_dict_attr_t const		*attr_packet_type = NULL;
	fr_dict_enum_value_t const	*type_enum = NULL;

	ssize_t				slen;
	char 				*namespace = NULL;
	char const			*packet_name = NULL;

	tmpl_t				*vpt = NULL, *src_vpt = NULL, *dst_vpt = NULL;

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	/*
	 *	subrequest { ... }
	 *
	 *	Create a subrequest which is of the same dictionary
	 *	and packet type as the current request.
	 *
	 *	We assume that the Packet-Type attribute exists.
	 */
	name2 = cf_section_name2(cs);
	if (!name2) {
		dict = unlang_ctx->rules->attr.dict_def;
		packet_name = name2 = unlang_ctx->section_name2;		
		attr_packet_type =  virtual_server_packet_type_by_cs(virtual_server_cs(unlang_ctx->vs));
		goto get_packet_type;
	}

	if (cf_section_name2_quote(cs) != T_BARE_WORD) {
		cf_log_err(cs, "The arguments to 'subrequest' must be a name or an attribute reference");
	print_url:
		cf_log_err(ci, DOC_KEYWORD_REF(subrequest));
		return NULL;
	}

	dict = unlang_ctx->rules->attr.dict_def;

	/*
	 *	@foo is "dictionary foo", as with references in the dictionaries.
	 *
	 *	@foo::bar is "dictionary foo, Packet-Type = ::bar"
	 *
	 *	foo::bar is "dictionary foo, Packet-Type = ::bar"
	 *
	 *	::bar is "this dictionary, Packet-Type = ::bar", BUT
	 *	we don't try to parse the new dictionary name, as it
	 *	doesn't exist.
	 */
	if ((name2[0] == '@') ||
	    ((name2[0] != ':') && (name2[0] != '&') && (strchr(name2 + 1, ':') != NULL))) {
		char *q;

		/*
		 *	This is a different protocol dictionary.  We reset the packet type.
		 *
		 *	@todo - the packet type should really be stored in #fr_dict_protocol_t.
		 */
		if (name2[0] == '@') {
			attr_packet_type = NULL;
			name2++;
		}

		MEM(namespace = talloc_strdup(parent, name2));
		q = namespace;

		while (fr_dict_attr_allowed_chars[(unsigned int) *q]) {
			q++;
		}
		*q = '\0';

		dict = fr_dict_by_protocol_name(namespace);
		if (!dict) {
			dict_ref = fr_dict_autoload_talloc(NULL, &dict, namespace);
			if (!dict_ref) {
				cf_log_err(cs, "Unknown namespace in '%s'", name2);
				talloc_free(namespace);
				return NULL;
			}
		}

		/*
		 *	Skip the dictionary name, and go to the thing
		 *	right after it.
		 */
		name2 += (q - namespace);
		TALLOC_FREE(namespace);
	}

	/*
	 *	@dict::enum is "other dictionary, Packet-Type = ::enum"
	 *	::enum is this dictionary, "Packet-Type = ::enum"
	 */
	if ((name2[0] == ':') && (name2[1] == ':')) {
		packet_name = name2;
		goto get_packet_type;
	}

	/*
	 *	Can't do foo.bar.baz::foo, the enums are only used for Packet-Type.
	 */
	if (strchr(name2, ':') != NULL) {
		cf_log_err(cs, "Reference cannot contain enum value in '%s'", name2);
		return NULL;
	}

	/*
	 *	Bare words are attribute references.
	 */
	slen = tmpl_afrom_attr_substr(parent, NULL, &vpt,
				      &FR_SBUFF_IN(name2, talloc_array_length(name2) - 1),
				      NULL, unlang_ctx->rules);
	if (slen <= 0) {
		cf_log_perr(cs, "Invalid argument to 'subrequest', failed parsing packet-type");
		goto print_url;
	}

	fr_assert(tmpl_is_attr(vpt));

	/*
	 *	Anything resembling an integer or string is
	 *	OK.  Nothing else makes sense.
	 */
	switch (tmpl_attr_tail_da(vpt)->type) {
	case FR_TYPE_INTEGER_EXCEPT_BOOL:
	case FR_TYPE_STRING:
		break;

	default:
		talloc_free(vpt);
		cf_log_err(cs, "Invalid data type for attribute %s.  "
			   "Must be an integer type or string", name2 + 1);
		goto print_url;
	}

	dict = unlang_ctx->rules->attr.dict_def;
	packet_name = NULL;

get_packet_type:
	/*
	 *      Local attributes cannot be used in a subrequest.  They belong to the parent.  Local attributes
	 *      are NOT copied to the subrequest.
	 *
	 *      @todo - maybe we want to copy local variables, too?  But there may be multiple nested local
	 *      variables, each with their own dictionary.
	 */
	dict = fr_dict_proto_dict(dict);

	/*
	 *	We're switching virtual servers, find the packet type by name.
	 */
	if (!attr_packet_type) {
		attr_packet_type =  fr_dict_attr_by_name(NULL, fr_dict_root(dict), "Packet-Type");
		if (!attr_packet_type) {
			cf_log_err(cs, "No such attribute 'Packet-Type' in namespace '%s'", fr_dict_root(dict)->name);
	error:
			talloc_free(namespace);
			talloc_free(vpt);
			talloc_free(dict_ref);
			goto print_url;
		}
	}

	if (packet_name) {
		/*
		 *	Allow ::enum-name for packet types
		 */
		if ((packet_name[0] == ':') && (packet_name[1] == ':')) packet_name += 2;

		type_enum = fr_dict_enum_by_name(attr_packet_type, packet_name, -1);
		if (!type_enum) {
			cf_log_err(cs, "No such value '%s' for attribute '%s' in namespace '%s'",
				   packet_name, attr_packet_type->name, fr_dict_root(dict)->name);
			goto error;
		}
	}

	/*
	 *	No longer needed
	 */
	talloc_free(namespace);

	/*
	 *	Source and destination arguments
	 */
	{
		char const	*dst, *src;

		src = cf_section_argv(cs, 0);
		if (src) {
			RULES_VERIFY(unlang_ctx->rules);

			(void) tmpl_afrom_substr(parent, &src_vpt,
						 &FR_SBUFF_IN(src, talloc_array_length(src) - 1),
						 cf_section_argv_quote(cs, 0), NULL, unlang_ctx->rules);
			if (!src_vpt) {
				cf_log_perr(cs, "Invalid argument to 'subrequest', failed parsing src");
				goto error;
			}

			if (!tmpl_contains_attr(src_vpt)) {
				cf_log_err(cs, "Invalid argument to 'subrequest' src must be an attr or list, got %s",
					   tmpl_type_to_str(src_vpt->type));
				talloc_free(src_vpt);
				goto error;
			}

			dst = cf_section_argv(cs, 1);
			if (dst) {
				RULES_VERIFY(unlang_ctx->rules);

				(void) tmpl_afrom_substr(parent, &dst_vpt,
							 &FR_SBUFF_IN(dst, talloc_array_length(dst) - 1),
							 cf_section_argv_quote(cs, 1), NULL, unlang_ctx->rules);
				if (!dst_vpt) {
					cf_log_perr(cs, "Invalid argument to 'subrequest', failed parsing dst");
					goto error;
				}

				if (!tmpl_contains_attr(dst_vpt)) {
					cf_log_err(cs, "Invalid argument to 'subrequest' dst must be an "
						   "attr or list, got %s",
						   tmpl_type_to_str(src_vpt->type));
					talloc_free(src_vpt);
					talloc_free(dst_vpt);
					goto error;
				}
			}
		}
	}

	if (!cf_item_next(cs, NULL)) {
		talloc_free(vpt);
		talloc_free(src_vpt);
		talloc_free(dst_vpt);
		return UNLANG_IGNORE;
	}

	t_rules = *unlang_ctx->rules;
	t_rules.parent = unlang_ctx->rules;
	t_rules.attr.dict_def = dict;
	t_rules.attr.allow_foreign = false;

	/*
	 *	Copy over the compilation context.  This is mostly
	 *	just to ensure that retry is handled correctly.
	 *	i.e. reset.
	 */
	unlang_compile_ctx_copy(&unlang_ctx2, unlang_ctx);

	/*
	 *	Then over-write the new compilation context.
	 */
	unlang_ctx2.section_name1 = "subrequest";
	unlang_ctx2.section_name2 = name2;
	unlang_ctx2.rules = &t_rules;

	/*
	 *	Compile the subsection with a *different* default dictionary.
	 */
	c = unlang_compile_section(parent, &unlang_ctx2, cs, UNLANG_TYPE_SUBREQUEST);
	if (!c) return NULL;

	/*
	 *	Set the dictionary and packet information, which tells
	 *	unlang_subrequest() how to process the request.
	 */
	g = unlang_generic_to_group(c);
	gext = unlang_group_to_subrequest(g);

	if (dict_ref) {
		/*
		 *	Parent the dictionary reference correctly now that we
		 *	have the section with the dependency.  This should
		 *	be fast as dict_ref has no siblings.
		 */
		talloc_steal(gext, dict_ref);
	}
	if (vpt) gext->vpt = talloc_steal(gext, vpt);

	gext->dict = dict;
	gext->attr_packet_type = attr_packet_type;
	gext->type_enum = type_enum;
	gext->src = src_vpt;
	gext->dst = dst_vpt;

	return c;
}


/** Initialise subrequest ops
 *
 */
int unlang_subrequest_op_init(void)
{
	unlang_register(&(unlang_op_t) {
			.name = "subrequest",
			.type = UNLANG_TYPE_SUBREQUEST,

			/*
			 *	Frame can't be cancelled, because children need to
			 *	write out status to the parent.  If we don't do this,
			 *	then all children must be detachable and must detach
			 *	so they don't try and write out status to a "done"
			 *	parent.
			 *
			 *	It's easier to allow the child/parent relationship
			 *	to end normally so that non-detachable requests are
			 *	guaranteed the parent still exists.
				 */
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_RCODE_SET | UNLANG_OP_FLAG_NO_FORCE_UNWIND,

			.compile = unlang_compile_subrequest,
			.interpret = unlang_subrequest_init,
			.signal = unlang_subrequest_signal,

			.unlang_size = sizeof(unlang_subrequest_t),
			.unlang_name = "unlang_subrequest_t",
			.pool_headers = (TMPL_POOL_DEF_HEADERS * 3),
			.pool_len = (TMPL_POOL_DEF_LEN * 3),

			.frame_state_size = sizeof(unlang_child_request_t),
			.frame_state_type = "unlang_child_request_t",
		});

	if (unlang_child_request_op_init() < 0) return -1;

	return 0;
}
