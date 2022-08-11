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
#include "unlang_priv.h"
#include "interpret_priv.h"
#include "subrequest_priv.h"
#include "subrequest_child_priv.h"

/** Send a signal from parent request to subrequest
 *
 */
static void unlang_subrequest_parent_signal(UNUSED request_t *request, unlang_stack_frame_t *frame,
					    fr_state_signal_t action)
{
	unlang_frame_state_subrequest_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_subrequest_t);
	request_t			*child = talloc_get_type_abort(state->child, request_t);

	/*
	 *	Parent should never receive a detach
	 *	signal whilst the child is running.
	 *
	 *	Only the child receives a detach
	 *	signal when the detach keyword is used.
	 */
	fr_assert(action != FR_SIGNAL_DETACH);

	/*
	 *	Forward other signals to the child
	 */
	unlang_interpret_signal(child, action);
}

/** Parent being resumed after a child completes
 *
 */
static unlang_action_t unlang_subrequest_parent_resume(rlm_rcode_t *p_result, request_t *request,
						       unlang_stack_frame_t *frame)
{
	unlang_group_t				*g = unlang_generic_to_group(frame->instruction);
	unlang_frame_state_subrequest_t		*state = talloc_get_type_abort(frame->state,
									       unlang_frame_state_subrequest_t);
	request_t				*child = state->child;
	unlang_subrequest_t			*gext;

	RDEBUG3("Subrequest complete");

	/*
	 *	Child detached
	 */
	if (!state->child) {
		RDEBUG3("Child has detached");
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

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
			*p_result = RLM_MODULE_FAIL;
			tmpl_dcursor_clear(&cc);
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		MEM(fr_pair_list_copy(vp, &vp->vp_group, &child->reply_pairs) >= 0);

		tmpl_dcursor_clear(&cc);
	}

	unlang_subrequest_detach_and_free(&child);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_subrequest_parent_init(rlm_rcode_t *p_result, request_t *request,
						     unlang_stack_frame_t *frame)
{
	unlang_frame_state_subrequest_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_subrequest_t);
	request_t			*child;
	rlm_rcode_t			rcode;
	fr_pair_t			*vp;

	unlang_group_t			*g;
	unlang_subrequest_t		*gext;

	/*
	 *	Initialize the state
	 */
	g = unlang_generic_to_group(frame->instruction);
	if (!g->num_children) {
		*p_result = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	gext = unlang_group_to_subrequest(g);
	child = state->child = unlang_io_subrequest_alloc(request, gext->dict, UNLANG_DETACHABLE);
	if (!child) {
	fail:
		rcode = RLM_MODULE_FAIL;

		/*
		 *	Pass the result back to the module
		 *	that created the subrequest, or
		 *	use it to modify the current section
		 *	rcode.
		 */
		if (state->p_result) *state->p_result = rcode;

		*p_result = rcode;
		return UNLANG_ACTION_CALCULATE_RESULT;
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

		if (tmpl_da(gext->vpt)->type == FR_TYPE_STRING) {
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

	if (gext->src) {
		if (tmpl_is_list(gext->src)) {
			if (tmpl_copy_pairs(child->request_ctx, &child->request_pairs, request, gext->src) < -1) {
				RPEDEBUG("Failed copying source attributes into subrequest");
				goto fail;
			}
		} else {
			if (tmpl_copy_pair_children(child->request_ctx, &child->request_pairs, request, gext->src) < -1) {
				RPEDEBUG("Failed copying source attributes into subrequest");
				goto fail;
			}
		}
	}

	/*
	 *	Setup the child so it'll inform us when
	 *	it resumes, or if it detaches.
	 */
	if (unlang_subrequest_child_push_resume(child, state) < 0) goto fail;

	/*
	 *	Push the first instruction the child's
	 *	going to run.
	 */
	if (unlang_interpret_push(child, g->children, frame->result,
				  UNLANG_NEXT_SIBLING, UNLANG_SUB_FRAME) < 0) goto fail;

	state->p_result = p_result;
	state->detachable = true;

	/*
	 *	Store/restore session information in the subrequest
	 *	keyed off the exact subrequest keyword.
	 */
	state->session.enable = true;
	state->session.unique_ptr = frame->instruction;
	state->session.unique_int = 0;

	frame_repeat(frame, unlang_subrequest_parent_resume);

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

/** Initialise subrequest ops
 *
 */
int unlang_subrequest_op_init(void)
{
	unlang_register(UNLANG_TYPE_SUBREQUEST,
			&(unlang_op_t){
				.name = "subrequest",
				.interpret = unlang_subrequest_parent_init,
				.signal = unlang_subrequest_parent_signal,
				.debug_braces = true,
				.frame_state_size = sizeof(unlang_frame_state_subrequest_t),
				.frame_state_type = "unlang_frame_state_subrequest_t",
			});

	if (unlang_subrequest_child_op_init() < 0) return -1;

	return 0;
}

void unlang_subrequest_op_free(void)
{
	unlang_subrequest_child_op_free();
}
