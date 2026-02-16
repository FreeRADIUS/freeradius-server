#pragma once
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
 * @file src/lib/server/process.h
 * @brief Declarations for functions which process packet state machines
 *
 * This is a convenience header to simplify defining packet processing state machines.
 *
 * The following macros must be defined before this header is included:
 *
 * - PROCESS_INST			the type of structure that holds instance data for the process module.
 * - PROCESS_PACKET_TYPE		an enum, or generic type (uint32) that can hold
 *					all valid packet types.
 * - PROCESS_PACKET_CODE_VALID		the name of a macro or function which accepts one argument
 *      				and evaluates to true if the packet code is valid.
 *
 * The following macros may (optionally) be defined before this header is included:
 *
 * - PROCESS_CODE_MAX			the highest valid protocol packet code + 1.
 * - PROCESS_CODE_DO_NOT_RESPOND	The packet code that's used to indicate that no response
 *					should be sent.
 * - PROCESS_STATE_EXTRA_FIELDS		extra fields to add to the fr_process_state_t structure.
 *
 * @copyright 2021 The FreeRADIUS server project
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/process_types.h>

/** Trace each state function as it's entered
 */
#ifndef NDEBUG
#  define PROCESS_TRACE	RDEBUG3("Entered state %s", __FUNCTION__)
#else
#  define PROCESS_TRACE
#endif

/** Convenience macro for providing CONF_SECTION offsets in section compilation arrays
 *
 */
#ifndef PROCESS_INST
#  error PROCESS_INST must be defined to the C type of the process instance e.g. process_bfd_t
#endif

#if defined(PROCESS_RCTX) && defined(PROCESS_RCTX_EXTRA_FIELDS)
#  error Only one of PROCESS_RCTX (the type of the rctx struct) OR PROCESS_RCTX_EXTRA_FIELDS (extra fields for the common rctx struct) can be defined.
#endif

#ifndef PROCESS_RCTX
#  define PROCESS_RCTX	process_rctx_t
#endif

#ifndef PROCESS_RCTX_RESULT
#  define PROCESS_RCTX_RESULT result
#endif

#define PROCESS_CONF_OFFSET(_x)	offsetof(PROCESS_INST, sections._x)
#define RESULT_UNUSED		UNUSED

#if defined(PROCESS_INST) && defined(PROCESS_PACKET_TYPE) && defined(PROCESS_PACKET_CODE_VALID)
typedef PROCESS_PACKET_TYPE fr_process_rcode_t[RLM_MODULE_NUMCODES];

#ifndef PROCESS_STATE_EXTRA_FIELDS
#  define PROCESS_STATE_EXTRA_FIELDS
#endif

#ifndef PROCESS_RCTX_EXTRA_FIELDS
#  define PROCESS_RCTX_EXTRA_FIELDS
#endif
/*
 *	Process state machine tables for rcode to packet.
 */
typedef struct {
	PROCESS_PACKET_TYPE	packet_type[RLM_MODULE_NUMCODES];	//!< rcode to packet type mapping.
	PROCESS_PACKET_TYPE	default_reply;	//!< if not otherwise set
	size_t			section_offset;	//!< Where to look in the process instance for
						///< a pointer to the section we should execute.
	rlm_rcode_t		default_rcode;	//!< Default rcode that's set in the frame we used to
						///< evaluate child sections.
	rlm_rcode_t		result_rcode;	//!< Result rcode we return if the virtual server is
						///< being called using the `call` keyword.
	module_method_t		resume;		//!< Function to call after running a recv section.

	/*
	 *	Each state has only one "recv" or "send".
	 */
	union {
		module_method_t		recv;		//!< Method to call when receiving this type of packet.
		module_method_t		send;		//!< Method to call when sending this type of packet.
	};
	PROCESS_STATE_EXTRA_FIELDS
} fr_process_state_t;

typedef struct {
	unlang_result_t		result;		//!< Result of the last section executed.
	PROCESS_RCTX_EXTRA_FIELDS
} process_rctx_t;

/*
 *	C doesn't technically support forward declaration of static variables.  Until such time as we
 *	rearrange all of the process code, disabling the warnings will have to do.
 *
 *	A real fix is to provide a header file which contains only the macro definitions for the process state
 *	machine.  The process files can include that, then define the function prototypes.  Then define their
 *	own process_state[] state machine, then define the functions.
 */
#ifdef __clang__
DIAG_OFF(tentative-definition-compat)
DIAG_OFF(tentative-definition-incomplete-type)
#endif

/*
 *	Some protocols have the same packet codes for requests and replies.
 */
#ifndef PROCESS_SEND_RECV
#define process_state_packet process_state
#define process_state_reply process_state
static fr_process_state_t const process_state[];
#else
static fr_process_state_t const process_state_packet[];
static fr_process_state_t const process_state_reply[];
#endif

/*
 *	Process state machine functions
 */
#define UPDATE_STATE_CS(_x) \
do { \
	state = &process_state_ ## _x[request->_x->code]; \
	memcpy(&cs, (CONF_SECTION * const *) (((uint8_t const *) &inst->sections) + state->section_offset), sizeof(cs)); \
} while (0)

#define UPDATE_STATE(_x) state = &process_state_ ## _x [request->_x->code]

#define RECV(_x) static inline unlang_action_t recv_ ## _x(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
#define SEND(_x) static inline unlang_action_t send_ ## _x(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
#define SEND_NO_RESULT(_x) static inline unlang_action_t send_ ## _x(UNUSED unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
#define RESUME(_x) static inline unlang_action_t resume_ ## _x(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
#define RESUME_FLAG(_x, _p_result_flag, _mctx_flag) static inline unlang_action_t resume_ ## _x(_p_result_flag unlang_result_t *p_result, _mctx_flag module_ctx_t const *mctx, request_t *request)

/** Returns the current rcode then resets it for the next module call
 *
 */
static inline CC_HINT(always_inline) unlang_result_t *process_result_reset(unlang_result_t *p_result, fr_process_state_t const *state)
{
	*p_result = UNLANG_RESULT_RCODE(state->default_rcode);
	return p_result;
}

#define RESULT_RCODE 	(((PROCESS_RCTX *)mctx->rctx)->result.rcode)
#define RESULT_P	process_result_reset(&(((PROCESS_RCTX *)mctx->rctx)->result), state)

/** Call a module method with a new rctx
 *
 * @note This should be used to add a rctxs when calling the initial recv section.
 *
 * @param[out] p_result		Pointer to the result code.
 * @param[in] mctx		Module context.
 * @param[in] request		Request.
 * @param[in] method		Method to call.
 * @param[in] rctx		Resume context to use to override the one in the mctx.
 * @return			Result of the method call.
 */
static inline CC_HINT(always_inline)
unlang_action_t process_with_rctx(unlang_result_t *p_result, module_ctx_t const *mctx,
				  request_t *request, module_method_t method, void *rctx)
{
	module_ctx_t our_mctx = *mctx;
	our_mctx.rctx = rctx;

	return method(p_result, &our_mctx, request);
}

/** Call a named recv function directly
 */
#define CALL_RECV(_x) recv_ ## _x(p_result, mctx, request)

/** Call a named recv function directly with a new rctx
 */
#define CALL_RECV_RCTX(_x, _rctx) process_with_rctx(p_result, mctx, request, recv_ ## _x, _rctx);

/** Call a named send function directly
 */
#define CALL_SEND(_x) send_ ## _x(p_result, mctx, request)

/** Call a named resume function directly
 */
#define CALL_RESUME(_x) resume_ ## _x(p_result, mctx, request)

/** Call the send function for the current state
 */
#define CALL_SEND_STATE(_state) state->send(p_result, mctx, request)

/** Set the current reply code, and call the send function for that state
 */
#define CALL_SEND_TYPE(_x) call_send_type(process_state_reply[(request->reply->code = _x)].send, p_result, mctx, request)

static inline unlang_action_t call_send_type(module_method_t send, \
					     unlang_result_t *p_result, module_ctx_t const *mctx,
					     request_t *request)
{
	/*
	 *	Stupid hack to stop this being honoured
	 *	by send_generic.
	 */
	pair_delete_reply(attr_packet_type);
	return send(p_result, mctx, request);
}

RECV(generic)
{
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	PROCESS_INST			*inst = mctx->mi->data;

	PROCESS_TRACE;

	UPDATE_STATE_CS(packet);

	if (!state->recv) {
		char const *name;

		name = fr_dict_enum_name_by_value(attr_packet_type, fr_box_uint32(request->packet->code));
		if (name) {
			REDEBUG("Invalid packet type (%s)", name);
		} else {
			REDEBUG("Invalid packet type (%u)", request->packet->code);
		}
		RETURN_UNLANG_FAIL;
	}


	if (cs) RDEBUG("Running '%s %s' from file %s", cf_section_name1(cs), cf_section_name2(cs), cf_filename(cs));
	return unlang_module_yield_to_section(RESULT_P, request,
					      cs, state->default_rcode, state->resume,
					      NULL, 0, mctx->rctx);
}

RESUME(recv_generic)
{
	rlm_rcode_t			rcode = RESULT_RCODE;
	fr_process_state_t const	*state;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);

	request->reply->code = state->packet_type[rcode];
	if (!request->reply->code) request->reply->code = state->default_reply;
#ifdef PROCESS_CODE_DO_NOT_RESPOND
	if (!request->reply->code) request->reply->code = PROCESS_CODE_DO_NOT_RESPOND;

#endif
	fr_assert(PROCESS_PACKET_CODE_VALID(request->reply->code));

	UPDATE_STATE(reply);
	fr_assert(state->send != NULL);
	return state->send(p_result, mctx, request);
}

RESUME_FLAG(recv_no_send,UNUSED,UNUSED)
{
	rlm_rcode_t			rcode = RESULT_RCODE;
	fr_process_state_t const	*state;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);

	request->reply->code = state->packet_type[rcode];
	if (!request->reply->code) request->reply->code = state->default_reply;
#ifdef PROCESS_CODE_DO_NOT_RESPOND
	if (!request->reply->code) request->reply->code = PROCESS_CODE_DO_NOT_RESPOND;

#endif
	fr_assert(request->reply->code != 0);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

SEND_NO_RESULT(generic)
{
	fr_pair_t 			*vp;
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	PROCESS_INST   			*inst = mctx->mi->data;

	PROCESS_TRACE;

#ifndef NDEBUG
	if (!(
#  ifdef PROCESS_CODE_DO_NOT_RESPOND
	    (request->reply->code == PROCESS_CODE_DO_NOT_RESPOND) ||
#  endif
	    PROCESS_PACKET_CODE_VALID(request->reply->code))) fr_assert(0);
#endif

	UPDATE_STATE_CS(reply);

	/*
	 *	Allow for over-ride of reply code, IF it's
	 *	within range, AND we've pre-compiled the
	 *	unlang.
	 *
	 *	Add reply->packet-type in case we're
	 *	being called via the `call {}` keyword.
	 *
	 *	@todo - enforce that this is an allowed reply for the
	 *	request.
	 */
	switch (pair_update_reply(&vp, attr_packet_type)) {
	case 0:	/* Does not exist */
	update_packet_type:
		vp->vp_uint32 = request->reply->code;
		break;

	case 1:	/* Exists */
		if (
#ifdef PROCESS_CODE_MAX
		    (vp->vp_uint32 != PROCESS_CODE_MAX) &&
#endif
		    PROCESS_PACKET_CODE_VALID(vp->vp_uint32) &&
		    process_state_reply[vp->vp_uint32].send) {
			request->reply->code = vp->vp_uint32;
			UPDATE_STATE_CS(reply);
			break;
		}

		RWDEBUG("Ignoring invalid packet-type reply.%pP", vp);
		goto update_packet_type;

	default:
		MEM(0);
	}

	if (cs) {
		RDEBUG("Running '%s %s' from file %s", cf_section_name1(cs), cf_section_name2(cs), cf_filename(cs));
	} else {
		char const *name;

		name = fr_dict_enum_name_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
		if (name) {
			RWDEBUG("No 'send %s { ... } section was found.", name);
		} else {
			RWDEBUG("No 'send %u { ... } section was found.", request->reply->code);
		}
	}

	return unlang_module_yield_to_section(RESULT_P, request,
					      cs, state->default_rcode, state->resume,
					      NULL, 0, mctx->rctx);
}

RESUME(send_generic)
{
	rlm_rcode_t			rcode = RESULT_RCODE;
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	PROCESS_INST 	  		*inst = mctx->mi->data;

	PROCESS_TRACE;

#ifndef NDEBUG
	if (!(
#  ifdef PROCESS_CODE_DO_NOT_RESPOND
	    (request->reply->code == PROCESS_CODE_DO_NOT_RESPOND) ||
#  endif
	    PROCESS_PACKET_CODE_VALID(request->reply->code))) fr_assert(0);
#endif
	/*
	 *	If they delete &reply.Packet-Type, tough for them.
	 */
	UPDATE_STATE_CS(reply);

	fr_assert(rcode < RLM_MODULE_NUMCODES);
	switch (state->packet_type[rcode]) {
	case 0:			/* don't change the reply */
		p_result->rcode = state->result_rcode;
		break;

	default:
		/*
		 *	If we're in the "do not respond" situation,
		 *	then don't change the packet code to something
		 *	else.  However, if we're in (say) Accept, and
		 *	the code says Reject, then go do reject.
		 *
		 *	The author of the state machine MUST ensure
		 *	that there isn't a loop in the state machine
		 *	definitions.
		 */
		if (
#ifdef PROCESS_CODE_DO_NOT_RESPOND
		    (request->reply->code != PROCESS_CODE_DO_NOT_RESPOND) &&
#endif
		    (state->packet_type[rcode] != request->reply->code)) {
			char const *old = cf_section_name2(cs);

			request->reply->code = state->packet_type[rcode];
			UPDATE_STATE_CS(reply);

			RWDEBUG("Failed running 'send %s', changing reply to %s", old, cf_section_name2(cs));

			return unlang_module_yield_to_section(RESULT_P, request,
							      cs, state->default_rcode, state->send,
							      NULL, 0, mctx->rctx);
		}
		p_result->rcode = state->result_rcode;

		fr_assert(!state->packet_type[rcode] || (state->packet_type[rcode] == request->reply->code));
		break;

#ifdef PROCESS_CODE_DO_NOT_RESPOND
	case PROCESS_CODE_DO_NOT_RESPOND:
		/*
		 *	There might not be send section defined
		 */
		if (cs) {
			RDEBUG("The 'send %s' section returned %s - not sending a response",
			       cf_section_name2(cs),
			       fr_table_str_by_value(rcode_table, rcode, "<INVALID>"));
		}
		request->reply->code = PROCESS_CODE_DO_NOT_RESPOND;
		p_result->rcode = state->result_rcode;
		break;
#endif
	}


	request->reply->timestamp = fr_time();

#ifdef PROCESS_CODE_DO_NOT_RESPOND
	/*
	 *	Check for "do not respond".
	 */
	if (request->reply->code == PROCESS_CODE_DO_NOT_RESPOND) {
		RDEBUG("Not sending reply to client");
		p_result->rcode = RLM_MODULE_HANDLED;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}
#endif

	return UNLANG_ACTION_CALCULATE_RESULT;
}

#ifdef PROCESS_CODE_DYNAMIC_CLIENT
RESUME_FLAG(new_client_done,,UNUSED)
{
	p_result->rcode = RLM_MODULE_OK;

	request->reply->timestamp = fr_time();

	return UNLANG_ACTION_CALCULATE_RESULT;
}

RESUME(new_client)
{
	rlm_rcode_t			rcode = RESULT_RCODE;
	CONF_SECTION			*cs;
	PROCESS_INST const		*inst = mctx->mi->data;
	fr_process_state_t const	*state;

	UPDATE_STATE(reply);

	switch (rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		RDEBUG("new client was successful.");
		cs = inst->sections.add_client;
		request->reply->code = PROCESS_CODE_DYNAMIC_CLIENT;
		break;

	default:
		RDEBUG("new client was denied.");
		cs = inst->sections.deny_client;
		request->reply->code = PROCESS_CODE_DO_NOT_RESPOND;
		break;
	}

	request->component = NULL;
	request->module = NULL;

	if (!cs) {
		p_result->rcode = RLM_MODULE_OK;
		request->reply->timestamp = fr_time();
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	RDEBUG("Running '%s %s' from file %s", cf_section_name1(cs), cf_section_name2(cs), cf_filename(cs));
	return unlang_module_yield_to_section(RESULT_P, request,
					      cs, RLM_MODULE_FAIL, resume_new_client_done,
					      NULL, 0, mctx->rctx);
}

static inline unlang_action_t new_client(UNUSED unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	CONF_SECTION			*cs;
	PROCESS_INST const		*inst = mctx->mi->data;
	fr_process_state_t const	*state;

	UPDATE_STATE(packet);

	PROCESS_TRACE;
	fr_assert(inst->sections.new_client != NULL);
	cs = inst->sections.new_client;

	RDEBUG("Running '%s %s' from file %s", cf_section_name1(cs), cf_section_name2(cs), cf_filename(cs));
	return unlang_module_yield_to_section(RESULT_P, request,
					      cs, RLM_MODULE_FAIL, resume_new_client,
					      NULL, 0, mctx->rctx);
}

#define DYNAMIC_CLIENT_SECTIONS \
	{ \
		.section = SECTION_NAME("new", "client"), \
		.actions = &mod_actions_authorize, \
		.offset = PROCESS_CONF_OFFSET(new_client), \
	}, \
	{ \
		.section = SECTION_NAME("add", "client"), \
		.actions = &mod_actions_authorize, \
		.offset = PROCESS_CONF_OFFSET(add_client), \
	}, \
	{ \
		.section = SECTION_NAME("deny", "client"), \
		.actions = &mod_actions_authorize, \
		.offset = PROCESS_CONF_OFFSET(deny_client), \
	}

#endif	/* PROCESS_DYNAMIC_CLIENT */

#endif	/* defined(PROCESS_INST) && defined(PROCESS_PACKET_TYPE) && defined(PROCESS_PACKET_CODE_VALID) */

#ifdef __cplusplus
}
#endif
