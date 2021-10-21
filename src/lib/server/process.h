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
 * - PROCESS_INST			the type fo structure that holds instance data for the process module.
 * - PROCESS_PACKET_TYPE		an enum, or generic type (uint32) that can hold
 *					all valid packet types.
 * - PROCESS_PACKET_CODE_VALID		the name of a macro or function which accepts one argument
 *      				and evaluates to true if the packet code is valid.
 *
 * The following macros may (optionally) be defined before this header is included:
 *
 * - PROCESS_CODE_MAX			the highest valid protocol packet code + 1.
 * - PROCESS_DO_NOT_RESPOND		The packet code that's used to indicate that no response
 *					should be sent.
 * - PROCESS_STATE_EXTRA_FIELDS		extra fields to add to the fr_process_state_t structure.
 *
 * @copyright 2021 The FreeRADIUS server project
 * @copyright 2021 Network RADIUS SARL (legal@networkradius.com)
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/pair.h>

/** Common public symbol definition for all process modules
 */
typedef struct fr_process_module_s {
	DL_MODULE_COMMON;				//!< Common fields for all loadable modules.
	FR_MODULE_COMMON;				//!< bootstrap, instantiate

	module_method_t			process;	//!< Process packets
	virtual_server_compile_t const	*compile_list;	//!< list of processing sections
	fr_dict_t const			**dict;		//!< pointer to local fr_dict_t *
} fr_process_module_t;

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
#ifdef PROCESS_INST
#  define PROCESS_CONF_OFFSET(_x)	offsetof(PROCESS_INST, sections._x)
#endif

#if defined(PROCESS_INST) && defined(PROCESS_PACKET_TYPE) && defined(PROCESS_PACKET_CODE_VALID)
typedef PROCESS_PACKET_TYPE fr_process_rcode_t[RLM_MODULE_NUMCODES];

#ifndef PROCESS_STATE_EXTRA_FIELDS
#  define PROCESS_STATE_EXTRA_FIELDS
#endif

/*
 *	Process state machine tables for rcode to packet.
 */
typedef struct {
	PROCESS_PACKET_TYPE	packet_type[RLM_MODULE_NUMCODES];	//!< rcode to packet type mapping.
	PROCESS_PACKET_TYPE	default_reply;	//!< if not otherwise set
	size_t			section_offset;	//!< Where to look in the process instance for
						///< a pointer to the section we should execute.
	rlm_rcode_t		rcode;		//!< Default rcode
	module_method_t		recv;		//!< Method to call when receiving this type of packet.
	unlang_module_resume_t	resume;		//!< Function to call after running a recv section.
	unlang_module_resume_t	send;		//!< Method to call when sending this type of packet.
	PROCESS_STATE_EXTRA_FIELDS
} fr_process_state_t;

/*
 *	Process state machine functions
 */
#define UPDATE_STATE_CS(_x) \
do { \
	state = &process_state[request->_x->code]; \
	memcpy(&cs, (CONF_SECTION * const *) (((uint8_t const *) &inst->sections) + state->section_offset), sizeof(cs)); \
} while (0)

#define UPDATE_STATE(_x) state = &process_state[request->_x->code]

static fr_process_state_t const process_state[];

#define RECV(_x) static inline unlang_action_t recv_ ## _x(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
#define SEND(_x) static inline unlang_action_t send_ ## _x(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request, void *rctx)
#define RESUME(_x) static inline unlang_action_t resume_ ## _x(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request, void *rctx)
#define SEND_NO_RCTX(_x) static inline unlang_action_t send_ ## _x(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request, UNUSED void *rctx)
#define RESUME_NO_RCTX(_x) static inline unlang_action_t resume_ ## _x(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request, UNUSED void *rctx)
#define RESUME_NO_MCTX(_x) static inline unlang_action_t resume_ ## _x(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request, UNUSED void *rctx)

/** Call a named recv function directly
 */
#define CALL_RECV(_x) recv_ ## _x(p_result, mctx, request);

/** Call a named send function directly
 */
#define CALL_SEND(_x) send_ ## _x(p_result, mctx, request, rctx)

/** Call a named resume function directly
 */
#define CALL_RESUME(_x) resume_ ## _x(p_result, mctx, request, rctx)

/** Call the send function for the current state
 */
#define CALL_SEND_STATE(_state) state->send(p_result, mctx, request, rctx)

/** Set the current reply code, and call the send function for that state
 */
#define CALL_SEND_TYPE(_x) call_send_type(process_state[(request->reply->code = _x)].send, p_result, mctx, request, rctx)

static inline unlang_action_t call_send_type(unlang_module_resume_t send, \
					     rlm_rcode_t *p_result, module_ctx_t const *mctx,
					     request_t *request, void *rctx)
{
	/*
	 *	Stupid hack to stop this being honoured
	 *	by send_generic.
	 */
	pair_delete_reply(attr_packet_type);
	return send(p_result, mctx, request, rctx);
}

RECV(generic)
{
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	PROCESS_INST const		*inst = mctx->instance;

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
		RETURN_MODULE_FAIL;
	}


	if (cs) RDEBUG("Running '%s %s' from file %s", cf_section_name1(cs), cf_section_name2(cs), cf_filename(cs));
	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->resume,
					      NULL, NULL);
}

RESUME(recv_generic)
{
	rlm_rcode_t			rcode = *p_result;
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	PROCESS_INST const   		*inst = mctx->instance;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);

	request->reply->code = state->packet_type[rcode];
	if (!request->reply->code) request->reply->code = state->default_reply;
#ifdef PROCESS_CODE_DO_NOT_RESPOND
	if (!request->reply->code) request->reply->code = PROCESS_CODE_DO_NOT_RESPOND;

#endif
	fr_assert(request->reply->code != 0);

	UPDATE_STATE_CS(reply);

	fr_assert(state->send != NULL);
	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->send,
					      NULL, rctx);
}

RESUME_NO_MCTX(recv_no_send)
{
	rlm_rcode_t			rcode = *p_result;
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

SEND(generic)
{
	fr_pair_t 			*vp;
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	PROCESS_INST const   		*inst = mctx->instance;

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
		    process_state[vp->vp_uint32].send) {
			request->reply->code = vp->vp_uint32;
			UPDATE_STATE_CS(reply);
			break;
		}

		RWDEBUG("Ignoring invalid packet-type &reply.%pP", vp);
		goto update_packet_type;

	default:
		MEM(0);
	}

	if (cs) RDEBUG("Running '%s %s' from file %s", cf_section_name1(cs), cf_section_name2(cs), cf_filename(cs));

	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->resume,
					      NULL, rctx);
}

RESUME(send_generic)
{
	rlm_rcode_t			rcode = *p_result;
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	PROCESS_INST const   		*inst = mctx->instance;

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
		fr_assert(request->reply->code != 0);
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

			return unlang_module_yield_to_section(p_result, request,
							      cs, state->rcode, state->send,
							      NULL, rctx);
		}

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
			       fr_table_str_by_value(rcode_table, rcode, "???"));
		}
		request->reply->code = PROCESS_CODE_DO_NOT_RESPOND;
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
		return UNLANG_ACTION_CALCULATE_RESULT;
	}
#endif

	return UNLANG_ACTION_CALCULATE_RESULT;
}

#endif	/* defined(PROCESS_INST) && defined(PROCESS_PACKET_TYPE) && defined(PROCESS_PACKET_CODE_VALID) */

#ifdef __cplusplus
}
#endif
