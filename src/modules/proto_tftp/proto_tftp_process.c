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
 * @file proto_tftp/proto_tftp_process.c
 * @brief TFTP requests handler.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/tftp/tftp.h>
#include <freeradius-devel/protocol/tftp/rfc1350.h>

#include "proto_tftp.h"

#include <libgen.h>   /* basename() */
#include <sys/stat.h> /* stat() */

/**
 *	That FIXUP is a temporary _ugly_ fix until we decide and fix the master.c adding
 *	the capability to be smart enough allowing single instances of proto_foo_bar.
 *
 *	In that case here, it is necessary to allow the "recv Read-Request {}" share the
 *	same context with "recv Data{}" allowing us to have the "rbtree_t *session_tree"
 *	being shared among them.
 *
 *	It was discussed with Alan a while ago and he knows how we should do that. but, for
 *	now it will be on hold.
 */
#define FIXUP

typedef struct {
	rbtree_t		*this;		//!< Pointer to wher is being linked.

	fr_ipaddr_t		src_ipaddr;	//!< Client ipaddr
	uint16_t 		src_port;	//!< Client port

	FILE 			*fp;		//!< Requested file in disk
	uint8_t			*block_data;	//!< Buffer with chunk of requested file
	uint16_t		block_size;	//!< Block size of requested file
	char			*filename;	//!< Requested file name
	size_t 			file_len;	//!< Requested file length
} tftp_state_t;

typedef struct {
#if !defined(FIXUP)
	rbtree_t	*session_tree;
#endif
	CONF_SECTION	*recv_read_request;
	void		*unlang_read_request;
	CONF_SECTION	*recv_acknowledgement;
	void		*unlang_acknowledgement;
	CONF_SECTION	*send_data;
	void		*unlang_data;
	CONF_SECTION	*send_error;
	void		*unlang_error;
} proto_tftp_process_t;

static fr_dict_t const *dict_tftp;

extern fr_dict_autoload_t proto_tftp_process_dict[];
fr_dict_autoload_t proto_tftp_process_dict[] = {
	{ .out = &dict_tftp, .proto = "tftp" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_tftp_opcode;
static fr_dict_attr_t const *attr_tftp_block;
static fr_dict_attr_t const *attr_tftp_block_size;
static fr_dict_attr_t const *attr_tftp_data;
static fr_dict_attr_t const *attr_tftp_error_code;
static fr_dict_attr_t const *attr_tftp_error_message;
static fr_dict_attr_t const *attr_tftp_filename;
static fr_dict_attr_t const *attr_tftp_opcode;
static fr_dict_attr_t const *attr_tftp_mode;

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t proto_tftp_process_dict_attr[];
fr_dict_attr_autoload_t proto_tftp_process_dict_attr[] = {
	{ .out = &attr_tftp_block, .name = "TFTP-Block", .type = FR_TYPE_UINT16, .dict = &dict_tftp },
	{ .out = &attr_tftp_block_size, .name = "TFTP-Block-Size", .type = FR_TYPE_UINT16, .dict = &dict_tftp },
	{ .out = &attr_tftp_data, .name = "TFTP-Data", .type = FR_TYPE_OCTETS, .dict = &dict_tftp },
	{ .out = &attr_tftp_error_code, .name = "TFTP-Error-Code", .type = FR_TYPE_UINT16, .dict = &dict_tftp },
	{ .out = &attr_tftp_error_message, .name = "TFTP-Error-Message", .type = FR_TYPE_STRING, .dict = &dict_tftp },
	{ .out = &attr_tftp_filename, .name = "TFTP-Filename", .type = FR_TYPE_STRING, .dict = &dict_tftp },
	{ .out = &attr_tftp_opcode, .name = "TFTP-Opcode", .type = FR_TYPE_UINT16, .dict = &dict_tftp },
	{ .out = &attr_tftp_mode, .name = "TFTP-Mode", .type = FR_TYPE_UINT8, .dict = &dict_tftp },

	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_tftp },

	{ NULL }
};

#if defined(FIXUP)
/*
 * TODO: It should be removed as soon as fix the master.c
 * about the current approach calling dl_module_instance()
 * multiple times for each "WhateveType {}" config entry type.
 */
static rbtree_t	*global_session_tree = NULL;
#endif

/*
 *	Session API needed to keep the received file over "Read-Request" indexing by (src_port + src_host)
 *	and restored to use with "Acknowledgement" packet.
 */

static int fr_tftp_state_cmp(const void *one, const void *two)
{
	const tftp_state_t *a = one, *b = two;
	int rcode;

	/*
	 *	1st. check the port, only two bytes...
	 */
	rcode = (a->src_port < b->src_port) - (a->src_port > b->src_port);
	if (rcode != 0) return rcode;

	/*
	 * 	Now, check if match the src_ipaddr.
	 */
	return memcmp(&a->src_ipaddr, &b->src_ipaddr, sizeof(a->src_ipaddr));
}

static int _fr_tftp_state_destroy(tftp_state_t *ctx)
{
	tftp_state_t *session = talloc_get_type_abort(ctx, tftp_state_t);

	fr_assert(session != NULL);
	fr_assert(session->this != NULL);

	DEBUG2("Destroy session for %pV:%d", fr_box_ipaddr(session->src_ipaddr), session->src_port);

	rbtree_deletebydata(session->this, session);

	if (session->fp != NULL) fclose(session->fp);

	talloc_free(session->filename);
	talloc_free(session);

	return 0;
}

static tftp_state_t *fr_ftp_state_lookup(UNUSED proto_tftp_process_t *inst, request_t *request)
{
	tftp_state_t *session, my_session = {
		.src_port = request->packet->socket.inet.src_port
	};

#if !defined(FIXUP)
	fr_assert(inst->session_tree != NULL);
#endif

	memcpy(&my_session.src_ipaddr, &request->packet->socket.inet.src_ipaddr, sizeof(request->packet->socket.inet.src_ipaddr));

#if !defined(FIXUP)
	session = rbtree_finddata(inst->session_tree, &my_session);
#else
	session = rbtree_finddata(global_session_tree, &my_session);
#endif

	if (!session) {
		RDEBUG2("Session not found for %pV:%d", fr_box_ipaddr(request->packet->socket.inet.src_ipaddr), my_session.src_port);
	} else {
		RDEBUG2("Found session session for %pV:%d with %s filename.", fr_box_ipaddr(request->packet->socket.inet.src_ipaddr),
				my_session.src_port, session->filename);
	}

	return session;
}

static tftp_state_t *fr_ftp_state_new(UNUSED proto_tftp_process_t *inst, request_t *request, char const *ftp_dir, char const *filename, uint16_t block_size, bool is_ascii)
{
	tftp_state_t *session;
	struct stat stat_buff;
	char *fullpath, *our_filename;
	char buff[PATH_MAX];

#if !defined(FIXUP)
	fr_assert(inst->session_tree != NULL);
#endif
	fr_assert(block_size >= FR_TFTP_BLOCK_MIN_SIZE && /* As described in https://tools.ietf.org/html/rfc2348 */
			  block_size <= FR_TFTP_BLOCK_MAX_SIZE);

	RDEBUG2("Create session for %pV:%d with %s filename (blocks of #%d)",
			fr_box_ipaddr(request->packet->socket.inet.src_ipaddr), request->packet->socket.inet.src_port, filename, block_size);

	/*
	 *	As we are using the 'packet_ctx' context. the _fr_tftp_state_destroy() destructor will be called
	 *	during the next proto cleanup managed by network API. then, it will be the momment to release
	 *	such 'session' (close the file, relase memory and remove the rbtree entry)
	 */
	session = talloc_zero(request->async->packet_ctx, tftp_state_t);
	if (!session) return NULL;

	talloc_set_name(session, "tftp_state_t");

	/* Ensure that file don't have any injection like '../../../path' */
	our_filename = basename_r(filename, buff);
	fullpath = talloc_typed_asprintf(session, "%s/%s", ftp_dir, our_filename);

	/* ... and if exists ... */
	if ((stat(fullpath, &stat_buff) != 0)) {
		REDEBUG("Such file '%s' not found.", fullpath);
		goto error;
	}

	/* ... and if is a regular file */
	if (!S_ISREG(stat_buff.st_mode)) {
		REDEBUG("Such file %s is not a regular file.", fullpath);
		goto error;
	}

	/*
	 *	Great! Let's track the 'Read-Request' filename/blocksize/mode by the client src_port/src_ipaddr.
	 */
	memcpy(&session->src_ipaddr, &request->packet->socket.inet.src_ipaddr, sizeof(request->packet->socket.inet.src_ipaddr));
	session->src_port   = request->packet->socket.inet.src_port;
	session->block_data = talloc_array(session, uint8_t, block_size);	/* The buffer is allocated once and always reused for each block read */
	session->block_size = block_size;
	session->filename   = talloc_strdup(session, our_filename);
	session->file_len   = stat_buff.st_size;

	session->fp = fopen(fullpath, is_ascii ? "r" : "rb");
	if (!session->fp) {
		REDEBUG("Failed to open %s", our_filename);
	error:
		if (session->fp) fclose(session->fp);
		talloc_free(session);
		return NULL;
	}

#if !defined(FIXUP)
	if (!rbtree_insert(inst->session_tree, session)) {
#else
	if (!rbtree_insert(global_session_tree, session)) {
#endif
		REDEBUG("Failed to create new session for src_port=%d with filename=%s", request->packet->socket.inet.src_port, our_filename);
		goto error;
	}

#if !defined(FIXUP)
	session->this = inst->session_tree;
#else
	session->this = global_session_tree;
#endif
	talloc_set_destructor(session, _fr_tftp_state_destroy);

	return session;
}

static bool fr_tftp_read_block(request_t *request, tftp_state_t *session, uint16_t block_num)
{
	size_t file_pos, block_chunk;
	ssize_t buffered = 0;
	fr_pair_t 	*vp;

	fr_assert(session != NULL);
	fr_assert(session->fp != NULL);
	fr_assert(session->block_size >= FR_TFTP_BLOCK_MIN_SIZE && /* As described in https://tools.ietf.org/html/rfc2348 */
			  session->block_size <= FR_TFTP_BLOCK_MAX_SIZE);

	block_chunk = (session->block_size * block_num);
	file_pos = (block_num > 1) ? block_chunk : 0;

	if (file_pos > 0) {
		file_pos -= session->block_size;
		fseek(session->fp, file_pos, SEEK_SET);
	}

	if (file_pos >= session->file_len) {
		file_pos = 0; /* truncated, nothing to read */
	} else {
		if ((buffered = fread(session->block_data, 1, session->block_size, session->fp)) < 0) {
			REDEBUG("proto_tftp: Problems with read()");
			return false;
		}
	}

	RDEBUG("Read block #%d (%zd of %zu) from (%s)", block_num, file_pos, session->file_len, session->filename);

	/*
	 *	Then, build the 'Data' reply packet.
	 */
	MEM(pair_update_reply(&vp, attr_tftp_data) >= 0);
	fr_pair_value_memdup(vp, (const uint8_t *)session->block_data, buffered, true);	// @todo: Change to steall() instead of replicate

	MEM(pair_update_reply(&vp, attr_tftp_block) >= 0);
	vp->vp_uint16 = block_num;

	MEM(pair_update_reply(&vp, attr_tftp_opcode) >= 0);
	vp->vp_uint16 = FR_PACKET_TYPE_VALUE_DATA;

	return true;
}

#define tftp_reply_error(msg) _tftp_reply_error(request, FR_TFTP_ERROR_CODE_VALUE_ILLEGAL_TFTP_OPERATION, msg)
#define tftp_reply_error_notfound(msg) _tftp_reply_error(request, FR_TFTP_ERROR_CODE_VALUE_FILE_NOT_FOUND, msg)

static void _tftp_reply_error(request_t *request, int error_code, char const *msg)
{
	fr_pair_t	*vp;

	WARN("%s", msg);

	request->reply->code = FR_PACKET_TYPE_VALUE_ERROR;

	/*
	 *	Then, build the 'Error' reply packet.
	 */
	MEM(pair_update_reply(&vp, attr_tftp_opcode) >= 0);
	vp->vp_uint16 = FR_PACKET_TYPE_VALUE_ERROR;

	/*
	 *	Set the server reply message.
	 */
	if (!fr_pair_find_by_da(&request->reply->vps, attr_tftp_error_message)) {
		MEM(pair_update_reply(&vp, attr_tftp_error_message) >= 0);
		fr_pair_value_strdup(vp, msg);
	}

	/*
	 *	Set the code error.
	 */
	MEM(pair_update_reply(&vp, attr_tftp_error_code) >= 0);
	vp->vp_uint16 = error_code;
}

static rlm_rcode_t mod_process(module_ctx_t const *mctx, request_t *request)
{
	proto_tftp_process_t *inst = talloc_get_type_abort(mctx->instance, proto_tftp_process_t);
	proto_tftp_t 		*parent_inst = talloc_get_type_abort(request->async->listen->app_instance, proto_tftp_t);
	rlm_rcode_t		rcode;
	CONF_SECTION		*unlang;
	fr_dict_enum_t const	*dv;
	fr_pair_t 		*vp;
	uint16_t 		opcode;
	tftp_state_t 		*session;
	char const 		*tftp_dir = parent_inst->directory;

	fr_assert(tftp_dir != NULL);

	REQUEST_VERIFY(request);

	switch (request->request_state) {
	case REQUEST_INIT:
		RDEBUG("Received %s ID %08x", fr_tftp_codes[request->packet->code], request->packet->id);
		log_request_proto_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");

		request->component = "tftp";

		dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->packet->code));
		if (!dv) {
			REDEBUG("Failed to find value for &request:Packet-Type");
			return RLM_MODULE_FAIL;
		}

		unlang = cf_section_find(request->server_cs, "recv", dv->name);
		if (!unlang) {
			RWDEBUG("Failed to find 'recv %s' section", dv->name);
			request->reply->code = FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND;
			goto send_reply;
		}

		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		if (unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME) < 0) return RLM_MODULE_FAIL;

		request->request_state = REQUEST_RECV;
		FALL_THROUGH;

	case REQUEST_RECV:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

		fr_assert(request->log.unlang_indent == 0);

		switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			break;

		case RLM_MODULE_HANDLED:
			goto send_reply;
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_DISALLOW:
		default:
			tftp_reply_error("Failed to process the request");
			goto send_reply;
		}

		/*
		 *	@todo: As we don't have yet a API to handle files over the Network.
		 *	all the file reply will be handled here.
		 */
		vp = fr_pair_find_by_da(&request->packet->vps, attr_tftp_opcode);
		if (!vp) {
			tftp_reply_error("Missing TFTP-Opcode");
			goto send_reply;
		}

		opcode = vp->vp_uint16;
		switch (opcode) {
			case FR_PACKET_TYPE_VALUE_READ_REQUEST:
			{
				const char *filename;
				bool is_ascii;
				uint16_t blksize = parent_inst->default_blksize;

				/*
				 *	Keep the state of Filename.
				 */
				vp = fr_pair_find_by_da(&request->packet->vps, attr_tftp_mode);
				if (!vp) {
					tftp_reply_error("Missing TFTP-Mode");
					goto send_reply;
				}
				is_ascii = (vp->vp_uint8 == FR_TFTP_MODE_VALUE_ASCII);

				vp = fr_pair_find_by_da(&request->packet->vps, attr_tftp_filename);
				if (!vp) {
					tftp_reply_error("Missing TFTP-Filename");
					goto send_reply;
				}
				filename = vp->vp_strvalue;

				vp = fr_pair_find_by_da(&request->packet->vps, attr_tftp_block_size);
				if (vp) {
					blksize = vp->vp_uint16;
				}

				/*
				 *	The master i/o can handler packets only <= 8k
				 */
				if (blksize > FR_TFTP_BLOCK_MAX_SIZE) {
					tftp_reply_error("Invalid blksize");
					goto send_reply;
				}

				/*
				 *	Don't call talloc_free() or anything for 'session' instance.
				 *	It will be freed by the proto clean up timers.
				 */
				session = fr_ftp_state_new(inst, request, tftp_dir, filename, blksize, is_ascii);
				if (!session) {
					tftp_reply_error("File not Found or Access Denied");
					goto send_reply;
				}

				/*
				 *	As we got a valid 'Read-Request', then reply the #1 data block.
				 */
				if (!fr_tftp_read_block(request, session, 1)) {
				err_io:
					tftp_reply_error("I/O Error");
				} else {
					/*
					 *	If we are here, so we have a valid Read-Request. therefore
					 *	we should save the session with the filename/fd and reuse
					 *	that over the 'Acknowledgement' request.
					 */

					request->reply->code = FR_PACKET_TYPE_VALUE_DATA;
				}

				goto send_reply;
			}
			break;

			case FR_PACKET_TYPE_VALUE_ACKNOWLEDGEMENT:
			{
				uint16_t block_num;

				session = fr_ftp_state_lookup(inst, request);
				if (!session) {
					tftp_reply_error_notfound("Session Notfound");
					goto send_reply;
				}

				vp = fr_pair_find_by_da(&request->packet->vps, attr_tftp_block);
				if (!vp) {
					tftp_reply_error("Missing TFTP-Block");
					goto send_reply;
				}

				block_num = (vp->vp_uint16 + 1);

				if (!fr_tftp_read_block(request, session, block_num)) goto err_io;

				request->reply->code = FR_PACKET_TYPE_VALUE_DATA;

				goto send_reply;
			}
			break;
		}

		dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
		unlang = NULL;
		if (dv) unlang = cf_section_find(request->server_cs, "send", dv->name);

		if (!unlang) goto send_reply;

	rerun_nak:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		if (unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME) < 0) return RLM_MODULE_FAIL;

		request->request_state = REQUEST_SEND;
		FALL_THROUGH;

	case REQUEST_SEND:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

		fr_assert(request->log.unlang_indent == 0);

		switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
		case RLM_MODULE_HANDLED:
			/* reply is already set */
			break;

		default:
			/*
			 *	If we over-ride an ACK with a NAK, run
			 *	the NAK section.
			 */
			if (request->reply->code != FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND) {
				dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
				RWDEBUG("Failed running 'send %s', trying 'send Do-Not-Respond'.", dv->name);

				request->reply->code = FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND;

				dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
				unlang = NULL;
				if (!dv) goto send_reply;

				unlang = cf_section_find(request->server_cs, "send", dv->name);
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'send %s' section as it does not exist", dv->name);
			}
			break;
		}

		request->reply->timestamp = fr_time();

	send_reply:
		/*
		 *	Check for "do not respond".
		 */
		if (request->reply->code == FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND) {
			RDEBUG("Not sending reply to client.");
			return RLM_MODULE_HANDLED;
		}

		if (RDEBUG_ENABLED) common_packet_debug(request, request->reply, false);
		break;

	default:
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

static int mod_instantiate(UNUSED void *instance, UNUSED CONF_SECTION *process_app_cs)
{
#if !defined(FIXUP)
	proto_tftp_process_t	*inst = talloc_get_type_abort(instance, proto_tftp_process_t);
	
	if (!inst->session_tree) {
		inst->session_tree = rbtree_talloc_alloc(NULL, fr_tftp_state_cmp, tftp_state_t, NULL, 0);
		printf("### jorge1: %s Creating inst->session_tree=%#x\n", __func__, (int)inst->session_tree);
	} else {
		printf("### jorge1: %s is created inst->session_tree=%#x\n", __func__, (int)inst->session_tree);
	}

#else
	// @todo: hack until the master.c be fixed to start single instance.
	if (!global_session_tree) {
		/*
		 *	All the entries will be released properly by the _fr_tftp_state_destroy() configured
		 *	as a destructor by fr_ftp_state_new().
		 */
		global_session_tree = rbtree_talloc_alloc(NULL, fr_tftp_state_cmp, tftp_state_t, NULL, 0);
	}

	fr_assert(global_session_tree != NULL);
#endif

	return 0;
}

static int mod_detach(UNUSED void *instance)
{
#if !defined(FIXUP)
	proto_tftp_process_t	*inst = talloc_get_type_abort(instance, proto_tftp_process_t);

	TALLOC_FREE(inst->session_tree);
#else
	// @todo: hack until the master.c be fixed to start single instance.
	TALLOC_FREE(global_session_tree);
#endif
	return 0;
}

static const virtual_server_compile_t compile_list[] = {
	{
		.name = "recv",
		.name2 = "Read-Request",
		.component = MOD_AUTHORIZE,
	},
	{
		.name = "recv",
		.name2 = "Acknowledgement",
		.component = MOD_AUTHORIZE,
	},
	{
		.name = "send",
		.name2 = "Data",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Error",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
	},

	COMPILE_TERMINATOR
};

extern fr_app_worker_t proto_tftp_process;
fr_app_worker_t proto_tftp_process = {
	.magic		= RLM_MODULE_INIT,
	.name		= "tftp_process",
	.detach		= mod_detach,

	.instantiate	= mod_instantiate,
	.entry_point	= mod_process,
	.compile_list	= compile_list,
};
