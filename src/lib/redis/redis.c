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
 * @file redis.c
 * @brief Common functions for interacting with Redis via hiredis
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000,2006,2015 The FreeRADIUS server project
 * @copyright 2011 TekSavvy Solutions (gabe@teksavvy.com)
 */
#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/util/debug.h>

fr_table_num_sorted_t const redis_reply_types[] = {
	{ "array",	REDIS_REPLY_ARRAY	},
	{ "error",	REDIS_REPLY_ERROR	},
	{ "integer",	REDIS_REPLY_INTEGER	},
	{ "nil",	REDIS_REPLY_NIL		},
	{ "status",	REDIS_REPLY_STATUS	},
	{ "string",	REDIS_REPLY_STRING	}
};
size_t redis_reply_types_len = NUM_ELEMENTS(redis_reply_types);

fr_table_num_sorted_t const redis_rcodes[] = {
	{ "ask",	REDIS_RCODE_ASK		},
	{ "error",	REDIS_RCODE_ERROR	},
	{ "move",	REDIS_RCODE_MOVE	},
	{ "reconnect",	REDIS_RCODE_RECONNECT	},
	{ "success",	REDIS_RCODE_SUCCESS	},
	{ "try again",	REDIS_RCODE_TRY_AGAIN	}
};
size_t redis_rcodes_len = NUM_ELEMENTS(redis_rcodes);

/** Print the version of libhiredis the server was built against
 *
 */
void fr_redis_version_print(void)
{
	INFO("libfreeradius-redis: libhiredis version: %i.%i.%i", HIREDIS_MAJOR, HIREDIS_MINOR, HIREDIS_PATCH);
}

/** Check the reply for errors
 *
 * @param conn used to issue the command.
 * @param reply to process.
 * @return
 *	- REDIS_RCODE_TRY_AGAIN - If the operation should be retries.
 *	- REDIS_RCODE_MOVED  	- If the key has been permanently moved.
 *	- REDIS_RCODE_ASK	- If the key has been temporarily moved.
 *	- REDIS_RCODE_SUCCESS   - if no errors.
 *	- REDIS_RCODE_ERROR     - on command/server error.
 *	- REDIS_RCODE_NO_SCRIPT - script specified by evalsha doesn't exist.
 *	- REDIS_RCODE_RECONNECT - on connection error (probably needs reconnecting).
 */
fr_redis_rcode_t fr_redis_command_status(fr_redis_conn_t *conn, redisReply *reply)
{
	size_t i = 0;

	if (!reply) switch (conn->handle->err) {
	case REDIS_OK:
		break;

	case REDIS_ERR_IO:
	case REDIS_ERR_EOF:
	case REDIS_ERR_OTHER:
		fr_strerror_printf("Connection error: %s", conn->handle->errstr);
		return REDIS_RCODE_RECONNECT;

	default:
	case REDIS_ERR_PROTOCOL:
		fr_strerror_printf("Command error: %s", conn->handle->errstr);
		return REDIS_RCODE_ERROR;
	}

	if (reply) switch (reply->type) {
	case REDIS_REPLY_STATUS:
		return REDIS_RCODE_SUCCESS;

	case REDIS_REPLY_ERROR:
		fr_strerror_printf("Server error: %s", reply->str);
		if (strncmp(REDIS_ERROR_MOVED_STR, reply->str, sizeof(REDIS_ERROR_MOVED_STR) - 1) == 0) {
			return REDIS_RCODE_MOVE;
		}
		if (strncmp(REDIS_ERROR_ASK_STR, reply->str, sizeof(REDIS_ERROR_ASK_STR) - 1) == 0) {
			return REDIS_RCODE_ASK;
		}
		if (strncmp(REDIS_ERROR_TRY_AGAIN_STR, reply->str, sizeof(REDIS_ERROR_TRY_AGAIN_STR) - 1) == 0) {
			return REDIS_RCODE_TRY_AGAIN;
		}
		if (strncmp(REDIS_ERROR_NO_SCRIPT_STR, reply->str, sizeof(REDIS_ERROR_NO_SCRIPT_STR) - 1) == 0) {
			return REDIS_RCODE_NO_SCRIPT;
		}
		return REDIS_RCODE_ERROR;

	/*
	 *	Recurse to check for nested errors
	 */
	case REDIS_REPLY_ARRAY:
		for (i = 0; i < reply->elements; i++) {
			int ret;

			ret = fr_redis_command_status(conn, reply->element[i]);
			if (ret < 0) return ret;
		}
		break;

	default:
		break;
	}
	return REDIS_RCODE_SUCCESS;
}

/** Print the response data in a useful treelike form
 *
 * @param lvl to print data at.
 * @param reply to print.
 * @param request The current request.
 * @param idx Response number.
 */
void fr_redis_reply_print(fr_log_lvl_t lvl, redisReply *reply, REQUEST *request, int idx)
{
	size_t i = 0;

	if (!reply) return;

	switch (reply->type) {
	case REDIS_REPLY_ERROR:
		REDEBUG("(%i) error   : %s", idx, reply->str);
		break;

	case REDIS_REPLY_STATUS:
		RDEBUGX(lvl, "(%i) status  : %s", idx, reply->str);
		break;

	case REDIS_REPLY_STRING:
		RDEBUGX(lvl, "(%i) string  : %s", idx, reply->str);
		break;

	case REDIS_REPLY_INTEGER:
		RDEBUGX(lvl, "(%i) integer : %lld", idx, reply->integer);
		break;

	case REDIS_REPLY_NIL:
		RDEBUGX(lvl, "(%i) nil", idx);
		break;

	case REDIS_REPLY_ARRAY:
		RDEBUGX(lvl, "(%i) array[%zu]", idx, reply->elements);
		for (i = 0; i < reply->elements; i++) {
			RINDENT();
			fr_redis_reply_print(lvl, reply->element[i], request, i);
			REXDENT();
		}
		break;
	}
}

/** Convert a string or integer type to #fr_value_box_t of specified type
 *
 * Will work with REDIS_REPLY_STRING (which is converted to #FR_TYPE_STRING
 * then cast to dst_type), or REDIS_REPLY_INTEGER (which is converted to
 * #FR_TYPE_UINT64, then cast to dst_type).
 *
 * @note Any unsupported types will trigger an assert. You must check the
 *	reply type prior to calling this function.
 *
 * @param[in,out] ctx to allocate any buffers in.
 * @param[out] out Where to write the cast type.
 * @param[in] reply to process.
 * @param[in] dst_type to convert to.
 * @param[in] dst_enumv Used to convert string types to integers for attributes
 *	with enumerated values.
 * @return
 *	- 1 if we received a NIL reply. Out will remain uninitialized.
 *	- 0 on success.
 *	- -1 on cast or parse failure.
 */
int fr_redis_reply_to_value_box(TALLOC_CTX *ctx, fr_value_box_t *out, redisReply *reply,
				 fr_type_t dst_type, fr_dict_attr_t const *dst_enumv)
{
	fr_value_box_t	in;

	memset(&in, 0, sizeof(in));

	switch (reply->type) {
	case REDIS_REPLY_NIL:
		return 1;

	/*
	 *	Try and convert the integer to the smallest
	 *	and simplest type possible, to give the cast
	 *	the greatest chance of success.
	 */
	case REDIS_REPLY_INTEGER:
		if (reply->integer < INT32_MIN) {	/* 64bit signed (not supported)*/
			fr_strerror_printf("Signed 64bit integers are not supported");
			return -1;
		}
		if (reply->integer < 0) {		/* 32bit signed (supported) */
			in.type = FR_TYPE_INT32;
			in.vb_int32 = (int32_t) reply->integer;
		}
		else if (reply->integer > UINT32_MAX) {	/* 64bit unsigned (supported) */
			in.type = FR_TYPE_UINT64;
			in.vb_uint64 = (uint64_t) reply->integer;
		}
		else if (reply->integer > UINT16_MAX) {	/* 32bit unsigned (supported) */
			in.type = FR_TYPE_UINT32;
			in.vb_uint32 = (uint32_t) reply->integer;
		}
		else if (reply->integer > UINT8_MAX) {	/* 16bit unsigned (supported) */
			in.type = FR_TYPE_UINT16;
			in.vb_uint16 = (uint16_t) reply->integer;
		}
		else {		/* 8bit unsigned (supported) */
			in.type = FR_TYPE_UINT8;
			in.vb_uint8 = (uint8_t) reply->integer;
		}
		break;

	case REDIS_REPLY_STRING:
	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_ERROR:
		in.type = FR_TYPE_STRING;
		in.datum.ptr = reply->str;
		in.datum.length = reply->len;
		break;

	case REDIS_REPLY_ARRAY:
		fr_assert(0);
	}

	if (fr_value_box_cast(ctx, out, dst_type, dst_enumv, &in) < 0) return -1;

	return 0;
}

/** Convert a pair of redis reply objects to a map
 *
 * The maps can then be applied using #map_to_request.
 *
 * @param[in,out] ctx to allocate maps in.
 * @param[out] out Where to write the head of the new maps list.
 * @param[in] request The current request.
 * @param[in] key to process.
 * @param[in] op to process.
 * @param[in] value to process.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_redis_reply_to_map(TALLOC_CTX *ctx, vp_map_t **out, REQUEST *request,
			  redisReply *key, redisReply *op, redisReply *value)
{
	vp_map_t	*map = NULL;
	ssize_t		slen;

	*out = NULL;

	if (key->type != REDIS_REPLY_STRING) {
		REDEBUG("Bad key type, expected string, got %s",
			fr_table_str_by_value(redis_reply_types, key->type, "<UNKNOWN>"));
	error:
		TALLOC_FREE(map);
		return -1;
	}

	if (op->type != REDIS_REPLY_STRING) {
		REDEBUG("Bad key type, expected string, got %s",
			fr_table_str_by_value(redis_reply_types, op->type, "<UNKNOWN>"));
		goto error;
	}

	RDEBUG3("Got key   : %s", key->str);
	RDEBUG3("Got op    : %s", op->str);
	RDEBUG3("Got value : %pV", fr_box_strvalue_len(value->str, value->len));

	map = talloc_zero(ctx, vp_map_t);
	slen = tmpl_afrom_attr_str(map, NULL, &map->lhs, key->str, &(vp_tmpl_rules_t){ .dict_def = request->dict });
	if (slen < 0) {
		REMARKER(key->str, -slen, "%s", fr_strerror());
		goto error;
	}

	map->op = fr_table_value_by_str(fr_tokens_table, op->str, T_INVALID);
	if (map->op == T_INVALID) {
		REDEBUG("Invalid operator \"%s\"", op->str);
		goto error;
	}

	switch (value->type) {
	case REDIS_REPLY_STRING:
	case REDIS_REPLY_INTEGER:
	{
		fr_value_box_t vpt;

		/* Logs own errors */
		if (fr_redis_reply_to_value_box(map, &vpt, value,
						 tmpl_da(map->lhs)->type, tmpl_da(map->lhs)) < 0) {
			RPEDEBUG("Failed converting Redis data");
			goto error;
		}

		/* This will only fail only memory allocation errors */
		if (tmpl_afrom_value_box(map, &map->rhs, &vpt, true) < 0) goto error;
	}
		break;

	default:
		REDEBUG("Bad value type, expected string or integer, got %s",
			fr_table_str_by_value(redis_reply_types, value->type, "<UNKNOWN>"));
		goto error;

	}
	MAP_VERIFY(map);

	*out = map;

	return 0;
}

/** Add a single map pair to an existing command string as three elements
 *
 * - Integer types will be encoded as integers.
 * - Strings and octets will be encoded in their raw form.
 * - Other types will be converted to their printable form and will be encoded as strings.
 *
 * @note lhs must be a #TMPL_TYPE_ATTR.
 * @note rhs must be a #TMPL_TYPE_DATA.
 *
 * @param pool to allocate any buffers in.
 * @param out Where to write pointers to the member of the tuple. Unused elements should be
 *	a multiple of three, and it should have at least three unused elements.
 * @param out_len Where to write the size of the data pointed to by the equivalent index
 *	in the out array.
 * @param map to convert.
 * @return
 *	0 on success.
 *	-1 on failure.
 */
int fr_redis_tuple_from_map(TALLOC_CTX *pool, char const *out[], size_t out_len[], vp_map_t *map)
{
	char		*new;

	char		key_buf[256];
	char		*key;
	size_t		key_len;
	size_t		need;

	fr_assert(tmpl_is_attr(map->lhs));
	fr_assert(tmpl_is_data(map->rhs));

	key_len = tmpl_snprint(&need, key_buf, sizeof(key_buf), map->lhs);
	if (need) {
		fr_strerror_printf("Key too long.  Must be < " STRINGIFY(sizeof(key_buf)) " "
				   "bytes, got %zu bytes", key_len);
		return -1;
	}
	key = talloc_bstrndup(pool, key_buf, key_len);
	if (!key) return -1;

	switch (tmpl_value_type(map->rhs)) {
	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		out[2] = tmpl_value(map->rhs)->datum.ptr;
		out_len[2] = tmpl_value_length(map->rhs);
		break;

	/*
	 *	For everything else we get the string representation
	 */
	default:
		new = fr_value_box_asprint(pool, tmpl_value(map->rhs), '\0');
		if (!new) {
			talloc_free(key);
			return -1;
		}
		out[2] = new;
		out_len[2] = talloc_array_length(new) - 1;
		break;
	}

	out[0] = key;
	out_len[0] = key_len;
	out[1] = fr_table_str_by_value(fr_tokens_table, map->op, NULL);
	out_len[1] = strlen(out[1]);

	return 0;
}

/** Simplifies handling of pipelined commands with Redis cluster
 *
 * Retrieve all available pipelined responses, and write them to the array.
 *
 * On encountering an error, all previously retrieved responses are freed, and the reply
 * containing the error is written to the first element of out. All responses after the
 * error are also freed.
 *
 * If the number of responses != pipelined, that's also an error, a very serious one,
 * in libhiredis or Redis.  We can't really do much here apart from error out.
 *
 * @param[out] pipelined	Number of pipelined commands we sent to the server.
 * @param[out] rcode		Status of the first errored response, or REDIS_RCODE_SUCCESS
 *				if all responses were processed.
 * @param[out] out		Where to write the replies from pipelined commands.
 *				Will contain exactly 1 element on error WHICH MUST BE FREED,
 *				else the number passed in pipelined.
 * @param[in] out_len		number of elements in out.
 * @param[in] conn		the pipelined commands were issued on.
 * @return
 *	- #REDIS_RCODE_SUCCESS on success.
 *	- #REDIS_RCODE_ERROR on command/response mismatch or command error.
 *	- REDIS_RCODE_* on other errors;
 */
fr_redis_rcode_t fr_redis_pipeline_result(unsigned int *pipelined, fr_redis_rcode_t *rcode,
					  redisReply *out[], size_t out_len,
					  fr_redis_conn_t *conn)
{
	size_t			i;
	redisReply		**out_p = out;
	fr_redis_rcode_t	status = REDIS_RCODE_SUCCESS;
	redisReply		*reply = NULL;

	fr_assert(out_len >= (size_t)*pipelined);

	fr_strerror();	/* Clear any outstanding errors */

	if ((size_t) *pipelined > out_len) {
		for (i = 0; i < (size_t)*pipelined; i++) {
			if (redisGetReply(conn->handle, (void **)&reply) != REDIS_OK) break;
			fr_redis_reply_free(&reply);
		}

		*pipelined = 0;			/* all outstanding responses should be cleared */

		fr_strerror_printf("Too many pipelined commands");
		out[0] = NULL;
		return REDIS_RCODE_ERROR;
	}

	for (i = 0; i < (size_t)*pipelined; i++) {
		bool maybe_more = false;

		/*
		 *	we don't need to check the return code here,
		 *	as it's also stored in the conn->handle.
		 */
		reply = NULL;	/* redisGetReply doesn't NULLify reply on error *sigh* */
		if (redisGetReply(conn->handle, (void **)&reply) == REDIS_OK) maybe_more = true;
		status = fr_redis_command_status(conn, reply);
		*out_p++ = reply;

		/*
		 *	Bail out of processing responses,
		 *	free the remaining ones (leaving this one intact)
		 *	pass control back to the cluster code.
		 */
		if (maybe_more && (status != REDIS_RCODE_SUCCESS)) {
			size_t j;
		error:
			/*
			 *	Append the hiredis error
			 */
			if (conn->handle->errstr[0]) fr_strerror_printf_push("%s", conn->handle->errstr);

			/*
			 *	Free everything that came before the bad reply
			 */
			for (j = 0; j < i; j++) {
				fr_redis_reply_free(&out[j]);
				out[j] = NULL;
			}

			/*
			 *	...and drain the rest of the pipelined responses
			 */
			for (j = i + 1; j < (size_t)*pipelined; j++) {
				redisReply *to_clear;

				if (redisGetReply(conn->handle, (void **)&to_clear) != REDIS_OK) break;
				fr_redis_reply_free(&to_clear);
			}

			out[0] = reply;

			*rcode = status;
			*pipelined = 0;		 /* all outstanding responses should be cleared */

			return reply ? 1 : 0;
		}
	}

	if (i != (size_t)*pipelined) {
		fr_strerror_printf("Expected %u responses, got %zu", *pipelined, i);
		status = REDIS_RCODE_ERROR;
		goto error;
	}

	*rcode = status;

	*pipelined = 0;				/* all outstanding responses should be cleared */

	return i;
}

/** Get the version of Redis running on the remote server
 *
 * This can be useful for some modules, as it allows adaptive behaviour, or early termination.
 *
 * @param[out] out Where to write the version string.
 * @param[in] out_len Length of the version string buffer.
 * @param[in] conn Used to query the version string.
 * @return
 *	- #REDIS_RCODE_SUCCESS on success.
 *	- #REDIS_RCODE_ERROR on command/response mismatch or command error.
 *	- REDIS_RCODE_* on other errors;
 */
fr_redis_rcode_t fr_redis_get_version(char *out, size_t out_len, fr_redis_conn_t *conn)
{
	redisReply		*reply;
	fr_redis_rcode_t	status;
	char			*p, *q;

	fr_assert(out_len > 0);
	out[0] = '\0';

	reply = redisCommand(conn->handle, "INFO SERVER");
	status = fr_redis_command_status(conn, reply);
	if (status != REDIS_RCODE_SUCCESS) return status;

	if (reply->type != REDIS_REPLY_STRING) {
		fr_strerror_printf("Bad value type, expected string or integer, got %s",
				   fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
	error:
		fr_redis_reply_free(&reply);
		return REDIS_RCODE_ERROR;
	}

	p = strstr(reply->str, "redis_version:");
	if (!p) {
		fr_strerror_printf("Response did not contain version string");
		goto error;
	}

	p = strchr(p, ':');
	fr_assert(p);
	p++;

	q = strstr(p, "\r\n");
	if (!q) q = p + strlen(p);

	if ((size_t)(q - p) >= out_len) {
		fr_strerror_printf("Version string %zu bytes, expected < %zu bytes", q - p, out_len);
		goto error;
	}
	strlcpy(out, p, (q - p) + 1);

	fr_redis_reply_free(&reply);

	return REDIS_RCODE_SUCCESS;
}

/** Convert version string into a 32bit unsigned integer for comparisons
 *
 * @param[in] version string to parse.
 * @return 32bit unsigned integer representing the version string.
 */
uint32_t fr_redis_version_num(char const *version)
{
	unsigned long num;
	uint32_t ret;
	char const *p = version;
	char *q;

	num = strtoul(p, &q, 10);
	if (num > UINT8_MAX) {
		fr_strerror_printf("Major version number %lu greater than " STRINGIFY(UINT8_MAX), num);
		return 0;
	}

	if ((p == q) || (q[0] != '.')) {
		fr_strerror_printf("Trailing garbage in Redis version \"%s\"", q);
		return 0;
	}
	ret = num << 24;
	p = q + 1;

	num = strtoul(p, &q, 10);
	if (num > UINT8_MAX) {
		fr_strerror_printf("Minor version number %lu greater than " STRINGIFY(UINT8_MAX), num);
		return 0;
	}

	if ((p == q) || (q[0] != '.')) {
		fr_strerror_printf("Trailing garbage in Redis version \"%s\"", q);
		return 0;
	}
	ret |= num << 16;
	p = q + 1;

	num = strtoul(p, &q, 10);
	if (num > UINT16_MAX) {
		fr_strerror_printf("Minor version number %lu greater than " STRINGIFY(UINT16_MAX), num);
		return 0;
	}

	if ((p == q) || (q[0] != '\0')) {
		fr_strerror_printf("Trailing garbage in Redis version \"%s\"", q);
		return 0;
	}

	return ret | num;
}
