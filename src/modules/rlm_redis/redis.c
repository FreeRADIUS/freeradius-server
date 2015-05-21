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
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2000,2006,2015  The FreeRADIUS server project
 * @copyright 2011 TekSavvy Solutions <gabe@teksavvy.com>
 */
#include "redis.h"
#include <freeradius-devel/rad_assert.h>

const FR_NAME_NUMBER redis_reply_types[] = {
	{ "string",	REDIS_REPLY_STRING },
	{ "integer",	REDIS_REPLY_INTEGER },
	{ "array",	REDIS_REPLY_ARRAY },
	{ "nil",	REDIS_REPLY_NIL },
	{ "status",	REDIS_REPLY_STATUS },
	{ "error",	REDIS_REPLY_ERROR },
	{ NULL,		-1 }
};

/** Check the reply for errors
 *
 * @param conn used to issue the command.
 * @param reply to process.
 * @return
 *	- 0 if no errors.
 *	- -1 on command/server error.
 *	- -2 on connection error (probably needs reconnecting)
 */
int fr_redis_command_status(redis_conn_t *conn, redisReply *reply)
{
	size_t i = 0;

	if (!reply) switch (conn->handle->err) {
	case REDIS_OK:
		break;

	case REDIS_ERR_IO:
	case REDIS_ERR_EOF:
	case REDIS_ERR_OTHER:
		fr_strerror_printf("Connection error: %s", conn->handle->errstr);
		return -2;

	default:
	case REDIS_ERR_PROTOCOL:
		fr_strerror_printf("Command error: %s", conn->handle->errstr);
		return -1;
	}

	if (reply) switch (reply->type) {
	case REDIS_REPLY_STATUS:
		return 0;

	case REDIS_REPLY_ERROR:
		fr_strerror_printf("Server error: %s", reply->str);
		return -1;

	/*
	 *	Recurse to check for nested errors
	 */
	case REDIS_REPLY_ARRAY:
		for (i = 0; i < reply->elements; i++) {
			int ret;

			ret = fr_redis_command_status(conn, reply->element[i]);
			if (ret < 0) return ret;
		}
	default:
		break;
	}
	return 0;
}

/** Print the response data in a useful treelike form
 *
 * @param lvl to print data at.
 * @param reply to print.
 * @param request The current request.
 * @param idx Response number.
 */
void fr_redis_response_print(log_lvl_t lvl, redisReply *reply, REQUEST *request, int idx)
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
			fr_redis_response_print(lvl, reply->element[i], request, i);
			REXDENT();
		}
		break;
	}
}

/** Convert a string or integer type to #value_data_t of specified type
 *
 * Will work with REDIS_REPLY_STRING (which is converted to #PW_TYPE_STRING
 * then cast to dst_type), or REDIS_REPLY_INTEGER (which is converted to
 * #PW_TYPE_INTEGER64, then cast to dst_type).
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
int fr_redis_reply_to_value_data(TALLOC_CTX *ctx, value_data_t *out, redisReply *reply,
				 PW_TYPE dst_type, DICT_ATTR const *dst_enumv)
{
	value_data_t	in;
	PW_TYPE		src_type = 0;

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
			src_type = PW_TYPE_SIGNED;
			in.sinteger = (int32_t) reply->integer;
			in.length = sizeof(in.sinteger);
		}
		else if (reply->integer > INT32_MAX) {	/* 64bit unsigned (supported) */
			src_type = PW_TYPE_INTEGER64;
			in.integer64 = (uint64_t) reply->integer;
			in.length = sizeof(in.integer64);
		}
		else if (reply->integer > INT16_MAX) {	/* 32bit unsigned (supported) */
			src_type = PW_TYPE_INTEGER;
			in.integer = (uint32_t) reply->integer;
			in.length = sizeof(in.integer);
		}
		else if (reply->integer > INT8_MAX) {	/* 16bit unsigned (supported) */
			src_type = PW_TYPE_SHORT;
			in.ushort = (uint16_t) reply->integer;
			in.length = sizeof(in.ushort);
		}
		else if (reply->integer >= 0) {		/* 8bit unsigned (supported) */
			src_type = PW_TYPE_BYTE;
			in.byte = (uint8_t) reply->integer;
			in.length = sizeof(in.byte);
		} else {
			rad_assert(0);
		}
		break;

	case REDIS_REPLY_STRING:
		src_type = PW_TYPE_STRING;
		in.ptr = reply->str;
		in.length = reply->len;
		break;

	case REDIS_REPLY_ARRAY:
	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_ERROR:
		rad_assert(0);
	}

	if (src_type == dst_type) {
		if (value_data_copy(ctx, out, src_type, &in) < 0) return -1;
	} else {
		if (value_data_cast(ctx, out, dst_type, dst_enumv, src_type, NULL, &in) < 0) return -1;
	}
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
			fr_int2str(redis_reply_types, key->type, "<UNKNOWN>"));
	error:
		TALLOC_FREE(map);
		return -1;
	}

	if (op->type != REDIS_REPLY_STRING) {
		REDEBUG("Bad key type, expected string, got %s",
			fr_int2str(redis_reply_types, op->type, "<UNKNOWN>"));
		goto error;
	}

	RDEBUG3("Got key   : %s", key->str);
	RDEBUG3("Got op    : %s", op->str);

	if (RDEBUG_ENABLED3) {
		char *p;

		p = fr_aprints(NULL, value->str, value->len, '"');
		RDEBUG3("Got value : %s", p);
		talloc_free(p);
	}

	map = talloc_zero(ctx, vp_map_t);
	slen = tmpl_afrom_attr_str(map, &map->lhs, key->str, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false);
	if (slen < 0) {
		REMARKER(key->str, -slen, fr_strerror());
		goto error;
	}

	map->op = fr_str2int(fr_tokens, op->str, T_INVALID);
	if (map->op == T_INVALID) {
		REDEBUG("Invalid operator \"%s\"", op->str);
		goto error;
	}

	switch (value->type) {
	case REDIS_REPLY_STRING:
	case REDIS_REPLY_INTEGER:
	{
		value_data_t vpt;

		/* Logs own errors */
		if (fr_redis_reply_to_value_data(map, &vpt, value,
						 map->lhs->tmpl_da->type, map->lhs->tmpl_da) < 0) {
			REDEBUG("Failed converting Redis data: %s", fr_strerror());
			goto error;
		}

		/* This will only fail only memory allocation errors */
		if (tmpl_afrom_value_data(map, &map->rhs, &vpt,
					  map->lhs->tmpl_da->type, map->lhs->tmpl_da, true) < 0) {
			goto error;
		}
	}
		break;

	default:
		REDEBUG("Bad value type, expected string or integer, got %s",
			fr_int2str(redis_reply_types, value->type, "<UNKNOWN>"));
		goto error;

	}
	VERIFY_MAP(map);

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
 * @param map to convert.
 */
int fr_redis_tuple_from_map(TALLOC_CTX *pool, char const *out[], size_t out_len[], vp_map_t *map)
{
	char		*new;

	char		key_buf[256];
	char		*key;
	size_t		key_len;

	rad_assert(map->lhs->type == TMPL_TYPE_ATTR);
	rad_assert(map->rhs->type == TMPL_TYPE_DATA);

	key_len = tmpl_prints(key_buf, sizeof(key_buf), map->lhs, map->lhs->tmpl_da);
	key = talloc_bstrndup(pool, key_buf, key_len);
	if (!key) return -1;

	switch (map->rhs->tmpl_data_type) {
	case PW_TYPE_STRING:
	case PW_TYPE_OCTETS:
		out[2] = map->rhs->tmpl_data_value.ptr;
		out_len[2] = map->rhs->tmpl_data_length;
		break;

	/*
	 *	For everything else we get the string representation
	 */
	default:
	{
		char	value[256];
		size_t	len;

		len = value_data_prints(value, sizeof(value), map->rhs->tmpl_data_type, map->lhs->tmpl_da,
					&map->rhs->tmpl_data_value, '\0');
		new = talloc_bstrndup(pool, value, len);
		if (!new) {
			talloc_free(key);
			return -1;
		}
		out[2] = new;
		out_len[2] = len;
		break;
	}
	}

	out[0] = key;
	out_len[0] = key_len;
	out[1] = fr_int2str(fr_tokens, map->op, NULL);
	out_len[1] = strlen(out[1]);

	return 0;
}

/** Callback for freeing a REDIS connection
 *
 */
static int _redis_conn_free(redis_conn_t *conn)
{
	redisFree(conn->handle);

	return 0;
}

/** Create a new connection to the REDIS directory
 *
 * @param ctx to allocate connection structure in. Will be freed at the same time as the pool.
 * @param instance data of type #redis_conn_conf_t. Holds parameters for establishing new connection.
 * @return
 *	- New #redis_conn_t on success.
 *	- NULL on failure.
 */
void *fr_redis_conn_create(TALLOC_CTX *ctx, void *instance)
{
	redis_conn_conf_t	*inst = instance;
	redis_conn_t		*conn = NULL;
	redisContext		*handle;
	redisReply		*reply = NULL;

	handle = redisConnect(inst->hostname, inst->port);
	if ((handle != NULL) && handle->err) {
		ERROR("%s: Connection failed: %s", inst->prefix, handle->errstr);
		redisFree(handle);
		return NULL;
	}
	else if (!handle) {
		ERROR("%s: Connection failed", inst->prefix);
		return NULL;
	}

	if (inst->password) {
		DEBUG3("%s: Executing: AUTH %s", inst->prefix, inst->password);
		reply = redisCommand(handle, "AUTH %s", inst->password);
		if (!reply) {
			ERROR("%s: Failed AUTH(enticating): %s", inst->prefix, handle->errstr);
		error:
			if (reply) freeReplyObject(reply);
			redisFree(handle);
			return NULL;
		}

		switch (reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(reply->str, "OK") != 0) {
				ERROR("%s: Failed AUTH(enticating): %s", inst->prefix, reply->str);
				goto error;
			}
			freeReplyObject(reply);
			break;	/* else it's OK */

		case REDIS_REPLY_ERROR:
			ERROR("%s: Failed AUTH(enticating): %s", inst->prefix, reply->str);
			goto error;

		default:
			ERROR("%s: Unexpected reply of type %s to AUTH", inst->prefix,
			      fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
			goto error;
		}
	}

	if (inst->database) {
		DEBUG3("%s: Executing: SELECT %i", inst->prefix, inst->database);
		reply = redisCommand(handle, "SELECT %i", inst->database);
		if (!reply) {
			ERROR("%s: Failed SELECT(ing) database %i: %s", inst->prefix, inst->database, handle->errstr);
			goto error;
		}

		switch (reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(reply->str, "OK") != 0) {
				ERROR("%s: Failed SELECT(ing) database %i: %s", inst->prefix,
				      inst->database, reply->str);
				goto error;
			}
			freeReplyObject(reply);
			break;	/* else it's OK */

		case REDIS_REPLY_ERROR:
			ERROR("%s: Failed SELECT(ing) database %i: %s", inst->prefix,
			      inst->database, reply->str);
			goto error;

		default:
			ERROR("%s: Unexpected reply of type %s, to SELECT", inst->prefix,
			      fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
			goto error;
		}
	}

	conn = talloc_zero(ctx, redis_conn_t);
	conn->handle = handle;
	talloc_set_destructor(conn, _redis_conn_free);

	return conn;
}

/** Print the version of libhiredis the server was built against
 *
 */
void fr_redis_version_print(void)
{
	static bool version_done;

	if (!version_done) {
		version_done = true;

		INFO("*: libhiredis version: %i.%i.%i", HIREDIS_MAJOR, HIREDIS_MINOR, HIREDIS_PATCH);
	}
}
