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
 * @file src/bin/fuzzer_json.c
 * @brief Functions to fuzz json
 * */
RCSID("$Id$")

#include <freeradius-devel/build.h>
#include <freeradius-devel/util/talloc.h>

DIAG_OFF(documentation)
DIAG_OFF(deprecated)

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <json-c/json.h>

/* Forward declarations for FreeRADIUS types to avoid header complexity */
typedef struct fr_jpath_node_s fr_jpath_node_t;

/* External declarations for functions */
extern ssize_t fr_jpath_parse(void *ctx, fr_jpath_node_t **head, 
			      char const *in, size_t inlen);

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	void *ctx = NULL;
	size_t split_point;

	/* Need at least 2 bytes */
	if (size < 2) {
		return 0;
	}

	/* Limit input size to prevent timeouts */
	if (size > 8192) {
		return 0;
	}

	/* Initialize talloc context */
	ctx = talloc_init("fuzzer_json");
	if (!ctx) {
		return 0;
	}

	/*
	 *	Use first byte to determine split between JSON and jpath
	 */
	split_point = (data[0] * size) / 256;
	if (split_point >= size - 1) {
		split_point = size / 2;
	}

	/*
	 *	JSON string to parse with json-c
	 */
	if (split_point > 1) {
		char *str = NULL;
		json_object *json_obj = NULL;

		str = talloc_strndup(ctx, (const char *)(data + 1), split_point - 1);
		if (str) {
			json_obj = json_tokener_parse(str);
			if (json_obj) {
				json_object_put(json_obj);
				json_obj = NULL;
			}
		}
	}

	/*
	 *	jpath expression string to parse with FreeRADIUS
	 */
	if (split_point < size - 1) {
		size_t len = size - split_point - 1;
		char *str = NULL;
		fr_jpath_node_t *jpath_head = NULL;

		if (len > 0) {
			str = talloc_strndup(ctx,
					     (const char *)(data + split_point + 1), 
					     len);
		}
        
		if (str) {
			(void) fr_jpath_parse(ctx, &jpath_head, str, len);
		}
	}

	talloc_free(ctx);
	return 0;
}
