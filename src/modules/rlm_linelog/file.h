/*
 * file.h
 *
 * Version:	$Id$
 *
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
 *
 * @copyright 2025 Network RADIUS SAS (legal@networkradius.com)
 */

#include "rlm_linelog.h"

/** linelog module thread specific structure
 */
typedef struct {
	fr_hash_table_t		*file_table;		//!< Hash table of files.
	fr_timer_list_t		*tl;			//!< Timer list for this thread.
} rlm_linelog_thread_t;

typedef struct rlm_linelog_file_s rlm_linelog_file_t;

typedef struct {
	request_t		*request;		//!< The request that created the data.
	rlm_linelog_file_t	*file;			//!< The file being written to.
	bool			failed;			//!< Write failed.
	size_t			data_len;		//!< How much data this entry holds in the sbuff.
	int			error;			//!< Error code if the write failed.
} rlm_linelog_file_entry_t;

typedef struct linelog_write_uctx_s linelog_write_uctx_t;

struct rlm_linelog_file_s {
	char const			*filename;		//!< Talloced filename string.
	fr_value_box_t			*log_header;		//!< Header to prepend to each log line.
	rlm_linelog_t const		*mod_inst;		//!< Module instance this file belongs to.
	rlm_linelog_thread_t		*thread_inst;		//!< Thread instance this file belongs to.
	fr_dbuff_uctx_talloc_t		tctx;			//!< Talloc context for the dbuff.
	fr_dbuff_t			dbuff;			//!< Talloced, dynamically resized dbuff containing
								//!< all of the linelog content to write out.
	fr_timer_t			*write;			//!< When we need to write out any pending data in the buffer.
	fr_timer_t			*expiry;		//!< When we should cleanup file metadata due to inactivity.
	rlm_linelog_file_entry_t	*entry_p;		//!< Last entry we wrote to.
	rlm_linelog_file_entry_t	*entry_last;		//!< Last entry in the array.
	rlm_linelog_file_entry_t	entry[];		//!< Array of metadata for each pending write.
};

typedef enum {
	LINELOG_BUFFER_WRITE_FAIL = -1,		//!< Writing buffered data failed.
	LINELOG_BUFFER_WRITE_YIELD = 0,		//!< Writing buffered data yielded.
	LINELOG_BUFFER_WRITE_DONE = 1		//!< Writing buffered data completed.
} linelog_buffer_action_t;

unlang_action_t file_batching_mod_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request);

xlat_action_t file_batching_xlat_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
					request_t *request, fr_value_box_list_t *in);

void file_batching_mod_handle_signal(module_ctx_t const *mctx, request_t *request, fr_signal_t action);

void file_batching_xlat_handle_signal(xlat_ctx_t const *xctx, request_t *request, fr_signal_t action);

linelog_buffer_action_t file_enqueue_write(rlm_linelog_file_entry_t **entry_p, module_ctx_t const *mctx,
					   linelog_call_env_t const *call_env, request_t *request,
					   struct iovec *vector_p, size_t vector_len);

void file_thread_init(rlm_linelog_thread_t *thread, fr_timer_list_t *tl);
