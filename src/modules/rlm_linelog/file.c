/*
 * file.c
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

RCSID("$Id$")

#include <freeradius-devel/util/iovec.h>

#include "file.h"

uint32_t filename_hash(void const *data)
{
	rlm_linelog_file_t const *file = data;

	return fr_hash_case_string(file->filename);
}

int8_t filename_cmp(void const *one, void const *two)
{
	rlm_linelog_file_t const *a = one;
	rlm_linelog_file_t const *b = two;

	return strcmp(a->filename, b->filename);
}

unlang_action_t batching_mod_resume(UNUSED unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_linelog_file_entry_t	*entry = (rlm_linelog_file_entry_t *)mctx->rctx;

	if (entry->failed) {
		RDEBUG2("Write failed");
		return UNLANG_ACTION_FAIL;
	}

	return UNLANG_ACTION_EXECUTE_NEXT;
}

xlat_action_t batching_xlat_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
					   request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_value_box_t			*wrote;
	rlm_linelog_file_entry_t 	*entry = (rlm_linelog_file_entry_t *)xctx->rctx;

	if (entry->failed) {
		RDEBUG2("Write failed");
		return XLAT_ACTION_FAIL;
	}

	MEM(wrote = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL));
	wrote->vb_size = entry->data_len;

	fr_dcursor_insert(out, wrote);

	return XLAT_ACTION_DONE;
}

static inline CC_HINT(always_inline) void _batching_handle_signal(request_t *request, NDEBUG_UNUSED fr_signal_t action, rlm_linelog_file_entry_t *entry)
{
	fr_assert(action == FR_SIGNAL_CANCEL);
	fr_assert(entry->request == request);

	RDEBUG("Request associated with buffered log has been cancelled");
	entry->request = NULL;
}

void batching_mod_handle_signal(module_ctx_t const *mctx, request_t *request, fr_signal_t action)
{
	_batching_handle_signal(request, action, (rlm_linelog_file_entry_t *)mctx->rctx);
}

void batching_xlat_handle_signal(xlat_ctx_t const *xctx, request_t *request, fr_signal_t action)
{
	_batching_handle_signal(request, action, (rlm_linelog_file_entry_t *)xctx->rctx);
}

inline CC_HINT(always_inline) void batching_cleanup(rlm_linelog_file_t *file)
{
	if (file->write) {
		fr_timer_delete(&file->write);
	}

	if (file->expiry) {
		fr_timer_delete(&file->expiry);
	}

	file->total_data_len = 0;
	talloc_free(file->log_header);

	fr_hash_table_delete(file->thread_inst->file_table, file);
	talloc_free(file);
}

static void _batching_cleanup_timer(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	batching_cleanup(talloc_get_type_abort(uctx, rlm_linelog_file_t));
}

static inline CC_HINT(always_inline) void _batching_mark_entries_failed(rlm_linelog_file_t *file, rlm_linelog_file_entry_t *start_entry)
{
	rlm_linelog_file_entry_t *entry;

	for (entry = start_entry; entry < file->entry_last; entry++) {
		entry->failed = true;
	}
}

static void _batch_write(rlm_linelog_file_t *file)
{
	int			ret, fd = -1;
	bool			with_delim, failed = false;
	char			*p;
	size_t			len = 0;
	off_t			offset;
	rlm_linelog_t const	*inst = talloc_get_type_abort_const(file->mod_inst, rlm_linelog_t);

	fr_assert(inst->file.buffer_write);
	fr_assert(file);
	fr_assert(file->filename);

	if (file->write) {
		FR_TIMER_DISARM(file->write);
	}

	with_delim = (inst->delimiter_len > 0);

	/* check path and eventually create subdirs */
	p = strrchr(file->filename, '/');
	if (p) {
		*p = '\0';
		if (fr_mkdir(NULL, file->filename, -1, 0700, NULL, NULL) < 0) {
			PERROR("Failed to create directory %s", file->filename);

		error:
			_batching_mark_entries_failed(file, file->entry);
			failed = true;
			goto done;
		}
		*p = '/';
	}

	fd = exfile_open(inst->file.ef, file->filename, inst->file.permissions, 0, &offset);
	if (fd < 0) {
		PERROR("Failed to open %s", file->filename);
		goto error;
	}

	if (inst->file.group_str && (chown(file->filename, -1, inst->file.group) == -1)) {
		PWARN("Unable to change system group of \"%s\"", file->filename);
	}

	/*
	 *	If a header format is defined and we are at the beginning
	 *	of the file then expand the format and write it out before
	 *	writing the actual log entries.
	 */
	if (!fr_type_is_null(file->log_header->type) && (offset == 0)) {
		struct iovec	head_vector_s[2];
		size_t		head_vector_len;

		memcpy(&head_vector_s[0].iov_base, &file->log_header->vb_strvalue, sizeof(head_vector_s[0].iov_base));
		head_vector_s[0].iov_len = file->log_header->vb_length;

		if (!with_delim) {
			head_vector_len = 1;
		} else {
			memcpy(&head_vector_s[1].iov_base, &(inst->delimiter),sizeof(head_vector_s[1].iov_base));
			head_vector_s[1].iov_len = inst->delimiter_len;
			head_vector_len = 2;
		}

		if (writev(fd, &head_vector_s[0], head_vector_len) < 0) {
			PERROR("Failed writing to \"%s\"", file->filename);
			/* Assert on the extra fatal errors */
			fr_assert((errno != EINVAL) && (errno != EFAULT));

		close_and_error:
			if (exfile_close(inst->file.ef, fd) < 0) {
				PERROR("Failed closing file %s", file->filename);
			}
			goto error;
		}
		if (inst->file.fsync && (fsync(fd) < 0)) {
			PERROR("Failed syncing \"%s\" to persistent storage", file->filename);
			goto close_and_error;
		}
	}

	fr_dbuff_set_end(&file->dbuff, fr_dbuff_current(&file->dbuff));
	fr_dbuff_set_to_start(&file->dbuff);
	do {
		ret = write(fd, fr_dbuff_current(&file->dbuff), fr_dbuff_remaining(&file->dbuff));
		if (ret > 0) {
			fr_dbuff_advance(&file->dbuff, ret);
		}
	} while ((fr_dbuff_remaining(&file->dbuff) && (ret > 0)) || ((ret < 0) && ((errno == EINTR) || (errno == EAGAIN))));

	if (fr_dbuff_remaining(&file->dbuff) > 0) {
		// Check if no space left on device but some data was written (move to truncate later)
		if ((errno == ENOSPC) && ((size_t)fr_dbuff_used(&file->dbuff) > 0)) {
			PWARN("No space left on device when writing to \"%s\"", file->filename);
		} else {
			ERROR("Failed writing to \"%s\": %s", file->filename, fr_syserror(errno));
			goto error;
		}
	}

	if (fsync(fd) < 0) {
		ERROR("Failed syncing \"%s\" to persistent storage: %s", file->filename, fr_syserror(errno));
		failed = true;
		goto error;
	}

	// If we didn't write all data, keep the file open for truncation later
	if ((size_t)fr_dbuff_used(&file->dbuff) == file->total_data_len) {
		if (exfile_close(inst->file.ef, fd) < 0) {
			PERROR("Failed closing file %s", file->filename);
		}
	}

done:
	for (rlm_linelog_file_entry_t *entry = file->entry; entry < file->entry_p; entry++) {
		if (failed) {
		write_failed:
			entry->failed = true;
			goto mark_resume;
		}

		len += entry->data_len;

		if (len > fr_dbuff_used(&file->dbuff)) {
			request_t *request = entry->request;
			ROPTIONAL(RWARN, WARN, "Buffered log write failed. Expected %zu bytes, but only %zu bytes were written", len, fr_dbuff_used(&file->dbuff));
			ftruncate(fd, offset + (len - entry->data_len));
			if (exfile_close(inst->file.ef, fd) < 0) {
				PERROR("Failed closing file %s after truncation", file->filename);
			}
			goto write_failed;
		}
	mark_resume:
		/*
		 * Needed because the write function could be called either from a timer or directly when the buffer is full
		 * in which case the last entry would not have been yielded
		 */
		if (unlang_interpret_is_resumable(entry->request)) {
			unlang_interpret_mark_runnable(entry->request);
		}
	}

	// Reset the buffer for future use
	fr_dbuff_reset_talloc(&file->dbuff);
	file->entry_p = file->entry;
	file->total_data_len = 0;

	// Set up expiry timer
	if (fr_time_delta_gt(inst->file.buffer_expiry, fr_time_delta_wrap(0))) {
		fr_timer_in(file,file->thread_inst->tl, &file->expiry, inst->file.buffer_expiry, false, _batching_cleanup_timer, file);
	}
}

static void _batching_handle_timeout(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	_batch_write((rlm_linelog_file_t *)uctx);
}

linelog_buffer_action_t batch_update(rlm_linelog_file_entry_t **entry_p, module_ctx_t const *mctx, linelog_call_env_t const *call_env, request_t *request, struct iovec *vector_p, size_t vector_len)
{
	int 			ret;
	char const		*path;
	rlm_linelog_file_t	*file;
	rlm_linelog_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_linelog_thread_t);
	rlm_linelog_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_linelog_t);

	fr_assert(inst->file.buffer_write);

	path = call_env->filename->vb_strvalue;

	file = fr_hash_table_find_by_key(thread->file_table, fr_hash_case_string(path), &(rlm_linelog_file_t){ .filename = path });

	if (!file) {
		file = talloc_size(mctx->thread, sizeof(rlm_linelog_file_t) + (sizeof(rlm_linelog_file_entry_t) * inst->file.buffer_count));
		talloc_set_name_const(file, "rlm_linelog_file_t");
		file->filename = talloc_strdup(file, path);
		file->log_header = fr_value_box_alloc_null(file);
		file->mod_inst = inst;
		file->thread_inst = thread;
		if (call_env->log_head && fr_value_box_copy(file, file->log_header, call_env->log_head) < 0) {
			RERROR("Failed to copy log header for buffered log file %pV", call_env->filename);
		error:
			talloc_free(file);
			return LINELOG_BUFFER_WRITE_FAIL;
		}
		file->entry_p = file->entry;
		file->entry_last = file->entry + inst->file.buffer_count;
		file->write = NULL;
		file->expiry = NULL;
		file->total_data_len = 0;
		fr_dbuff_init_talloc(file, &file->dbuff, &file->tctx, 1024, SIZE_MAX);

		if (!fr_hash_table_insert(thread->file_table, file)) {
			RERROR("Failed tracking buffered log file %pV", call_env->filename);
			goto error;
		}
	}

	if (file->expiry) {
		FR_TIMER_DISARM(file->expiry);
	}

	fr_assert(file->entry_p < file->entry_last);
	*file->entry_p = (rlm_linelog_file_entry_t){ .request = request, .file = file, .failed = false, .data_len = 0 };
	ret = fr_concatv(&file->dbuff, vector_p, vector_len);

	if (ret < 0) {
		RERROR("Failed to buffer log entry for %pV", call_env->filename);
		file->entry_p->failed = true;
		return LINELOG_BUFFER_WRITE_FAIL;
	}

	*entry_p = file->entry_p;

	// Set the timer to write out after delay
	if (fr_time_delta_gt(inst->file.buffer_delay, fr_time_delta_wrap(0)) && !fr_timer_armed(file->write) ) {
		fr_timer_in(file, file->thread_inst->tl, &file->write, inst->file.buffer_delay, false, _batching_handle_timeout, file);
	}

	file->entry_p->data_len = ret;
	file->total_data_len += ret;
	file->entry_p++;

	if (file->entry_p == file->entry_last) {
		_batch_write(file);

		return LINELOG_BUFFER_WRITE_DONE;
	}

	return LINELOG_BUFFER_WRITE_YIELD;
}
