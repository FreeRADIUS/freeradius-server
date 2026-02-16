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

#include <sys/stat.h>

#include "file.h"

static uint32_t filename_hash(void const *data)
{
	rlm_linelog_file_t const *file = data;

	return fr_hash_string(file->filename);
}

static int8_t filename_cmp(void const *one, void const *two)
{
	rlm_linelog_file_t const *a = one;
	rlm_linelog_file_t const *b = two;

	return CMP(strcmp(a->filename, b->filename), 0);
}

unlang_action_t file_batching_mod_resume(UNUSED unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_linelog_file_entry_t	*entry = (rlm_linelog_file_entry_t *)mctx->rctx;

	if (entry->failed) {
		REDEBUG("Write failed - %s", fr_syserror(entry->error));
		return UNLANG_ACTION_FAIL;
	}

	return UNLANG_ACTION_EXECUTE_NEXT;
}

xlat_action_t file_batching_xlat_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
					request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_value_box_t			*wrote;
	rlm_linelog_file_entry_t 	*entry = (rlm_linelog_file_entry_t *)xctx->rctx;

	if (entry->failed) {
		REDEBUG("Write failed - %s", fr_syserror(entry->error));
		return XLAT_ACTION_FAIL;
	}

	MEM(wrote = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL));
	wrote->vb_size = entry->data_len;

	fr_dcursor_insert(out, wrote);

	return XLAT_ACTION_DONE;
}

static inline CC_HINT(always_inline)
void _batching_handle_signal(NDEBUG_UNUSED request_t *request,
			     NDEBUG_UNUSED fr_signal_t action, rlm_linelog_file_entry_t *entry)
{
	fr_assert(action == FR_SIGNAL_CANCEL);
	fr_assert(entry->request == request);

	entry->request = NULL;
}

void file_batching_mod_handle_signal(module_ctx_t const *mctx, request_t *request, fr_signal_t action)
{
	_batching_handle_signal(request, action, (rlm_linelog_file_entry_t *)mctx->rctx);
}

void file_batching_xlat_handle_signal(xlat_ctx_t const *xctx, request_t *request, fr_signal_t action)
{
	_batching_handle_signal(request, action, (rlm_linelog_file_entry_t *)xctx->rctx);
}

static int _file_free(rlm_linelog_file_t *file)
{
	fr_hash_table_delete(file->thread_inst->file_table, file);

	return 0;
}

static void _batching_cleanup_timer(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	talloc_free(uctx);
}

static inline CC_HINT(always_inline)
void batching_mark_entries_failed(rlm_linelog_file_t *file, rlm_linelog_file_entry_t *start_entry, int error)
{
	rlm_linelog_file_entry_t *entry;

	for (entry = start_entry; entry < file->entry_p; entry++) {
		entry->failed = true;
		entry->error = error;

		if (unlang_interpret_is_resumable(entry->request)) {
			unlang_interpret_mark_runnable(entry->request);
		}
	}
}

static void _batch_write(rlm_linelog_file_t *file)
{
	int			ret, written, fd = -1;
	bool			with_delim;
	size_t			len = 0, header_len = 0;
	off_t			offset, file_size;
	int			write_error = 0;
	struct stat		stat_buf;
	struct iovec		to_write[3];
	struct iovec		*to_write_p = to_write;
	rlm_linelog_t const	*inst = talloc_get_type_abort_const(file->mod_inst, rlm_linelog_t);

	fr_assert(inst->file.buffer_write);
	fr_assert(file);
	fr_assert(file->filename);

	if (file->write) {
		FR_TIMER_DISARM(file->write);
	}

	with_delim = (inst->delimiter_len > 0);

	fd = exfile_open(inst->file.ef, file->filename, inst->file.permissions, 0, &offset);
	if (fd < 0) {
		PERROR("Failed to open %s", file->filename);
	error:
		batching_mark_entries_failed(file, file->entry, errno);
		goto done;
	}

	if (inst->file.group_str && (chown(file->filename, -1, inst->file.group) == -1)) {
		ERROR("Unable to change system group of \"%s\" - %s", file->filename, fr_syserror(errno));
		goto error;
	}

	/*
	 *	If a header format is defined and we are at the beginning
	 *	of the file then expand the format and write it out before
	 *	writing the actual log entries.
	 */
	if (!fr_type_is_null(file->log_header->type) && (offset == 0)) {
		to_write_p->iov_base = UNCONST(char *, file->log_header->vb_strvalue);
		header_len = to_write_p->iov_len = file->log_header->vb_length;
		to_write_p++;

		if (with_delim) {
			to_write_p->iov_base = UNCONST(char *, inst->delimiter);
			header_len += to_write_p->iov_len = inst->delimiter_len;
			to_write_p++;
		}
	}

	to_write_p->iov_base = fr_dbuff_start(&file->dbuff);
	to_write_p->iov_len = fr_dbuff_used(&file->dbuff);
	to_write_p++;

	if (fstat(fd, &stat_buf) < 0) {
		ERROR("Failed to stat file %s - %s", file->filename, fr_syserror(errno));
		goto error;
	}
	file_size = stat_buf.st_size;

	errno = 0;
	ret = fr_writev(fd, to_write, to_write_p - to_write, fr_time_delta_from_sec(0));
	written = ret - header_len;
	write_error = errno;
	if (ret >= 0) {
		if (ret < (ssize_t)(header_len)) {
			ret = ftruncate(fd, 0);
			if (ret < 0) {
				ERROR("Failed truncating file \"%s\" after partial header write - %s",
				      file->filename, fr_syserror(errno));
			}

			PERROR("Failed writing header to \"%s\"", file->filename);
			goto error;
		}
	} else {
		/*
		 *	 Check for partial write
		 */
		if (fstat(fd, &stat_buf) < 0) {
			ERROR("Failed to stat file %s - %s", file->filename, fr_syserror(errno));
			goto error;
		}

		written = stat_buf.st_size - file_size - header_len;

		if ((errno == ENOSPC) && (written > 0)) {
			ERROR("No space left on device when writing to \"%s\". Not all data was written",
			      file->filename);
		} else {
			ERROR("Failed writing to \"%s\" - %s", file->filename, fr_syserror(errno));
			goto error;
		}
	}

	if (fsync(fd) < 0) {
		ERROR("Failed syncing \"%s\" to persistent storage - %s", file->filename, fr_syserror(errno));
		goto error;
	}

	for (rlm_linelog_file_entry_t *entry = file->entry; entry < file->entry_p; entry++) {
		len += entry->data_len;

		if (len > (size_t)written) {
			request_t *request = entry->request;
			ROPTIONAL(RWARN, WARN, "Buffered log write failed. Expected %zu bytes, but only %zu bytes were written", len, (size_t)written);
			ret = ftruncate(fd, offset + (len - entry->data_len + header_len));
			if (ret < 0) {
				ERROR("Failed truncating file \"%s\" after partial write - %s",
				      file->filename, fr_syserror(errno));
			}

			batching_mark_entries_failed(file, entry, write_error);
			break;
		}

		/*
		 *	Needed because the write function could be called either from a timer, or directly
		 *	when the buffer is full.  In which case the last entry would not have been yielded
		 */
		if (unlang_interpret_is_resumable(entry->request)) {
			unlang_interpret_mark_runnable(entry->request);
		}
	}

done:
	if ((fd >= 0) && (exfile_close(inst->file.ef, fd) < 0)) {
		PERROR("Failed closing file %s", file->filename);
	}

	fr_dbuff_reset_talloc(&file->dbuff);
	file->entry_p = file->entry;

	if (fr_time_delta_gt(inst->file.buffer_expiry, fr_time_delta_wrap(0))) {
		(void) fr_timer_in(file, file->thread_inst->tl, &file->expiry, inst->file.buffer_expiry,
				   false, _batching_cleanup_timer, file);
	}
}

static void _batching_handle_timeout(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	_batch_write((rlm_linelog_file_t *)uctx);
}

linelog_buffer_action_t file_enqueue_write(rlm_linelog_file_entry_t **entry_p, module_ctx_t const *mctx,
					   linelog_call_env_t const *call_env, request_t *request,
					   struct iovec *vector_p, size_t vector_len)
{
	int 			ret;
	char const		*path;
	rlm_linelog_file_t	*file;
	rlm_linelog_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_linelog_thread_t);
	rlm_linelog_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_linelog_t);

	fr_assert(inst->file.buffer_write);

	path = call_env->filename->vb_strvalue;

	file = fr_hash_table_find_by_key(thread->file_table, fr_hash_case_string(path),
					 &(rlm_linelog_file_t){ .filename = path });

	if (!file) {
		MEM(file = talloc_size(mctx->thread, sizeof(rlm_linelog_file_t) + (sizeof(rlm_linelog_file_entry_t) * inst->file.buffer_count)));
		talloc_set_name_const(file, "rlm_linelog_file_t");

		file->filename = talloc_strdup(file, path);
		MEM(file->log_header = fr_value_box_alloc_null(file));
		file->mod_inst = inst;
		file->thread_inst = thread;

		if (call_env->log_head && fr_value_box_copy(file, file->log_header, call_env->log_head) < 0) {
			RPERROR("Failed to copy log header for buffered log file %pV", call_env->filename);
		error:
			talloc_free(file);
			return LINELOG_BUFFER_WRITE_FAIL;
		}

		file->entry_p = file->entry;
		file->entry_last = file->entry + inst->file.buffer_count;
		file->write = NULL;
		file->expiry = NULL;
		fr_dbuff_init_talloc(file, &file->dbuff, &file->tctx, 1024, SIZE_MAX);

		if (!fr_hash_table_insert(thread->file_table, file)) {
			RPERROR("Failed tracking buffered log file %pV", call_env->filename);
			goto error;
		}

		talloc_set_destructor(file, _file_free);
	}

	if (file->expiry) {
		FR_TIMER_DISARM(file->expiry);
	}

	fr_assert(file->entry_p < file->entry_last);
	*file->entry_p = (rlm_linelog_file_entry_t) {
		.request = request,
		.file = file,
		.failed = false,
		.data_len = 0,
		.error = 0
	};

	ret = fr_concatv(&file->dbuff, vector_p, vector_len);
	if (ret < 0) {
		RERROR("Failed to buffer log entry for %pV", call_env->filename);
		file->entry_p->failed = true;
		return LINELOG_BUFFER_WRITE_FAIL;
	}

	*entry_p = file->entry_p;

	if (fr_time_delta_gt(inst->file.buffer_delay, fr_time_delta_wrap(0)) && !fr_timer_armed(file->write) ) {
		if (unlikely(fr_timer_in(file, file->thread_inst->tl, &file->write, inst->file.buffer_delay,
					 false, _batching_handle_timeout, file)) < 0) {
			RWARN("Failed adding timer to write logs for %pV", call_env->filename);
		}
	}

	file->entry_p->data_len = ret;
	file->entry_p++;

	if (file->entry_p == file->entry_last) {
		_batch_write(file);

		return LINELOG_BUFFER_WRITE_DONE;
	}

	return LINELOG_BUFFER_WRITE_YIELD;
}

void CC_HINT(nonnull) file_thread_init(rlm_linelog_thread_t *thread, fr_timer_list_t *tl)
{
	MEM(thread->file_table = fr_hash_table_alloc(thread, filename_hash, filename_cmp, NULL));
	thread->tl = tl;
}
