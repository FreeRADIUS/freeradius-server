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
 * @file proto_detail_work.c
 * @brief Detail handler for files
 *
 * @copyright 2017 The FreeRADIUS server project.
 * @copyright 2017 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/base.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/server/rad_assert.h>
#include "proto_detail.h"

#include <fcntl.h>
#include <sys/stat.h>

#ifndef NDEBUG
#if 0
/*
 *	When we want detailed debugging here, without detailed server
 *	debugging.
 */
#define MPRINT DEBUG
#else
#define MPRINT DEBUG3
#endif
#else
// No debugging, just remove the mprint entirely
#define MPRINT(_x, ...)
#endif

typedef struct {
	proto_detail_work_thread_t	*parent;		//!< talloc_parent is SLOW!
	fr_time_t			timestamp;		//!< when we read the entry.
	off_t				done_offset;		//!< where we're tracking the status

	int				id;			//!< for retransmission counters

	uint8_t				*packet;		//!< for retransmissions
	size_t				packet_len;		//!< for retransmissions

	fr_time_delta_t			rt;
	uint32_t       			count;			//!< number of retransmission tries

	fr_time_t			start;			//!< when we started trying to send

	fr_event_timer_t const		*ev;			//!< retransmission timer
	fr_dlist_t			entry;			//!< for the retransmission list
} fr_detail_entry_t;

static CONF_PARSER limit_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", FR_TYPE_UINT32, proto_detail_work_t, irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", FR_TYPE_UINT32, proto_detail_work_t, mrt), .dflt = STRINGIFY(16) },

	/*
	 *	Retransmit indefinitely, as v2 and v3 did.
	 */
	{ FR_CONF_OFFSET("max_rtx_count", FR_TYPE_UINT32, proto_detail_work_t, mrc), .dflt = STRINGIFY(0) },
	/*
	 *	...again same as v2 and v3.
	 */
	{ FR_CONF_OFFSET("max_rtx_duration", FR_TYPE_UINT32, proto_detail_work_t, mrd), .dflt = STRINGIFY(0) },
	{ FR_CONF_OFFSET("maximum_outstanding", FR_TYPE_UINT32, proto_detail_work_t, max_outstanding), .dflt = STRINGIFY(1) },
	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER file_listen_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_STRING | FR_TYPE_REQUIRED, proto_detail_work_t, filename_work ) },

	{ FR_CONF_OFFSET("track", FR_TYPE_BOOL, proto_detail_work_t, track_progress ) },

	{ FR_CONF_OFFSET("retransmit", FR_TYPE_BOOL, proto_detail_work_t, retransmit ), .dflt = "yes" },

	{ FR_CONF_POINTER("limit", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) limit_config },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t proto_detail_work_dict[];
fr_dict_autoload_t proto_detail_work_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },

	{ NULL }
};

static fr_dict_attr_t const *attr_packet_transmit_counter;

extern fr_dict_attr_autoload_t proto_detail_work_dict_attr[];
fr_dict_attr_autoload_t proto_detail_work_dict_attr[] = {
	{ .out = &attr_packet_transmit_counter, .name = "Packet-Transmit-Counter", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ NULL }
};

/*
 *	All of the decoding is done by proto_detail.c
 */
static int mod_decode(void const *instance, REQUEST *request, UNUSED uint8_t *const data, UNUSED size_t data_len)
{

	proto_detail_work_t const	*inst = talloc_get_type_abort_const(instance, proto_detail_work_t);
	fr_detail_entry_t const		*track = request->async->packet_ctx;
	VALUE_PAIR *vp;

	request->config = main_config;
	request->client = inst->client;

	request->packet->id = track->id;
	request->reply->id = track->id;
	REQUEST_VERIFY(request);

	MEM(pair_update_request(&vp, attr_packet_transmit_counter) >= 0);
	vp->vp_uint32 = track->count;

	return 0;
}

static fr_event_update_t pause_read[] = {
	FR_EVENT_SUSPEND(fr_event_io_func_t, read),
	{ 0 }
};

static fr_event_update_t resume_read[] = {
	FR_EVENT_RESUME(fr_event_io_func_t, read),
	{ 0 }
};

static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, size_t *leftover, uint32_t *priority, UNUSED bool *is_dup)
{
	proto_detail_work_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_detail_work_t);
	proto_detail_work_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_detail_work_thread_t);

	ssize_t				data_size;
	size_t				packet_len;
	fr_detail_entry_t		*track;
	uint8_t				*partial, *end, *next, *p, *record_end;
	uint8_t				*stopped_search;
	off_t				done_offset;

	rad_assert(*leftover < buffer_len);
	rad_assert(thread->fd >= 0);

	MPRINT("AT COUNT %d offset %ld", thread->count, (long) thread->read_offset);

	/*
	 *	Process retransmissions before anything else in the
	 *	file.
	 */
	track = fr_dlist_head(&thread->list);
	if (track) {
		fr_dlist_remove(&thread->list, track);

		/*
		 *	Don't over-write "leftover" bytes!
		 */
		if (*leftover) {
			rad_assert(thread->leftover == 0);
			if (!thread->leftover_buffer) MEM(thread->leftover_buffer = talloc_array(thread, uint8_t, buffer_len));

			memcpy(thread->leftover_buffer, buffer, *leftover);
			thread->leftover = *leftover;
			*leftover = 0;
		}

		rad_assert(buffer_len >= track->packet_len);
		memcpy(buffer, track->packet, track->packet_len);

		DEBUG("Retrying packet %d (retransmission %u)", track->id, track->count);
		*packet_ctx = track;
		*recv_time_p = track->timestamp;
		*priority = inst->parent->priority;
		return track->packet_len;
	}

	/*
	 *	If we decide that we're closing, ignore everything
	 *	else in the file.  Someone extended the file on us
	 *	without locking it first.  So too bad for them.
	 */
	if (thread->closing) {
		if (inst->track_progress) thread->read_offset = lseek(thread->fd, 0, SEEK_END);
		return 0;
	}

	/*
	 *	Once a socket is ready, the network side tries to read
	 *	many packets.  So if we want to stop it from reading,
	 *	we have to check this ourselves.
	 */
	if (thread->outstanding >= inst->max_outstanding) {
		rad_assert(thread->paused);
		return 0;
	}

	/*
	 *	If we've cached leftover data from the ring buffer,
	 *	copy it back.
	 */
	if (thread->leftover) {
		rad_assert(*leftover == 0);
		rad_assert(thread->leftover < buffer_len);

		memcpy(buffer, thread->leftover_buffer, thread->leftover);
		*leftover = thread->leftover;
		thread->leftover = 0;
	}

	/*
	 *	Seek to the current read offset.
	 */
	(void) lseek(thread->fd, thread->read_offset, SEEK_SET);

	/*
	 *	There will be "leftover" bytes left over in the buffer
	 *	from any previous read.  At the start of the file,
	 *	"leftover" will be zero.
	 */
	partial = buffer + *leftover;

	MPRINT("READ leftover %zd", *leftover);

	/*
	 *	Try to read as much data as possible.
	 */
	if (!thread->eof) {
		size_t room;

		room = buffer_len - *leftover;

		data_size = read(thread->fd, partial, room);
		if (data_size < 0) {
			ERROR("proto_detail (%s): Failed reading file %s: %s",
			      thread->name, thread->filename_work, fr_syserror(errno));
			return -1;
		}

		MPRINT("GOT %zd bytes", data_size);

		/*
		 *	Remember the read offset, and whether we got EOF.
		 */
		thread->read_offset = lseek(thread->fd, 0, SEEK_CUR);

		/*
		 *	Only set EOF if there's no more data in the buffer to manage.
		 */
		thread->eof = (data_size == 0) || (thread->read_offset == thread->file_size) || ((size_t) data_size < room);
		if (thread->eof) {
			MPRINT("Set EOF data_size %ld vs room %ld", data_size, room);
			MPRINT("Set EOF read %ld vs file %ld", (long) thread->read_offset, (long) thread->file_size);
		}
		end = partial + data_size;

	} else {
		MPRINT("READ UNTIL EOF");
		/*
		 *	We didn't read any more data from the file,
		 *	but there should be data left in the buffer.
		 */
		rad_assert(*leftover > 0);
		end = buffer + *leftover;
	}

redo:
	next = NULL;
	stopped_search = end;

	/*
	 *	Look for "end of record" marker, starting from the
	 *	beginning of the buffer.
	 *
	 *	Note that all of the data MUST be printable, and raw
	 *	LFs are forbidden in attribute contents.
	 */
	rad_assert((buffer + thread->last_search) <= end);

	MPRINT("Starting search from offset %ld", thread->last_search);

	p = buffer + thread->last_search;
	while (p < end) {
		if (p[0] != '\n') {
			p++;
			continue;
		}
		if ((p + 1) == end) {
			/*
			 *	Remember the last LF, so if the next
			 *	read starts with a LF, we can find the
			 *	end of record marker.
			 */
			stopped_search = p;
			break; /* no more data */
		}

		if (p[1] == '\n') {
			p[0] = '\0';
			p[1] = '\0';
			next = p + 2;
			stopped_search = next;
			break;
		}

		/*
		 *	If we're not at EOF, and we're not at end of
		 *	record, every line MUST have a leading tab.
		 */
		if (p[1] != '\t') {
			ERROR("proto_detail (%s): Malformed line found at offset %zu in file %s",
			      thread->name, (size_t)((p - buffer) + thread->header_offset),
			      thread->filename_work);
			return -1;
		}

		/*
		 *	Smash the \n with zero, so that each line can
		 *	be parsed individually.
		 */
		p[0] = '\0';

		/*
		 *	Skip the \n\t
		 */
		if ((p + 2) >= end) {
			stopped_search = p;
			break;
		}

		p += 2;

		/*
		 *	Skip attribute name
		 */
		while ((p < end) && !isspace(*p)) p++;

		/*
		 *	Not enough room for " = ", skip this sanity
		 *	check, and just search for a \n on the next
		 *	round through the loop.
		 */
		if ((end - p) < 3) {
			stopped_search = p;
			break;
		}

		/*
		 *	Check for " = ".  If the line doesn't contain
		 *	this, it's malformed.
		 */
		if (memcmp(p, " = ", 3) != 0) {
			ERROR("proto_detail (%s): Malformed line found at offset %zu: %.*s of file %s",
			      thread->name,
			      (size_t)((p - buffer) + thread->header_offset), (int) (end - p), p,
			      thread->filename_work);
			return -1;
		}

		/*
		 *	Skip the " = ", and go back to the top of the
		 *	loop where we check for the next \n.
		 */
		p += 3;
	}

	thread->last_search = (stopped_search - buffer);

	/*
	 *	If there is a next record, remember how large this
	 *	record is, and update "leftover" bytes.
	 */
	if (next) {
		packet_len = next - buffer;
		*leftover = end - next;

		MPRINT("FOUND next at %zd, leftover is %zd", packet_len, *leftover);

	} else if (!thread->eof) {
		if ((size_t) (end - buffer) == buffer_len) {
			ERROR("proto_detail (%s): Too large entry (>%d bytes) found at offset %zu: %.*s of file %s",
			      thread->name, (int) buffer_len,
			      (size_t)((p - buffer) + thread->header_offset), (int) (end - p), p,
			      thread->filename_work);
			return -1;
		}

		/*
		 *	We're not at EOF, and there is no "next"
		 *	entry.  Remember all of the leftover data in
		 *	the buffer, and ask the caller to call us when
		 *	there's more data.
		 */
		*leftover = end - buffer;
		MPRINT("Not at EOF, and no next.  Leftover is %zd", *leftover);
		return 0;

	} else {
		/*
		 *	Else we're at EOF, it's OK to not have an "end
		 *	of record" marker.  We just eat all of the
		 *	remaining data.
		 */
		packet_len = end - buffer;
		*leftover = 0;

		MPRINT("NO end of record, but at EOF, found %zd leftover is 0", packet_len);
	}

	/*
	 *	Too big?  Ignore it.
	 *
	 *	@todo - skip the record, using memmove() etc.
	 */
	if (packet_len > inst->parent->max_packet_size) {
		DEBUG("Ignoring 'too large' entry at offset %zu of %s",
		      (size_t) thread->header_offset, thread->filename_work);
		DEBUG("Entry size %lu is greater than allowed maximum %u",
		      packet_len, inst->parent->max_packet_size);
	skip_record:
		MPRINT("Skipping record");
		if (next) {
			memmove(buffer, next, (end - next));
			data_size = (end - next);
			*leftover = 0;
			end = buffer + data_size;
			thread->last_search = 0;

			/*
			 *	No more data, we're done.
			 */
			if (end == buffer) return 0;
			goto redo;
		}

		rad_assert(*leftover == 0);
		goto done;
	}

	/*
	 *	Search for the "Timestamp" attribute.  We overload
	 *	that to track which entries have been used.
	 */
	record_end = buffer + packet_len;
	p = buffer;
	done_offset = 0;

	while (p < record_end) {
		if (*p != '\0') {
			p++;
			continue;
		}

		p++;
		if (p == record_end) break;

		if (((record_end - p) >= 5) &&
		    (memcmp(p, "\tDone", 5) == 0)) {
			goto skip_record;
		}

		if (((record_end - p) > 10) &&
		    (memcmp(p, "\tTimestamp", 10) == 0)) {
			p++;
			done_offset = thread->header_offset + (p - buffer);
		}
	}

	/*
	 *	Allocate the tracking entry.
	 */
	track = talloc_zero(thread, fr_detail_entry_t);
	track->parent = thread;
	track->timestamp = fr_time();
	track->id = thread->count++;
	track->rt = inst->irt;
	track->rt *= NSEC;

	track->done_offset = done_offset;
	if (inst->retransmit) {
		track->packet = talloc_memdup(track, buffer, packet_len);
		track->packet_len = packet_len;
	}

	/*
	 *	We've read one more packet.
	 */
	thread->header_offset += packet_len;

	*packet_ctx = track;
	*recv_time_p = track->timestamp;
	*priority = inst->parent->priority;

done:
	/*
	 *	If we're at EOF, mark us as "closing".
	 */
	if (thread->eof) {
		rad_assert(!thread->closing);
		thread->closing = (*leftover == 0);
		MPRINT("AT EOF, BUT CLOSING %d", thread->closing);
	}

	thread->outstanding++;

	/*
	 *	Pause reading until such time as we need more packets.
	 */
	if (!thread->paused && (thread->outstanding >= inst->max_outstanding)) {
		(void) fr_event_filter_update(thread->el, thread->fd, FR_EVENT_FILTER_IO, pause_read);
		thread->paused = true;

		/*
		 *	Back up so that read() knows there's more data.
		 */
		if (*leftover) (void) lseek(thread->fd, thread->read_offset - 1, SEEK_SET);
	}

	/*
	 *	Next time, start searching from the start of the
	 *	buffer.
	 */
	thread->last_search = 0;

	MPRINT("Returning NUM %u - %.*s", thread->outstanding, (int) packet_len, buffer);
	return packet_len;
}


static void work_retransmit(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_detail_entry_t		*track = talloc_get_type_abort(uctx, fr_detail_entry_t);
	proto_detail_work_thread_t     	*thread = track->parent;

	DEBUG("%s - retransmitting packet %d", thread->name, track->id);
	track->count++;

	fr_dlist_insert_tail(&thread->list, track);

	if (thread->paused && (thread->outstanding < thread->inst->max_outstanding)) {
		(void) fr_event_filter_update(thread->el, thread->fd, FR_EVENT_FILTER_IO, resume_read);
		thread->paused = false;
	}

	rad_assert(thread->fd >= 0);

	/*
	 *	Seek to the START of the file, so that the FD will
	 *	always return ready.
	 *
	 *	The mod_read() function will take care of seeking to
	 *	the correct read offset.
	 */
	(void) lseek(thread->fd, 0, SEEK_SET);

#ifdef __linux__
	fr_network_listen_read(thread->nr, thread->listen);
#endif
}

static ssize_t mod_write(fr_listen_t *li, void *packet_ctx, fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_detail_work_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_detail_work_t);
	proto_detail_work_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_detail_work_thread_t);
	fr_detail_entry_t		*track = packet_ctx;

	if (buffer_len < 1) return -1;

	rad_assert(thread->outstanding > 0);
	rad_assert(thread->fd >= 0);

	if (!buffer[0]) {
		fr_time_t now;

		/*
		 *	Cap at MRC, if required.
		 */
		if (inst->mrc && (track->count >= inst->mrc)) {
			DEBUG("%s - packet %d failed after %u retransmissions",
			      thread->name, track->id, track->count);
			goto fail;
		}

		now = fr_time();

		if (track->count == 0) {
			track->rt = inst->irt;
			track->rt *= NSEC;
			track->start = request_time;

		} else {
			/*
			 *	Cap at MRD, if required.
			 */
			if (inst->mrd) {
				fr_time_t end;

				end = track->start;
				end += ((fr_time_t) inst->mrd) * NSEC;
				if (now >= end) {
					DEBUG("%s - packet %d failed after %u seconds",
					      thread->name, track->id, inst->mrd);
					goto fail;
				}
			}

			// @todo - add random delays...

		} /* we're on retransmission N */

		DEBUG("%s - packet %d failed during processing.  Will retransmit in %d.%06ds",
		      thread->name, track->id, (int) (track->rt / NSEC), (int) ((track->rt % NSEC) / 1000));

		if (fr_event_timer_at(thread, thread->el, &track->ev,
				      now + track->rt, work_retransmit, track) < 0) {
			ERROR("%s - Failed inserting retransmission timeout", thread->name);
		fail:
			if (inst->track_progress && (track->done_offset > 0)) goto mark_done;
			goto free_track;
		}

		if (!thread->paused && (thread->outstanding >= inst->max_outstanding)) {
			(void) fr_event_filter_update(thread->el, thread->fd, FR_EVENT_FILTER_IO, pause_read);
			thread->paused = true;
		}

		return 1;

	} else if (inst->track_progress && (track->done_offset > 0)) {
	mark_done:
		/*
		 *	Seek to the entry, mark it as done, and then seek to
		 *	the point in the file where we were reading from.
		 */
		(void) lseek(thread->fd, track->done_offset, SEEK_SET);
		if (write(thread->fd, "Done", 4) < 0) {
			ERROR("%s - Failed marking entry as done: %s", thread->name, fr_syserror(errno));
		}
		(void) lseek(thread->fd, thread->read_offset, SEEK_SET);
	}

free_track:
	thread->outstanding--;

	/*
	 *	If we need to read some more packet, let's do so.
	 */
	if (thread->paused && (thread->outstanding < inst->max_outstanding)) {
		(void) fr_event_filter_update(thread->el, thread->fd, FR_EVENT_FILTER_IO, resume_read);
		thread->paused = false;

		/*
		 *	And seek to the start of the file, so that the
		 *	reader gets activated again.  The reader will
		 *	lseek() to the read offset, so this seek is fine.
		 */
		(void) lseek(thread->fd, 0, SEEK_SET);
	}

	/*
	 *	@todo - add a used / free pool for these
	 */
	talloc_free(track);

	/*
	 *	Close the socket if we're at EOF, and there are no
	 *	outstanding replies to deal with.
	 */
	if (thread->closing && !thread->outstanding) {
		MPRINT("WRITE ASKED TO CLOSE");
		return 0;
	}

	MPRINT("WRITE RETURN B %ld", buffer_len);
	return buffer_len;
}

/** Open a detail listener
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_detail_work_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_detail_work_t);
	proto_detail_work_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_detail_work_thread_t);

	fr_dlist_init(&thread->list, fr_detail_entry_t, entry);

	/*
	 *	Open the file if we haven't already been given one.
	 */
	if (thread->fd < 0) {
		thread->filename_work = talloc_strdup(inst, inst->filename_work);

		li->fd = thread->fd = open(thread->filename_work, inst->mode);
		if (thread->fd < 0) {
			cf_log_err(inst->cs, "Failed opening %s: %s", thread->filename_work, fr_syserror(errno));
			return -1;
		}
	}

	/*
	 *	If we're tracking progress, learn where the EOF is.
	 */
	if (inst->track_progress) {
		struct stat buf;

		if (fstat(thread->fd, &buf) < 0) {
			cf_log_err(inst->cs, "Failed examining %s: %s", thread->filename_work, fr_syserror(errno));
			return -1;
		}

		thread->file_size = buf.st_size;
	} else {
		/*
		 *	Avoid triggering erroneous EOF.
		 */
		thread->file_size = 1;
	}

	rad_assert(thread->name == NULL);
	rad_assert(thread->filename_work != NULL);
	thread->name = talloc_typed_asprintf(thread, "proto_detail working file %s", thread->filename_work);

	DEBUG("Listening on %s bound to virtual server %s",
	      thread->name, cf_section_name2(inst->parent->server_cs));

	return 0;
}


static int mod_close_internal(proto_detail_work_thread_t *thread)
{
	/*
	 *	One less worker...  we check for "0" because of the
	 *	hacks in proto_detail which let us start up with
	 *	"transport = work" for debugging purposes.
	 */
	if (thread->file_parent) {
		pthread_mutex_lock(&thread->file_parent->worker_mutex);
		if (thread->file_parent->num_workers > 0) thread->file_parent->num_workers--;
		pthread_mutex_unlock(&thread->file_parent->worker_mutex);
	}

	DEBUG("Closing and deleting detail worker file %s", thread->name);

#ifdef NOTE_REVOKE
	fr_event_fd_delete(thread->el, thread->fd, FR_EVENT_FILTER_VNODE);
#endif
	fr_event_fd_delete(thread->el, thread->fd, FR_EVENT_FILTER_IO);

	unlink(thread->filename_work);

	close(thread->fd);
	thread->fd = -1;

	/*
	 *	If we've been spawned from proto_detail_file, clean
	 *	ourselves up, including our listener.
	 */
	if (thread->listen) {
		talloc_free(thread->listen);
	}

	return 0;
}


/** Close  a detail listener
 *
 */
static int mod_close(fr_listen_t *li)
{
	proto_detail_work_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_detail_work_thread_t);

	return mod_close_internal(thread);
}

#ifdef NOTE_REVOKE
static void mod_revoke(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	proto_detail_work_thread_t *thread = talloc_get_type_abort(uctx, proto_detail_work_thread_t);

	/*
	 *	The underlying file system is gone.  Stop reading the
	 *	file, destroy all of the IO handlers, and delete everything.
	 */
	DEBUG("Detail worker %s had file system unmounted.  Stopping.", thread->name);
	mod_close_internal(thread);
}
#endif


/** Set the event list for a new IO instance
 *
 * @param[in] li the listener
 * @param[in] el the event list
 * @param[in] nr context from the network side
 */
static void mod_event_list_set(fr_listen_t *li, fr_event_list_t *el, void *nr)
{
	proto_detail_work_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_detail_work_thread_t);

#ifdef NOTE_REVOKE
	fr_event_vnode_func_t funcs;

	memset(&funcs, 0, sizeof(funcs));
	funcs.revoke = mod_revoke;

	if (fr_event_filter_insert(thread, el, thread->fd, FR_EVENT_FILTER_VNODE, &funcs, NULL, thread) < 0) {
		WARN("Failed to add event watching for unmounted file system");
	}
#endif

	thread->el = el;
	thread->nr = nr;
}


static char const *mod_name(fr_listen_t *li)

{	proto_detail_work_thread_t *thread = talloc_get_type_abort(li->thread_instance, proto_detail_work_thread_t);

	return thread->name;
}

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *cs)
{
	proto_detail_work_t *inst = talloc_get_type_abort(instance, proto_detail_work_t);
	RADCLIENT *client;

	client = inst->client = talloc_zero(inst, RADCLIENT);
	if (!inst->client) return 0;

	client->ipaddr.af = AF_INET;
	client->ipaddr.addr.v4.s_addr = htonl(INADDR_NONE);
	client->src_ipaddr = client->ipaddr;

	client->longname = client->shortname = client->secret = inst->filename;
	client->nas_type = talloc_strdup(client, "other");

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_detail_work_t	*inst = talloc_get_type_abort(instance, proto_detail_work_t);
	dl_module_inst_t const	*dl_inst;

	/*
	 *	Find the dl_module_inst_t holding our instance data
	 *	so we can find out what the parent of our instance
	 *	was.
	 */
	dl_inst = dl_module_instance_by_data(instance);
	rad_assert(dl_inst);

	inst->parent = talloc_get_type_abort(dl_inst->parent->data, proto_detail_t);
	inst->cs = cs;

	if (inst->track_progress) {
		inst->mode = O_RDWR;
	} else {
		inst->mode = O_RDONLY;
	}

	if (inst->retransmit) {
		FR_INTEGER_BOUND_CHECK("limit.initial_rtx_time", inst->irt, >=, 1);
		FR_INTEGER_BOUND_CHECK("limit.initial_rtx_time", inst->irt, <=, 60);

		/*
		 *	If you need more than this, just set it to
		 *	"0", and check Packet-Transmit-Count manually.
		 */
		FR_INTEGER_BOUND_CHECK("limit.max_rtx_count", inst->mrc, <=, 20);
		FR_INTEGER_BOUND_CHECK("limit.max_rtx_duration", inst->mrd, <=, 600);

		/*
		 *	This is a reasonable value.
		 */
		FR_INTEGER_BOUND_CHECK("limit.max_rtx_timer", inst->mrt, <=, 30);
	}

	FR_INTEGER_BOUND_CHECK("limit.maximum_outstanding", inst->max_outstanding, >=, 1);
	FR_INTEGER_BOUND_CHECK("limit.maximum_outstanding", inst->max_outstanding, <=, 256);

	return 0;
}


/** Private interface for use by proto_detail_file
 *
 */
extern fr_app_io_t proto_detail_work;
fr_app_io_t proto_detail_work = {
	.magic			= RLM_MODULE_INIT,
	.name			= "detail_work",
	.config			= file_listen_config,
	.inst_size		= sizeof(proto_detail_work_t),
	.thread_inst_size	= sizeof(proto_detail_work_thread_t),
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 65536,
	.default_reply_size	= 32,

	.open			= mod_open,
	.close			= mod_close,
	.read			= mod_read,
	.decode			= mod_decode,
	.write			= mod_write,
	.event_list_set		= mod_event_list_set,
	.get_name		= mod_name,
};
