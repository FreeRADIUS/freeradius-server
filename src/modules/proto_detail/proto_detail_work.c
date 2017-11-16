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
 * @file proto_detail_file.c
 * @brief Detail handler for files
 *
 * @copyright 2017 The FreeRADIUS server project.
 * @copyright 2017 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_detail.h"

#include <fcntl.h>
#include <sys/stat.h>

#if 0
/*
 *	When we want detailed debugging here, without detailed server
 *	debugging.
 */
#define MPRINT DEBUG
#else
#define MPRINT DEBUG3
#endif

typedef struct {
	fr_time_t			timestamp;		//!< when we read the entry.
	off_t				done_offset;		//!< where we're tracking the status

	int				id;			//!< for retransmission counters

	uint8_t				*packet;		//!< for retransmissions
	size_t				packet_len;		//!< for retransmissions

	uint32_t			rt;
	uint32_t       			count;			//!< number of retransmission tries

	struct timeval			start;			//!< when we started trying to send
	struct timeval			next;			//!< when it next fires

	fr_event_timer_t const		*ev;			//!< retransmission timer
	fr_dlist_t			entry;			//!< for the retransmission list
} fr_detail_entry_t;

static CONF_PARSER limit_config[] = {
	{ FR_CONF_OFFSET("initial_retransmission_time", FR_TYPE_UINT32, proto_detail_work_t, irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("maximum_retransmission_time", FR_TYPE_UINT32, proto_detail_work_t, mrt), .dflt = STRINGIFY(16) },
	{ FR_CONF_OFFSET("maximum_retransmission_count", FR_TYPE_UINT32, proto_detail_work_t, mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("maximum_retransmission_duration", FR_TYPE_UINT32, proto_detail_work_t, mrd), .dflt = STRINGIFY(30) },
	{ FR_CONF_OFFSET("maximum_outstanding", FR_TYPE_UINT32, proto_detail_work_t, max_outstanding), .dflt = STRINGIFY(1) },
	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER file_listen_config[] = {
	{ FR_CONF_OFFSET("filename.work", FR_TYPE_STRING | FR_TYPE_REQUIRED, proto_detail_work_t, filename_work ) },

	{ FR_CONF_OFFSET("track", FR_TYPE_BOOL, proto_detail_work_t, track_progress ) },

	{ FR_CONF_OFFSET("retransmit", FR_TYPE_BOOL, proto_detail_work_t, retransmit ), .dflt = "yes" },

	{ FR_CONF_POINTER("limit", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) limit_config },
	CONF_PARSER_TERMINATOR
};

/*
 *	All of the decoding is done by proto_detail.c
 */
static int mod_decode(void const *instance, REQUEST *request, UNUSED uint8_t *const data, UNUSED size_t data_len)
{

	proto_detail_work_t const	*inst = talloc_get_type_abort_const(instance, proto_detail_work_t);
	fr_detail_entry_t const		*track = request->async->packet_ctx;
	VALUE_PAIR *vp;

	request->root = &main_config;
	request->client = inst->client;

	request->packet->id = track->id;
	request->reply->id = track->id;
	REQUEST_VERIFY(request);

	vp = fr_pair_make(request->packet, &request->packet->vps,
			  "Packet-Transmit-Counter", NULL, T_OP_EQ);
	if (vp) vp->vp_uint32 = track->count;

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

static ssize_t mod_read(void *instance, void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, uint32_t *priority)
{
	proto_detail_work_t		*inst = talloc_get_type_abort(instance, proto_detail_work_t);

	ssize_t				data_size;
	size_t				packet_len;
	fr_detail_entry_t		*track;
	uint8_t				*partial, *end, *next, *p;
	uint8_t				*stopped_search;
	off_t				done_offset;
	fr_dlist_t			*entry;

	rad_assert(*leftover < buffer_len);
	rad_assert(inst->fd >= 0);

	/*
	 *	Process retransmissions before anything else in the
	 *	file.
	 */
	entry = FR_DLIST_FIRST(inst->list);
	if (entry) {
		track = fr_ptr_to_type(fr_detail_entry_t, entry, entry);

		fr_dlist_remove(&track->entry);

		rad_assert(buffer_len >= track->packet_len);
		memcpy(buffer, track->packet, track->packet_len);

		DEBUG("Retrying packet %d (retransmission %u)",
		      track->id, track->count);
		*packet_ctx = track;
		*recv_time = &track->timestamp;
		*priority = inst->parent->priority;
		return track->packet_len;
	}

	/*
	 *	If we decide that we're closing, ignore everything
	 *	else in the file.  Someone extended the file on us
	 *	without locking it first.  So too bad for them.
	 */
	if (inst->closing) {
		if (inst->track_progress) inst->read_offset = lseek(inst->fd, 0, SEEK_END);
		return 0;
	}

	/*
	 *	Seek to the current read offset.
	 */
	(void) lseek(inst->fd, inst->read_offset, SEEK_SET);

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
	if (!inst->eof) {
		size_t room;

		room = buffer_len - *leftover;

		data_size = read(inst->fd, partial, room);
		if (data_size < 0) return -1;

		MPRINT("GOT %zd bytes", data_size);

		/*
		 *	Remember the read offset, and whether we got EOF.
		 */
		inst->read_offset = lseek(inst->fd, 0, SEEK_CUR);
		inst->eof = (data_size == 0) || (inst->read_offset == inst->file_size) || ((size_t) data_size < room);
		end = partial + data_size;

	} else {
		MPRINT("AT EOF");

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
	rad_assert((buffer + inst->last_search) <= end);

	MPRINT("Starting search from offset %ld", inst->last_search);

	p = buffer + inst->last_search;
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
			DEBUG("Malformed line found at offset %zd",
			      (size_t) (p - buffer) + inst->header_offset);
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
			DEBUG("Malformed line found at offset %zd: %.*s",
			      (size_t) (p - buffer) + inst->header_offset, (int) (end - p), p);
			return -1;
		}

		/*
		 *	Skip the " = ", and go back to the top of the
		 *	loop where we check for the next \n.
		 */
		p += 3;
	}

	inst->last_search = (stopped_search - buffer);

	/*
	 *	If there is a next record, remember how large this
	 *	record is, and update "leftover" bytes.
	 */
	if (next) {
		packet_len = next - buffer;
		*leftover = end - next;

		MPRINT("FOUND next at %zd, leftover is %zd", packet_len, *leftover);

	} else if (!inst->eof) {
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
		      (size_t) inst->header_offset, inst->filename_work);
		DEBUG("Entry size %lu is greater than allowed maximum %u",
		      packet_len, inst->parent->max_packet_size);
	skip_record:
		MPRINT("Skipping record");
		if (next) {
			memmove(buffer, next, (end - next));
			data_size = (end - next);
			*leftover = 0;
			end = buffer + data_size;
			inst->last_search = 0;

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
	end = buffer + packet_len;
	p = buffer;
	done_offset = 0;

	while (p < end) {
		if (*p != '\0') {
			p++;
			continue;
		}

		p++;
		if (p == end) break;

		if (((end - p) >= 5) &&
		    (memcmp(p, "\tDone", 5) == 0)) {
			goto skip_record;
		}

		if (((end - p) > 10) &&
		    (memcmp(p, "\tTimestamp", 10) == 0)) {
			p++;
			done_offset = inst->header_offset + (p - buffer);
		}
	}

	/*
	 *	Allocate the tracking entry.
	 */
	track = talloc_zero(instance, fr_detail_entry_t);
	track->timestamp = fr_time();
	track->id = inst->count++;
	track->rt = inst->irt;

	track->done_offset = done_offset;
	if (inst->retransmit) {
		track->packet = talloc_memdup(track, buffer, packet_len);
		track->packet_len = packet_len;
	}

	/*
	 *	We've read one more packet.
	 */
	inst->header_offset += packet_len;

	*packet_ctx = track;
	*recv_time = &track->timestamp;
	*priority = inst->parent->priority;

done:
	/*
	 *	If we're at EOF, mark us as "closing".
	 */
	if (inst->eof) {
		rad_assert(!inst->closing);
		inst->closing = (*leftover == 0);
	}

	inst->outstanding++;

	/*
	 *	Pause reading until such time as we need more packets.
	 */
	if (!inst->paused && (inst->outstanding >= inst->max_outstanding)) {
		(void) fr_event_filter_update(inst->el, inst->fd, FR_EVENT_FILTER_IO, pause_read);
		inst->paused = true;

		/*
		 *	Back up so that read() knows there's more data.
		 */
		if (*leftover) (void) lseek(inst->fd, inst->read_offset - 1, SEEK_SET);
	}

	/*
	 *	Next time, start searching from the start of the
	 *	buffer.
	 */
	inst->last_search = 0;

	MPRINT("Returning NUM %u - %.*s", inst->outstanding, (int) packet_len, buffer);
	return packet_len;
}


static void work_retransmit(UNUSED fr_event_list_t *el, UNUSED struct timeval *now, void *uctx)
{
	fr_detail_entry_t		*track = talloc_get_type_abort(uctx, fr_detail_entry_t);
	proto_detail_work_t		*inst = talloc_parent(track);

	DEBUG("%s - retransmitting packet %d", inst->name, track->id);
	track->count++;

	fr_dlist_insert_tail(&inst->list, &track->entry);

	if (inst->paused && (inst->outstanding < inst->max_outstanding)) {
		(void) fr_event_filter_update(inst->el, inst->fd, FR_EVENT_FILTER_IO, resume_read);
		inst->paused = false;
	}

	rad_assert(inst->fd >= 0);

	/*
	 *	Seek to the START of the file, so that the FD will
	 *	always return ready.
	 *
	 *	The mod_read() function will take care of seeking to
	 *	the correct read offset.
	 */
	(void) lseek(inst->fd, 0, SEEK_SET);

#ifdef __linux__
	fr_network_listen_read(inst->nr, talloc_parent(inst));
#endif
}

static ssize_t mod_write(void *instance, void *packet_ctx,
			 fr_time_t request_time, uint8_t *buffer, size_t buffer_len)
{
	proto_detail_work_t		*inst = talloc_get_type_abort(instance, proto_detail_work_t);
	fr_detail_entry_t		*track = packet_ctx;

	if (buffer_len < 1) return -1;

	rad_assert(inst->outstanding > 0);
	rad_assert(inst->fd >= 0);

	if (!buffer[0]) {
		struct timeval when, now;

		/*
		 *	Cap at MRC, if required.
		 */
		if (inst->mrc && (track->count >= inst->mrc)) {
			DEBUG("%s - packet %d failed after %u retransmissions",
			      inst->name, track->id, track->count);
			goto fail;
		}

		gettimeofday(&now, NULL);

		if (track->count == 0) {
			track->rt = inst->irt * USEC;
			fr_time_to_timeval(&track->start, request_time);
			track->next = track->start;
			track->next.tv_usec += track->rt;
			track->next.tv_sec += track->next.tv_usec / USEC;
			track->next.tv_usec %= USEC;

		} else {
			/*
			 *	Cap at MRD, if required.
			 */
			if (inst->mrd) {
				struct timeval end;

				end = track->start;
				end.tv_sec += inst->mrd;
				if (timercmp(&now, &end, >=)) {
					DEBUG("%s - packet %d failed after %u seconds",
					      inst->name, track->id, inst->mrd);
					goto fail;
				}
			}

			// @todo - add random delays...

		} /* we're on retransmission N */

		when.tv_sec = track->rt / USEC;
		when.tv_usec = track->rt % USEC;

		DEBUG("%s - packet %d failed during processing.  Will retransmit in %d.%06ds",
		      inst->name, track->id, (int) when.tv_sec, (int) when.tv_usec);

		fr_timeval_add(&when, &now, &when);

		if (fr_event_timer_insert(inst, inst->el, &track->ev, &when, work_retransmit, track) < 0) {
			ERROR("%s - Failed inserting retransmission timeout", inst->name);
		fail:
			if (inst->track_progress && (track->done_offset > 0)) goto mark_done;
			goto free_track;
		}

		if (!inst->paused && (inst->outstanding >= inst->max_outstanding)) {
			(void) fr_event_filter_update(inst->el, inst->fd, FR_EVENT_FILTER_IO, pause_read);
			inst->paused = true;
		}
		return 1;

	} else if (inst->track_progress && (track->done_offset > 0)) {
	mark_done:
		/*
		 *	Seek to the entry, mark it as done, and then seek to
		 *	the point in the file where we were reading from.
		 */
		(void) lseek(inst->fd, track->done_offset, SEEK_SET);
		(void) write(inst->fd, "Done", 4);
		(void) lseek(inst->fd, inst->read_offset, SEEK_SET);
	}

free_track:
	inst->outstanding--;

	/*
	 *	If we need to read some more packet, let's do so.
	 */
	if (inst->paused && (inst->outstanding < inst->max_outstanding)) {
		(void) fr_event_filter_update(inst->el, inst->fd, FR_EVENT_FILTER_IO, resume_read);
		inst->paused = false;
	}

	/*
	 *	@todo - add a used / free pool for these
	 */
	talloc_free(track);

	/*
	 *	Close the socket if we're at EOF, and there are no
	 *	outstanding replies to deal with.
	 */
	if (inst->closing && !inst->outstanding) {
		return 0;
	}

	return buffer_len;
}

#ifdef NOTE_REVOKE
static void mod_revoke(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	proto_detail_work_t *inst = talloc_get_type_abort(uctx, proto_detail_work_t);

	/*
	 *	The underlying file system is gone.  Stop reading the
	 *	file, destroy all of the IO handlers, and delete
	 */
	fr_event_fd_delete(el, fd, FR_EVENT_FILTER_VNODE);
	fr_event_fd_delete(el, fd, FR_EVENT_FILTER_IO);

	DEBUG("Detail worker %s had file system unmounted.  Stopping.", inst->name);
	talloc_free(inst);
}
#endif

/** Open a detail listener
 *
 * @param[in] instance of the detail worker.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_open(void *instance)
{
	proto_detail_work_t *inst = talloc_get_type_abort(instance, proto_detail_work_t);

	/*
	 *	Open the file if we haven't already been given one.
	 */
	if (inst->fd < 0) {
		inst->fd = open(inst->filename_work, inst->mode);
		if (inst->fd < 0) {
			cf_log_err(inst->cs, "Failed opening %s: %s", inst->filename_work, fr_syserror(errno));
			return -1;
		}
	}

	/*
	 *	If we're tracking progress, learn where the EOF is.
	 */
	if (inst->track_progress) {
		struct stat buf;

		if (fstat(inst->fd, &buf) < 0) {
			cf_log_err(inst->cs, "Failed examining %s: %s", inst->filename_work, fr_syserror(errno));
			return -1;
		}

		inst->file_size = buf.st_size;
	} else {
		/*
		 *	Avoid triggering erroneous EOF.
		 */
		inst->file_size = 1;
	}

	rad_assert(inst->name == NULL);
	rad_assert(inst->filename_work != NULL);
	inst->name = talloc_typed_asprintf(inst, "detail working file %s", inst->filename_work);

	DEBUG("Listening on %s bound to virtual server %s",
	      inst->name, cf_section_name2(inst->parent->server_cs));

	return 0;
}


/** Close  a detail listener
 *
 * @param[in] instance of the detail worker.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_close(void *instance)
{
	proto_detail_work_t *inst = talloc_get_type_abort(instance, proto_detail_work_t);

	PTHREAD_MUTEX_LOCK(&inst->parent->worker_mutex);
	inst->parent->work_io_instance = NULL;
	inst->parent->num_workers--;
	PTHREAD_MUTEX_UNLOCK(&inst->parent->worker_mutex);

	DEBUG("Detail worker at EOF. Closing and deleting %s", inst->name);
	unlink(inst->filename_work);
	close(inst->fd);
	inst->fd = -1;

	if (inst->free_on_close) {
		talloc_free(talloc_parent(inst));
	}

	return 0;
}

/** Get the file descriptor for this IO instance
 *
 * @param[in] instance of the detail worker
 * @return the file descriptor
 */
static int mod_fd(void const *instance)
{
	proto_detail_work_t const *inst = talloc_get_type_abort_const(instance, proto_detail_work_t);

	return inst->fd;
}


/** Set the event list for a new IO instance
 *
 * @param[in] instance of the detail worker
 * @param[in] el the event list
 * @param[in] nr context from the network side
 */
static void mod_event_list_set(void *instance, fr_event_list_t *el, void *nr)
{
	proto_detail_work_t *inst = talloc_get_type_abort(instance, proto_detail_work_t);

#ifdef NOTE_REVOKE
	fr_event_vnode_func_t funcs;

	memset(&funcs, 0, sizeof(funcs));
	funcs.revoke = mod_revoke;

	if (fr_event_filter_insert(inst, el, inst->fd, FR_EVENT_FILTER_VNODE, &funcs, NULL, inst) < 0) {
		WARN("Failed to add event watching for unmounted file system");
	}
#endif

	inst->el = el;
	inst->nr = nr;
}


static int mod_instantiate(void *instance, UNUSED CONF_SECTION *cs)
{
	proto_detail_work_t *inst = talloc_get_type_abort(instance, proto_detail_work_t);
	RADCLIENT *client;

	FR_DLIST_INIT(inst->list);

	client = inst->client = talloc_zero(inst, RADCLIENT);
	if (!inst->client) return 0;

	client->ipaddr.af = AF_INET;
	client->ipaddr.addr.v4.s_addr = htonl(INADDR_NONE);
	client->src_ipaddr = client->ipaddr;

	client->longname = client->shortname = client->secret = inst->filename_work;
	client->nas_type = talloc_strdup(client, "other");

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_detail_work_t	*inst = talloc_get_type_abort(instance, proto_detail_work_t);
	dl_instance_t const	*dl_inst;

	/*
	 *	Find the dl_instance_t holding our instance data
	 *	so we can find out what the parent of our instance
	 *	was.
	 */
	dl_inst = dl_instance_find(instance);
	rad_assert(dl_inst);

	inst->parent = talloc_get_type_abort(dl_inst->parent->data, proto_detail_t);
	inst->cs = cs;
	inst->fd = -1;

	if (inst->track_progress) {
		inst->mode = O_RDWR;
	} else {
		inst->mode = O_RDONLY;
	}

	if (inst->retransmit) {
		FR_INTEGER_BOUND_CHECK("limit.initial_retransmission_time", inst->irt, >=, 1);
		FR_INTEGER_BOUND_CHECK("limit.initial_retransmission_time", inst->irt, <=, 60);

		/*
		 *	If you need more than this, just set it to
		 *	"0", and check Packet-Transmit-Count manually.
		 */
		FR_INTEGER_BOUND_CHECK("limit.maximum_retransmission_count", inst->mrc, <=, 20);
		FR_INTEGER_BOUND_CHECK("limit.maximum_retransmission_duration", inst->mrd, <=, 600);

		/*
		 *	This is a reasonable value.
		 */
		FR_INTEGER_BOUND_CHECK("limit.maximum_retransmission_timer", inst->mrt, <=, 30);
	}

	FR_INTEGER_BOUND_CHECK("limit.maximum_outstanding", inst->max_outstanding, >=, 1);
	FR_INTEGER_BOUND_CHECK("limit.maximum_outstanding", inst->max_outstanding, <=, 256);

	return 0;
}

static int mod_detach(void *instance)
{
	proto_detail_work_t	*inst = talloc_get_type_abort(instance, proto_detail_work_t);

	if (inst->fd >= 0) close(inst->fd);

	/*
	 *	One less worker...  we check for "0" because of the
	 *	hacks in proto_detail which let us start up with
	 *	"transport = work" for debugging purposes.
	 */
	PTHREAD_MUTEX_LOCK(&inst->parent->worker_mutex);
	if (inst->parent->num_workers > 0) inst->parent->num_workers--;
	PTHREAD_MUTEX_UNLOCK(&inst->parent->worker_mutex);

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
	.detach			= mod_detach,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 65536,
	.default_reply_size	= 32,

	.open			= mod_open,
	.close			= mod_close,
	.read			= mod_read,
	.decode			= mod_decode,
	.write			= mod_write,
	.fd			= mod_fd,
	.event_list_set		= mod_event_list_set,
};
