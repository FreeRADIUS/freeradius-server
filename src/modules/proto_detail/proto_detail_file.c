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
#include <freeradius-devel/udp.h>
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
} fr_detail_entry_t;

typedef struct {
	CONF_SECTION			*cs;			//!< our configuration section
	proto_detail_t	const		*parent;		//!< The module that spawned us!
	char const			*name;			//!< debug name for printing

	int				fd;			//!< file descriptor

	fr_event_list_t			*el;			//!< for various timers
	fr_schedule_t			*sc;			//!< the scheduler, where we insert new readers

	char const			*filename;     		//!< file name, usually with wildcards
	char const			*filename_work;		//!< work file name

	bool				vnode;			//!< are we the vnode instance, or the filename_work instance?
	bool				eof;			//!< are we at EOF on reading?
	bool				closing;		//!< we should be closing the file

	int				outstanding;		//!< number of outstanding records;

	size_t				last_search;		//!< where we last searched in the buffer
								//!< MUST be offset, as the buffers can change.

	off_t				file_size;		//!< size of the file
	off_t				header_offset;		//!< offset of the current header we're reading
	off_t				read_offset;		//!< where we're reading from in filename_work
} proto_detail_file_t;

static const CONF_PARSER file_listen_config[] = {
//	{ FR_CONF_OFFSET("filename", FR_TYPE_STRING | FR_TYPE_REQUIRED, proto_detail_file_t, filename ) },

	{ FR_CONF_OFFSET("filename.work", FR_TYPE_STRING | FR_TYPE_REQUIRED, proto_detail_file_t, filename_work ) },

	CONF_PARSER_TERMINATOR
};


static int mod_decode(void const *instance, REQUEST *request, UNUSED uint8_t *const data, UNUSED size_t data_len)
{

	proto_detail_file_t const     	*inst = talloc_get_type_abort_const(instance, proto_detail_file_t);
//	fr_detail_entry_t const			*track = request->async->packet_ctx;

	request->root = &main_config;
	request->packet->id = inst->outstanding;
	request->reply->id = inst->outstanding;
	REQUEST_VERIFY(request);

	return 0;
}

static ssize_t mod_read(void *instance, void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, uint32_t *priority)
{
	proto_detail_file_t		*inst = talloc_get_type_abort(instance, proto_detail_file_t);

	ssize_t				data_size;
	size_t				packet_len;
	fr_detail_entry_t		*track;
	uint8_t				*partial, *end, *next, *p;
	uint8_t				*stopped_search;
	off_t				done_offset;

	rad_assert(*leftover < buffer_len);

	/*
	 *	If we decide that we're closing, ignore everything
	 *	else in the file.  Someone extended the file on us
	 *	without locking it first.  So too bad for them.
	 */
	if (inst->closing) {
		inst->read_offset = lseek(inst->fd, 0, SEEK_END);
		return 0;
	}

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
		inst->eof = (data_size == 0) || (inst->read_offset == inst->file_size);
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
			/*
			 *	@todo - be smart, and eat multiple
			 *	records until we find one which isn't
			 *	done.
			 */
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
	track = talloc(instance, fr_detail_entry_t);
	track->timestamp = fr_time();

	track->done_offset = done_offset;

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
	 *	Next time, start searching from the start of the
	 *	buffer.
	 */
	inst->last_search = 0;

	MPRINT("Returning NUM %d - %.*s", inst->outstanding, (int) packet_len, buffer);
	return packet_len;
}

static ssize_t mod_write(void *instance, void *packet_ctx,
			 UNUSED fr_time_t request_time, uint8_t *buffer, size_t buffer_len)
{
	proto_detail_file_t		*inst = talloc_get_type_abort(instance, proto_detail_file_t);
	fr_detail_entry_t		*track = packet_ctx;

	if (buffer_len < 1) return -1;

	rad_assert(inst->outstanding > 0);
	inst->outstanding--;

	if (buffer[0] == 0) {
		DEBUG("Got Do-Not-Respond, not writing reply");

	} else if (track->done_offset > 0) {
		/*
		 *	Seek to the entry, mark it as done, and then seek to
		 *	the point in the file where we were reading from.
		 */
		(void) lseek(inst->fd, track->done_offset, SEEK_SET);
		(void) write(inst->fd, "Done", 4);
		(void) lseek(inst->fd, inst->read_offset, SEEK_SET);
	}

	/*
	 *	@todo - add a used / free pool for these
	 */
	talloc_free(track);

	/*
	 *	@todo - close the socket if we're at EOF, and outstanding == 0?
	 */
	if (inst->closing && !inst->outstanding) {
		DEBUG("EOF. Closing %s", inst->name);
		return 0;
	}

	return buffer_len;
}

/** Open a UDP listener for RADIUS
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_open(void *instance)
{
	proto_detail_file_t *inst = talloc_get_type_abort(instance, proto_detail_file_t);
	struct stat buf;

	inst->fd = open(inst->filename_work, O_RDWR);
	if (inst->fd < 0) {
		cf_log_err(inst->cs, "Failed opening %s: %s", inst->filename_work, fr_syserror(errno));
		return -1;
	}

	if (fstat(inst->fd, &buf) < 0) {
		cf_log_err(inst->cs, "Failed examining %s: %s", inst->filename_work, fr_syserror(errno));
		return -1;
	}

	rad_assert(inst->name == NULL);
	inst->name = talloc_asprintf(inst, "detail working file %s", inst->filename_work);
	inst->file_size = buf.st_size;

	DEBUG("Listening on %s bound to virtual server %s",
	      inst->name, cf_section_name2(inst->parent->server_cs));

	return 0;
}

/** Get the file descriptor for this socket.
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @return the file descriptor
 */
static int mod_fd(void const *instance)
{
	proto_detail_file_t const *inst = talloc_get_type_abort_const(instance, proto_detail_file_t);

	return inst->fd;
}


/** Set the event list for a new socket
 *
 * @param[in] instance of the RADIUS UDP I/O path.
 * @param[in] el the event list
 */
static void mod_event_list_set(void *instance, fr_event_list_t *el)
{
	proto_detail_file_t *inst;

	memcpy(&inst, &instance, sizeof(inst)); /* const issues */

	inst = talloc_get_type_abort(instance, proto_detail_file_t);

	inst->el = el;
}


static int mod_instantiate(UNUSED void *instance, UNUSED CONF_SECTION *cs)
{
//	proto_detail_file_t *inst = talloc_get_type_abort(instance, proto_detail_file_t);


	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_detail_file_t	*inst = talloc_get_type_abort(instance, proto_detail_file_t);
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

	return 0;
}

static int mod_detach(void *instance)
{
	proto_detail_file_t	*inst = talloc_get_type_abort(instance, proto_detail_file_t);

	/*
	 *	@todo - have our OWN event loop for timers, and a
	 *	"copy timer from -> to, which means we only have to
	 *	delete our child event loop from the parent on close.
	 */

	close(inst->fd);
	return 0;
}


/** Private interface for use by proto_detail_file
 *
 */
extern fr_app_io_t proto_detail_file;
fr_app_io_t proto_detail_file = {
	.magic			= RLM_MODULE_INIT,
	.name			= "detail_file",
	.config			= file_listen_config,
	.inst_size		= sizeof(proto_detail_file_t),
	.detach			= mod_detach,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 65536,
	.default_reply_size	= 32,

	.open			= mod_open,
	.read			= mod_read,
	.decode			= mod_decode,
	.write			= mod_write,
	.fd			= mod_fd,
	.event_list_set		= mod_event_list_set,
};
