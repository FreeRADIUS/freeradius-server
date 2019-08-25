/*
 *	rlm_radius state machine
 */
static void mod_radius_fd_idle(rlm_radius_connection_t *c);

static void mod_radius_fd_active(rlm_radius_connection_t *c);

static void mod_radius_conn_error(UNUSED fr_event_list_t *el, int sock, UNUSED int flags, int fd_errno, void *uctx);

static int CC_HINT(nonnull) mod_add(rlm_radius_t *inst, rlm_radius_connection_t *c, REQUEST *request);


#ifndef USEC
#define USEC (1000000)
#endif

// @todo - pass in REQUEST, or maybe request_io_ctx, so we can store these numbers in the rlm_link_t?
bool rlm_radius_update_delay(struct timeval *start, uint32_t *rt, uint32_t *count, int code, void *client_io_ctx, struct timeval *now)
{
	uint32_t delay, frac;
	rlm_radius_retry_t const *retry;
	rlm_radius_thread_t *t;

	(void) talloc_get_type_abort(client_io_ctx, rlm_radius_client_io_ctx_t);

	t = talloc_parent(client_io_ctx);

	(void) talloc_get_type_abort(t, rlm_radius_thread_t);

	rad_assert(code > 0);
	rad_assert(code < FR_MAX_PACKET_CODE);
	rad_assert(t->inst->packets[code].irt != 0);

	retry = &t->inst->packets[code];

	/*
	 *	First packet: use IRT.
	 */
	if (!*rt) {
		gettimeofday(start, NULL);
		*rt = retry->irt * USEC;
		*count = 1;
		return true;
	}

	/*
	 *	Later packets, do more stuff.
	 */
	(*count)++;

	/*
	 *	We retried too many times.  Fail.
	 */
	if (retry->mrc && (*count > retry->mrc)) {
		return false;
	}

	/*
	 *	Cap delay at MRD
	 */
	if (now && retry->mrd) {
		struct timeval end;

		end = *start;
		end.tv_sec += retry->mrd;

		if (timercmp(now, &end, >=)) {
			return false;
		}
	}

	/*
	 *	RFC 5080 Section 2.2.1
	 *
	 *	RT = 2*RTprev + RAND*RTprev
	 *	   = 1.9 * RTprev + rand(0,.2) * RTprev
	 *	   = 1.9 * RTprev + rand(0,1) * (RTprev / 5)
	 */
	delay = fr_rand();
	delay ^= (delay >> 16);
	delay &= 0xffff;
	frac = *rt / 5;
	delay = ((frac >> 16) * delay) + (((frac & 0xffff) * delay) >> 16);

	delay += (2 * *rt) - (*rt / 10);

	/*
	 *	Cap delay at MRT
	 */
	if (retry->mrt && (delay > (retry->mrt * USEC))) {
		int mrt_usec = retry->mrt * USEC;

		/*
		 *	delay = MRT + RAND * MRT
		 *	      = 0.9 MRT + rand(0,.2)  * MRT
		 */
		delay = fr_rand();
		delay ^= (delay >> 15);
		delay &= 0x1ffff;
		delay = ((mrt_usec >> 16) * delay) + (((mrt_usec & 0xffff) * delay) >> 16);
		delay += mrt_usec - (mrt_usec / 10);
	}

	*rt = delay;

	return true;
}




/*
 *	So transports can calculate retransmission timers.
 */
bool rlm_radius_update_delay(struct timeval *start, uint32_t *rt, uint32_t *count, int code, void *client_io_ctx, struct timeval *now);

typedef struct rlm_radius_client_io_ctx_t rlm_radius_client_io_ctx_t;



static int mod_write(REQUEST *request, void *request_ctx, void *io_ctx)
{
	rlm_radius_client_io_ctx_t *io = talloc_get_type_abort(io_ctx, rlm_radius_client_io_ctx_t);
	request_ctx_t *track = (request_ctx_t *) request_ctx; /* not talloc'd */
	ssize_t packet_len, data_size;
	rlm_radius_request_t *rr;

	rad_assert(request->packet->code > 0);
	rad_assert(request->packet->code < FR_MAX_PACKET_CODE);

	/*
	 *	Create the tracking table if it doesn't already exist.
	 *
	 *	@todo - move this into the "init" routine?  where was can examine
	 *	        the rlm_radius_t, and create the relevant data structures.
	 */
	if (!io->id[request->packet->code]) {
		io->id[request->packet->code] = rr_track_create(io_ctx);
		if (!io->id[request->packet->code]) {
			RDEBUG("Failed creating tracking table for code %d", request->packet->code);
			return -1;
		}
	}

	/*
	 *	Allocate an ID
	 */
	rr = rr_track_alloc(io->id[request->packet->code], request, request->packet->code, io, request_ctx);
	if (!rr) {
		RDEBUG("Failed allocating packet ID for code %d", request->packet->code);
		return -1;
	}

	packet_len = fr_radius_encode(io->buffer, io->buflen, NULL, io->inst->secret, strlen(io->inst->secret),
				      rr->code, rr->id, request->packet->vps);
	if (packet_len < 0) {
		RDEBUG("Failed encoding packet: %s", fr_strerror());

		// @todo - distinguish write errors from encode errors?
		return -1;
	}

	data_size = udp_send(io->fd, io->buffer, packet_len, 0,
			     &io->dst_ipaddr, io->dst_port,
			     0,	/* if_index */
			     &io->src_ipaddr, io->src_port);

	// @todo - put the packet into an RB tree, too, so we can find replies...
	memcpy(&track->header, io->buffer, 20);

	if (data_size < packet_len) {
		rad_assert(0 == 1);
	}

	return 1;
}

/** Get a printable name for the socket
 *
 */
static char const *mod_get_name(TALLOC_CTX *ctx, void *io_ctx)
{
	rlm_radius_client_io_ctx_t *io = talloc_get_type_abort(io_ctx, rlm_radius_client_io_ctx_t);
	char src_buf[FR_IPADDR_STRLEN], dst_buf[FR_IPADDR_STRLEN];

	fr_inet_ntop(dst_buf, sizeof(dst_buf), &io->dst_ipaddr);

	// @todo - make sure to get the local port number we're bound to

	if (fr_ipaddr_is_inaddr_any(&io->inst->src_ipaddr)) {
		return talloc_asprintf(ctx, "home server %s port %u", dst_buf, io->dst_port);
	}

	fr_inet_ntop(src_buf, sizeof(src_buf), &io->inst->src_ipaddr);
	return talloc_asprintf(ctx, "from %s to home server %s port %u", src_buf, dst_buf, io->dst_port);
}


/** Shutdown/close a file descriptor
 *
 */
static void mod_close(int fd, void *io_ctx)
{
	rlm_radius_client_io_ctx_t *io = talloc_get_type_abort(io_ctx, rlm_radius_client_io_ctx_t);

	if (shutdown(fd, SHUT_RDWR) < 0) DEBUG3("Shutdown on socket (%i) failed: %s", fd, fr_syserror(errno));
	if (close(fd) < 0) DEBUG3("Closing socket (%i) failed: %s", fd, fr_syserror(errno));

	io->fd = -1;
}

/** Do more setup once the connection has been opened
 *
 */
static fr_connection_state_t mod_open(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED void *io_ctx)
{
//	rlm_radius_client_io_ctx_t_t *io = talloc_get_type_abort(io_ctx, rlm_radius_client_io_ctx_t);

	// @todo - create the initial Status-Server for negotiation and send that

	return FR_CONNECTION_STATE_CONNECTED;
}


/** Initialize the connection.
 *
 */
static fr_connection_state_t mod_init(int *fd_out, void *io_ctx, void const *uctx)
{
	int fd;
	rlm_radius_client_io_ctx_t *io = talloc_get_type_abort(io_ctx, rlm_radius_client_io_ctx_t);
	rlm_radius_udp_t const *inst = talloc_get_type_abort(uctx, rlm_radius_udp_t);

	io->inst = inst;

	io->max_packet_size = inst->max_packet_size;
	io->buflen = io->max_packet_size;
	io->buffer = talloc_array(io, uint8_t, io->buflen);

	if (!io->buffer) {
		return FR_CONNECTION_STATE_FAILED;
	}

	io->dst_ipaddr = inst->dst_ipaddr;
	io->dst_port = inst->dst_port;
	io->src_ipaddr = inst->src_ipaddr;
	io->src_port = 0;

	/*
	 *	Open the outgoing socket.
	 *
	 *	@todo - pass src_ipaddr, and remove later call to fr_socket_bind()
	 *	which does return the src_port, but doesn't set the "don't fragment" bit.
	 */
	fd = fr_socket_client_udp(&io->src_ipaddr, &io->dst_ipaddr, io->dst_port, true);
	if (fd < 0) {
		DEBUG("Failed opening RADIUS client UDP socket: %s", fr_strerror());
		return FR_CONNECTION_STATE_FAILED;
	}

#if 0
	if (fr_socket_bind(fd, &io->src_ipaddr, &io->src_port, inst->interface) < 0) {
		DEBUG("Failed binding RADIUS client UDP socket: %s FD %d %pV port %u interface %s", fr_strerror(), fd, fr_box_ipaddr(io->src_ipaddr),
			io->src_port, inst->interface);
		return FR_CONNECTION_STATE_FAILED;
	}
#endif

	// @todo - set recv_buff and send_buff socket options

	io->fd = fd;

	// @todo - initialize the tracking memory, etc.

	*fd_out = fd;

	return FR_CONNECTION_STATE_CONNECTING;
}
