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
 * @file rlm_icmp.c
 * @brief Send ICMP echo requests.
 *
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#define LOG_PREFIX mctx->inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/cap.h>
#include <freeradius-devel/util/debug.h>

#include <fcntl.h>
#include <unistd.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct {
	char const	*interface;
	fr_time_delta_t	timeout;
	fr_ipaddr_t	src_ipaddr;
} rlm_icmp_t;

typedef struct {
	fr_rb_tree_t	*tree;
	int		fd;

	uint32_t	data;
	uint16_t	ident;
	uint32_t	counter;

	fr_type_t	ipaddr_type;
	uint8_t		request_type;
	uint8_t		reply_type;
} rlm_icmp_thread_t;

typedef struct {
	fr_rb_node_t	node;			//!< Entry in the outstanding list of echo requests.
	bool		replied;		//!< do we have a reply?
	fr_value_box_t	*ip;			//!< the IP we're pinging
	uint32_t	counter;	       	//!< for pinging the same IP multiple times
	request_t	*request;		//!< so it can be resumed when we get the echo reply
} rlm_icmp_echo_t;

typedef struct CC_HINT(__packed__) {
	uint8_t		type;
	uint8_t		code;
	uint16_t	checksum;
	uint16_t	ident;
	uint16_t	sequence;
	uint32_t	data;			//!< another 32-bits of randomness
	uint32_t	counter;		//!< so that requests for the same IP are unique
} icmp_header_t;

#define ICMP_ECHOREPLY		(0)
#define ICMP_ECHOREQUEST	(8)

#define ICMPV6_ECHOREQUEST	(128)
#define ICMPV6_ECHOREPLY	(129)

/*
 *	Calculate the ICMP portion of the checksum
 */
static uint16_t icmp_checksum(uint8_t *data, size_t data_len, uint16_t checksum)
{
	uint8_t *p, *end;
	uint64_t sum;

	sum = checksum;
	data_len &= ~((size_t) 1); /* ensure it's always 16-bit aligned */

	p = data;
	end = data + data_len;
	while (p < end) {
		sum += fr_nbo_to_uint16(p);	 /* type / code */
		p += 2;
	}

	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

	return ((uint16_t) ~sum);
}

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, rlm_icmp_t, interface) },
	{ FR_CONF_OFFSET("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, rlm_icmp_t, src_ipaddr) },
	{ FR_CONF_OFFSET("timeout", FR_TYPE_TIME_DELTA, rlm_icmp_t, timeout), .dflt = "1s" },
	CONF_PARSER_TERMINATOR
};

static xlat_action_t xlat_icmp_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      xlat_ctx_t const *xctx,
				      UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	rlm_icmp_echo_t *echo = talloc_get_type_abort(xctx->rctx, rlm_icmp_echo_t);
	rlm_icmp_thread_t *t = talloc_get_type_abort(xctx->mctx->thread, rlm_icmp_thread_t);
	fr_value_box_t	*vb;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL, false));
	vb->vb_bool = echo->replied;

	(void) fr_rb_delete(t->tree, echo);
	talloc_free(echo);

	fr_dcursor_insert(out, vb);

	return XLAT_ACTION_DONE;
}

static void xlat_icmp_cancel(xlat_ctx_t const *xctx, request_t *request, fr_state_signal_t action)
{
	rlm_icmp_echo_t *echo = talloc_get_type_abort(xctx->rctx, rlm_icmp_echo_t);
	rlm_icmp_thread_t *t = talloc_get_type_abort(xctx->mctx->thread, rlm_icmp_thread_t);

	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Cancelling ICMP request for %pV (counter=%d)", echo->ip, echo->counter);

	(void) fr_rb_delete(t->tree, echo);
	talloc_free(echo);
}


static void _xlat_icmp_timeout(xlat_ctx_t const *xctx, request_t *request, UNUSED fr_time_t fired)
{
	rlm_icmp_echo_t *echo = talloc_get_type_abort(xctx->rctx, rlm_icmp_echo_t);

	if (echo->replied) return; /* it MUST already have been marked resumable. */

	RDEBUG2("No response to ICMP request for %pV (counter=%d)", echo->ip, echo->counter);

	unlang_interpret_mark_runnable(request);
}

static xlat_arg_parser_t const xlat_icmp_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Xlat to ping a specified ip address
 *
 * Example (ping 192.0.2.1):
@verbatim
"%(icmp:192.0.2.1)"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_icmp(TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
			       xlat_ctx_t const *xctx,
			       request_t *request, fr_value_box_list_t *in)
{
	rlm_icmp_t		*inst = talloc_get_type_abort(xctx->mctx->inst->data, rlm_icmp_t);
	rlm_icmp_thread_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_icmp_thread_t);
	rlm_icmp_echo_t		*echo;
	icmp_header_t		icmp;
	uint16_t		checksum;
	ssize_t			rcode;
	socklen_t      		salen;
	struct sockaddr_storage	dst;
	fr_value_box_t		*in_head = fr_dlist_head(in);

	/*
	 *	If there's no input, do we can't ping anything.
	 */
	if (!in_head) return XLAT_ACTION_FAIL;

	if (fr_value_box_cast_in_place(ctx, in_head, t->ipaddr_type, NULL) < 0) {
		RPEDEBUG("Failed casting result to IP address");
		return XLAT_ACTION_FAIL;
	}

	MEM(echo = talloc_zero(ctx, rlm_icmp_echo_t));
	echo->ip = in_head;
	echo->request = request;
	echo->counter = t->counter++;

	/*
	 *	Add the IP to the local tracking heap, so that the IO
	 *	functions can find it.
	 *
	 *	This insert will never fail, because of the unique
	 *	counter above.
	 */
	if (!fr_rb_insert(t->tree, echo)) {
		RPEDEBUG("Failed inserting IP into tracking table");
		talloc_free(echo);
		return XLAT_ACTION_FAIL;
	}

	if (unlang_xlat_timeout_add(request, _xlat_icmp_timeout, echo,
				    fr_time_add(fr_time(), inst->timeout)) < 0) {
		RPEDEBUG("Failed adding timeout");
		(void) fr_rb_delete(t->tree, echo);
		talloc_free(echo);
		return XLAT_ACTION_FAIL;
	}

	RDEBUG("Sending ICMP request to %pV (counter=%d)", echo->ip, echo->counter);

	icmp = (icmp_header_t) {
		.type = t->request_type,
		.ident = t->ident,
		.data = t->data,
		.counter = echo->counter
	};

	(void) fr_ipaddr_to_sockaddr(&dst, &salen, &echo->ip->vb_ip, 0);

	/*
	 *	Calculate the checksum
	 */
	checksum = 0;

	/*
	 *	Start off with the IPv6 pseudo-header checksum
	 */
	if (t->ipaddr_type == FR_TYPE_IPV6_ADDR) {
		checksum = fr_ip6_pesudo_header_checksum(&inst->src_ipaddr.addr.v6, &echo->ip->vb_ip.addr.v6,
							 sizeof(ip_header6_t) + sizeof(icmp), IPPROTO_ICMPV6);
	}

	/*
	 *	Followed by checksumming the actual ICMP packet.
	 */
	icmp.checksum = htons(icmp_checksum((uint8_t *) &icmp, sizeof(icmp), checksum));

	rcode = sendto(t->fd, &icmp, sizeof(icmp), 0, (struct sockaddr *) &dst, salen);
	if (rcode < 0) {
		REDEBUG("Failed sending ICMP request to %pV: %s", echo->ip, fr_syserror(errno));
		(void) fr_rb_delete(t->tree, echo);
		talloc_free(echo);
		return XLAT_ACTION_FAIL;
	}

	if ((size_t) rcode < sizeof(icmp)) {
		REDEBUG("Failed sending entire ICMP packet");
		(void) fr_rb_delete(t->tree, echo);
		talloc_free(echo);
		return XLAT_ACTION_FAIL;
	}

	return unlang_xlat_yield(request, xlat_icmp_resume, xlat_icmp_cancel, echo);
}

static int8_t echo_cmp(void const *one, void const *two)
{
	rlm_icmp_echo_t const *a = one;
	rlm_icmp_echo_t const *b = two;

	/*
	 *	No need to check IP, because "counter" is unique for each packet.
	 */
	return CMP(a->counter, b->counter);
}

static void mod_icmp_read(UNUSED fr_event_list_t *el, UNUSED int sockfd, UNUSED int flags, void *uctx)
{
	module_thread_inst_ctx_t const	*mctx = talloc_get_type_abort(uctx, module_thread_inst_ctx_t);
	rlm_icmp_thread_t		*t = talloc_get_type_abort(mctx->thread, rlm_icmp_thread_t);

	ssize_t			len;
	icmp_header_t		*icmp;
	rlm_icmp_echo_t		my_echo, *echo;
	uint64_t		buffer[256];

	len = read(t->fd, (char *) buffer, sizeof(buffer));
	if (len <= 0) return;

	HEXDUMP4((uint8_t const *)buffer, len, "received icmp packet ");

	/*
	 *	Ignore packets if we haven't sent any requests.
	 */
	if (fr_rb_num_elements(t->tree) == 0) {
		return;
	}

	// buffer is actually the IP header + the ICMP packet
	if (t->ipaddr_type == FR_TYPE_IPV4_ADDR) {
		ip_header_t *ip = (ip_header_t *) buffer;

		if (IP_V(ip) != 4) {
			return;
		}

		if ((IP_HL(ip) + sizeof(*icmp)) > sizeof(buffer)) {
			return;
		}

		icmp = (icmp_header_t *) (((uint8_t *) buffer) + IP_HL(ip));
	} else if (t->ipaddr_type == FR_TYPE_IPV6_ADDR) {
		/*
		 *	Outgoing packets automatically have an IPv6 header prepended to them
		 *	(based on the destination address).  ICMPv6 pseudo header checksum field
		 *	(icmp6_cksum) will be filled automatically by the kernel. Incoming packets
		 *	are received without the IPv6 header nor IPv6 extension headers.
		 *
		 *	Note that this behavior is opposite from IPv4
		 *	raw sockets and ICMPv4 sockets.
		 *
		 *	Therefore, we don't have ip6 headers here. Only the icmp6 packet.
		 */
		icmp = (icmp_header_t *) (((uint8_t *) buffer));
	} else {
		/*
		 *	No idea.  Ignore it.
		 */
		return;
	}

	/*
	 *	Ignore packets which aren't an echo reply, or which
	 *	weren't for us.  This is done *before* looking packets
	 *	up in the rbtree, as these checks ensure that the
	 *	packet is for this specific thread.
	 */
	if ((icmp->type != t->reply_type) ||
	    (icmp->ident != t->ident) || (icmp->data != t->data)) {
		return;
	}

	/*
	 *	Look up the packet by the fields which determine *our* ICMP packets.
	 */
	my_echo.counter = icmp->counter;
	echo = fr_rb_find(t->tree, &my_echo);
	if (!echo) {
		DEBUG("Can't find packet counter=%d in tree", icmp->counter);
		return;
	}

	(void) fr_rb_delete(t->tree, echo);

	/*
	 *	We have a reply!
	 */
	echo->replied = true;
	unlang_interpret_mark_runnable(echo->request);
}

static void mod_icmp_error(fr_event_list_t *el, UNUSED int sockfd, UNUSED int flags,
			   UNUSED int fd_errno, void *uctx)
{
	module_ctx_t const	*mctx = talloc_get_type_abort(uctx, module_ctx_t);
	rlm_icmp_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_icmp_thread_t);

	ERROR("Failed reading from ICMP socket - Closing it");

	(void) fr_event_fd_delete(el, t->fd, FR_EVENT_FILTER_IO);
	close(t->fd);
	t->fd = -1;
}

/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	module_thread_inst_ctx_t	*our_mctx;
	rlm_icmp_t			*inst = talloc_get_type_abort(mctx->inst->data, rlm_icmp_t);
	rlm_icmp_thread_t		*t = talloc_get_type_abort(mctx->thread, rlm_icmp_thread_t);
	fr_ipaddr_t			ipaddr, *src;

	int fd, af, proto;

	/*
	 *	Create a copy of the mctx on the heap that we can
	 *	pass as the uctx to the io functions.
	 */
	MEM(our_mctx = talloc_zero(t, module_thread_inst_ctx_t));
	memcpy(our_mctx, mctx, sizeof(*our_mctx));

	MEM(t->tree = fr_rb_inline_alloc(t, rlm_icmp_echo_t, node, echo_cmp, NULL));

	/*
	 *      Since these fields are random numbers, we don't care
	 *      about network / host byte order.  No one other than us
	 *      will be interpreting these fields.  As such, we can
	 *      just treat them as host byte order.
	 *
	 *      The only side effect of this choice is that this code
	 *      will use (e.g.) 0xabcd for the ident, and Wireshark,
	 *      tcpdump, etc. may show the ident as 0xcdab.  That's
	 *      fine.
	 */
	t->data = fr_rand();
	t->ident = fr_rand();

	af = inst->src_ipaddr.af;

	switch (af) {
	default:
		fr_strerror_const("Unsupported address family");
		return -1;

	case AF_UNSPEC:
	case AF_INET:
		af = AF_INET;
		proto = IPPROTO_ICMP;
		t->request_type = ICMP_ECHOREQUEST;
		t->reply_type = ICMP_ECHOREPLY;
		t->ipaddr_type = FR_TYPE_IPV4_ADDR;
		break;

	case AF_INET6:
		af = AF_INET6;
		proto = IPPROTO_ICMPV6;
		t->request_type = ICMPV6_ECHOREQUEST;
		t->reply_type = ICMPV6_ECHOREPLY;
		t->ipaddr_type = FR_TYPE_IPV6_ADDR;
		break;
	}

	/*
	 *	Try and open with SOCK_DGRAM.
	 *	If we get permission denied, fall back to SOCK_RAW.
	 *	For some reason with docker, even if we have all
	 *	the capabilities opening a SOCK_DGRAM/IPPROTO_ICMP
	 *	socket fails.
	 *
	 *	We don't appear to need to specify the IP header
	 *	and the xlat works fine.  Very strange.
	 */
	fd = socket(af, SOCK_DGRAM, proto);
	if (fd < 0) fd = socket(af, SOCK_RAW, proto);
	if (fd < 0) {
		fr_strerror_printf("Failed opening socket (%s, %s): %s",
				   fr_table_str_by_value(fr_net_af_table, af, "<INVALID>"),
				   fr_table_str_by_value(fr_net_ip_proto_table, proto, "<INVALID>"),
				   fr_syserror(errno));
		return -1;
	}

#ifndef FD_CLOEXEC
#define FD_CLOEXEC (0)
#endif

	(void) fcntl(fd, F_SETFL, O_NONBLOCK | FD_CLOEXEC);

	if (inst->src_ipaddr.af != AF_UNSPEC) {
		ipaddr = inst->src_ipaddr;
		src = &ipaddr;
	} else {
		src = NULL;
	}

	/*
	 *	Only bind if we have a src and interface.
	 */
	if (src && inst->interface && (fr_socket_bind(fd, src, NULL, inst->interface) < 0)) {
		close(fd);
		return -1;
	}

	/*
	 *	We assume that the outbound socket is always writable.
	 *	If not, too bad.  Packets will get lost.
	 */
	if (fr_event_fd_insert(t, mctx->el, fd,
			       mod_icmp_read,
			       NULL,
			       mod_icmp_error,
			       our_mctx) < 0) {
		fr_strerror_const_push("Failed adding socket to event loop");
		close(fd);
		return -1;
	}
	t->fd = fd;

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_icmp_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_icmp_t);
	xlat_t		*xlat;

	xlat = xlat_register_module(inst, mctx, mctx->inst->name, xlat_icmp, XLAT_FLAG_NEEDS_ASYNC);
	xlat_func_args(xlat, xlat_icmp_args);

	FR_TIME_DELTA_BOUND_CHECK("timeout", inst->timeout, >=, fr_time_delta_from_msec(100)); /* 1/10s minimum timeout */
	FR_TIME_DELTA_BOUND_CHECK("timeout", inst->timeout, <=, fr_time_delta_from_sec(10));

#ifdef __linux__
#  ifndef HAVE_CAPABILITY_H
	if ((geteuid() != 0)) PWARN("Server not built with cap interface, opening raw sockets will likely fail");
#  else
	/*
	 *	Request RAW capabilities on Linux.  On other systems this does nothing.
	 */
	if ((fr_cap_enable(CAP_NET_RAW, CAP_EFFECTIVE) < 0) && (geteuid() != 0)) {
		PERROR("Failed setting capabilities required to open ICMP socket");
		return -1;
	}
#  endif
#endif

	return 0;
}


/** Destroy thread data for the submodule.
 *
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_icmp_thread_t *t = talloc_get_type_abort(mctx->thread, rlm_icmp_thread_t);

	if (t->fd < 0) return 0;

	(void) fr_event_fd_delete(mctx->el, t->fd, FR_EVENT_FILTER_IO);
	close(t->fd);
	t->fd = -1;

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_icmp;
module_rlm_t rlm_icmp = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "icmp",
		.type		= MODULE_TYPE_THREAD_SAFE,
		.inst_size	= sizeof(rlm_icmp_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.thread_inst_size = sizeof(rlm_icmp_thread_t),
		.thread_inst_type = "rlm_icmp_thread_t",
		.thread_instantiate = mod_thread_instantiate,
		.thread_detach	= mod_thread_detach
	}
};
