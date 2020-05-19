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
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_icmp (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>
#include <fcntl.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct {
	char const	*name;
	char const	*xlat_name;
	char const	*interface;
	fr_time_delta_t	timeout;
	fr_ipaddr_t	src_ipaddr;
} rlm_icmp_t;

typedef struct {
	rlm_icmp_t	*inst;
	rbtree_t	*tree;
	int		fd;
	fr_event_list_t *el;

	uint32_t	data;
	uint16_t	ident;
	uint32_t	counter;

	fr_type_t	ipaddr_type;
	uint8_t		request_type;
	uint8_t		reply_type;
} rlm_icmp_thread_t;

typedef struct {
	bool		replied;		//!< do we have a reply?
	fr_value_box_t	*ip;			//!< the IP we're pinging
	uint32_t	counter;	       	//!< for pinging the same IP multiple times
	REQUEST		*request;		//!< so it can be resumed when we get the echo reply
} rlm_icmp_echo_t;

/** Wrapper around the module thread stuct for individual xlats
 *
 */
typedef struct {
	rlm_icmp_t		*inst;		//!< Instance of rlm_icmp.
	rlm_icmp_thread_t	*t;		//!< rlm_icmp thread instance.
} xlat_icmp_thread_inst_t;

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
		sum += fr_net_to_uint16(p);	 /* type / code */
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

static xlat_action_t xlat_icmp_resume(TALLOC_CTX *ctx, fr_cursor_t *out,
				      UNUSED REQUEST *request,
				      UNUSED void const *xlat_inst, void *xlat_thread_inst,
				      UNUSED fr_value_box_t **in, void *rctx)
{
	rlm_icmp_echo_t *echo = talloc_get_type_abort(rctx, rlm_icmp_echo_t);
	xlat_icmp_thread_inst_t	*thread = talloc_get_type_abort(xlat_thread_inst, xlat_icmp_thread_inst_t);
	fr_value_box_t	*vb;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL, false));
	vb->vb_bool = echo->replied;

	(void) rbtree_deletebydata(thread->t->tree, echo);
	talloc_free(echo);

	fr_cursor_insert(out, vb);

	return XLAT_ACTION_DONE;
}

static void xlat_icmp_cancel(REQUEST *request, UNUSED void *xlat_inst, void *xlat_thread_inst,
			     void *rctx, fr_state_signal_t action)
{
	rlm_icmp_echo_t *echo = talloc_get_type_abort(rctx, rlm_icmp_echo_t);
	xlat_icmp_thread_inst_t	*thread = talloc_get_type_abort(xlat_thread_inst, xlat_icmp_thread_inst_t);

	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Cancelling ICMP request for %pV (counter=%d)", echo->ip, echo->counter);

	(void) rbtree_deletebydata(thread->t->tree, echo);
	talloc_free(echo);
}


static void _xlat_icmp_timeout(REQUEST *request,
			     UNUSED void *xlat_inst, UNUSED void *xlat_thread_inst, void *rctx, UNUSED fr_time_t fired)
{
	rlm_icmp_echo_t *echo = talloc_get_type_abort(rctx, rlm_icmp_echo_t);

	if (echo->replied) return; /* it MUST already have been marked resumable. */

	RDEBUG2("No response to ICMP request for %pV (counter=%d)", echo->ip, echo->counter);

	unlang_interpret_resumable(request);
}

/** Xlat to delay the request
 *
 * Example (ping 192.0.2.1):
@verbatim
"%{icmp:192.0.2.1}"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_icmp(TALLOC_CTX *ctx, UNUSED fr_cursor_t *out,
			       REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
			       fr_value_box_t **in)
{
	void			*instance;
	rlm_icmp_t const	*inst;
	xlat_icmp_thread_inst_t	*thread = talloc_get_type_abort(xlat_thread_inst, xlat_icmp_thread_inst_t);
	rlm_icmp_echo_t		*echo;
	icmp_header_t		icmp;
	uint16_t		checksum;
	ssize_t			rcode;
	socklen_t      		salen;
	struct sockaddr_storage	dst;

	memcpy(&instance, xlat_inst, sizeof(instance));	/* Stupid const issues */

	inst = talloc_get_type_abort(instance, rlm_icmp_t);

	/*
	 *	If there's no input, do nothing.
	 */
	if (!*in) return XLAT_ACTION_FAIL;

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	if (fr_value_box_cast_in_place(ctx, *in, thread->t->ipaddr_type, NULL) < 0) {
		RPEDEBUG("Failed casting result to IP address");
		return XLAT_ACTION_FAIL;
	}

	MEM(echo = talloc_zero(ctx, rlm_icmp_echo_t));
	echo->ip = *in;
	echo->request = request;
	echo->counter = thread->t->counter++;

	/*
	 *	Add the IP to the local tracking heap, so that the IO
	 *	functions can find it.
	 *
	 *	This insert will never fail, because of the unique
	 *	counter above.
	 */
	if (!rbtree_insert(thread->t->tree, echo)) {
		RPEDEBUG("Failed inserting IP into tracking table");
		talloc_free(echo);
		return XLAT_ACTION_FAIL;
	}

	if (unlang_xlat_event_timeout_add(request, _xlat_icmp_timeout, echo, fr_time() + inst->timeout) < 0) {
		RPEDEBUG("Failed adding timeout");
		(void) rbtree_deletebydata(thread->t->tree, echo);
		talloc_free(echo);
		return XLAT_ACTION_FAIL;
	}

	RDEBUG("Sending ICMP request to %pV (counter=%d)", echo->ip, echo->counter);

	icmp = (icmp_header_t) {
		.type = thread->t->request_type,
		.ident = thread->t->ident,
		.data = thread->t->data,
		.counter = echo->counter
	};

	(void) fr_ipaddr_to_sockaddr(&echo->ip->vb_ip, 0, &dst, &salen);

	/*
	 *	Calculate the checksum
	 */
	checksum = 0;

	/*
	 *	Start off with the IPv6 pseudo-header checksum
	 */
	if (thread->t->ipaddr_type == FR_TYPE_IPV6_ADDR) {
		checksum = fr_ip6_pesudo_header_checksum(&thread->t->inst->src_ipaddr.addr.v6, &echo->ip->vb_ip.addr.v6,
							 sizeof(ip_header6_t) + sizeof(icmp), IPPROTO_ICMPV6);
	}

	/*
	 *	Followed by checksumming the actual ICMP packet.
	 */
	icmp.checksum = htons(icmp_checksum((uint8_t *) &icmp, sizeof(icmp), checksum));

	rcode = sendto(thread->t->fd, &icmp, sizeof(icmp), 0, (struct sockaddr *) &dst, salen);
	if (rcode < 0) {
		REDEBUG("Failed sending ICMP request to %pV: %s", echo->ip, fr_syserror(errno));
		(void) rbtree_deletebydata(thread->t->tree, echo);
		talloc_free(echo);
		return XLAT_ACTION_FAIL;
	}

	if ((size_t) rcode < sizeof(icmp)) {
		REDEBUG("Failed sending entire ICMP packet");
		(void) rbtree_deletebydata(thread->t->tree, echo);
		talloc_free(echo);
		return XLAT_ACTION_FAIL;
	}

	return unlang_xlat_yield(request, xlat_icmp_resume, xlat_icmp_cancel, echo);
}

/** Resolves and caches the module's thread instance for use by a specific xlat instance
 *
 * @param[in] xlat_inst			UNUSED.
 * @param[in] xlat_thread_inst		pre-allocated structure to hold pointer to module's
 *					thread instance.
 * @param[in] exp			UNUSED.
 * @param[in] uctx			Module's global instance.  Used to lookup thread
 *					specific instance.
 * @return 0.
 */
static int mod_xlat_thread_instantiate(UNUSED void *xlat_inst, void *xlat_thread_inst,
				       UNUSED xlat_exp_t const *exp, void *uctx)
{
	rlm_icmp_t		*inst = talloc_get_type_abort(uctx, rlm_icmp_t);
	xlat_icmp_thread_inst_t	*xt = xlat_thread_inst;

	xt->inst = inst;
	xt->t = talloc_get_type_abort(module_thread_by_data(inst)->data, rlm_icmp_thread_t);

	return 0;
}

static int mod_xlat_instantiate(void *xlat_inst, UNUSED xlat_exp_t const *exp, void *uctx)
{
	*((void **)xlat_inst) = talloc_get_type_abort(uctx, rlm_icmp_t);
	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_icmp_t *inst = instance;
	xlat_t const *xlat;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) inst->xlat_name = cf_section_name1(conf);
	inst->name = inst->xlat_name;

	xlat = xlat_async_register(inst, inst->xlat_name, xlat_icmp);
	xlat_async_instantiate_set(xlat, mod_xlat_instantiate, rlm_icmp_t *, NULL, inst);
	xlat_async_thread_instantiate_set(xlat, mod_xlat_thread_instantiate, xlat_icmp_thread_inst_t, NULL, inst);

	FR_TIME_DELTA_BOUND_CHECK("timeout", inst->timeout, >=, fr_time_delta_from_msec(100)); /* 1/10s minimum timeout */
	FR_TIME_DELTA_BOUND_CHECK("timeout", inst->timeout, <=, fr_time_delta_from_sec(10));

	return 0;
}


/** Destroy thread data for the submodule.
 *
 */
static int mod_thread_detach(fr_event_list_t *el, void *thread)
{
	rlm_icmp_thread_t *t = talloc_get_type_abort(thread, rlm_icmp_thread_t);

	if (t->fd < 0) return 0;

	(void) fr_event_fd_delete(el, t->fd, FR_EVENT_FILTER_IO);
	close(t->fd);
	t->fd = -1;

	return 0;
}

static int echo_cmp(void const *one, void const *two)
{
	rlm_icmp_echo_t const *a = one;
	rlm_icmp_echo_t const *b = two;

	/*
	 *	No need to check IP, because "counter" is unique for each packet.
	 */
	return (a->counter < b->counter) - (a->counter > b->counter);
}

static void mod_icmp_read(UNUSED fr_event_list_t *el, UNUSED int sockfd, UNUSED int flags, void *ctx)
{
	rlm_icmp_thread_t *t = talloc_get_type_abort(ctx, rlm_icmp_thread_t);
	rlm_icmp_t *inst = t->inst;
	ssize_t len;
	icmp_header_t *icmp;
	rlm_icmp_echo_t my_echo, *echo;
	uint64_t buffer[256];

	len = read(t->fd, (char *) buffer, sizeof(buffer));
	if (len <= 0) return;

	HEXDUMP4((uint8_t const *)buffer, len, "received icmp packet ");

	/*
	 *	Ignore packets if we haven't sent any requests.
	 */
	if (rbtree_num_elements(t->tree) == 0) {
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
	echo = rbtree_finddata(t->tree, &my_echo);
	if (!echo) {
		DEBUG("Can't find packet counter=%d in tree", icmp->counter);
		return;
	}

	(void) rbtree_deletebydata(t->tree, echo);

	/*
	 *	We have a reply!
	 */
	echo->replied = true;
	unlang_interpret_resumable(echo->request);
}

static void mod_icmp_error(fr_event_list_t *el, UNUSED int sockfd, UNUSED int flags,
			   UNUSED int fd_errno, void *ctx)
{
	rlm_icmp_thread_t *t = talloc_get_type_abort(ctx, rlm_icmp_thread_t);
	rlm_icmp_t *inst = t->inst;

	ERROR("Failed reading from ICMP socket - Closing it");

	(void) fr_event_fd_delete(el, t->fd, FR_EVENT_FILTER_IO);
	close(t->fd);
	t->fd = -1;
}


/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(UNUSED CONF_SECTION const *cs, void *instance, fr_event_list_t *el, void *thread)
{
	int fd, af, proto;
	rlm_icmp_t *inst = talloc_get_type_abort(instance, rlm_icmp_t);
	rlm_icmp_thread_t *t = talloc_get_type_abort(thread, rlm_icmp_thread_t);
	fr_ipaddr_t ipaddr, *src;

	MEM(t->tree = rbtree_alloc(t, echo_cmp, NULL, RBTREE_FLAG_NONE));
	t->inst = inst;
	t->el = el;

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
		fr_strerror_printf("Unsupported address family");
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

	fd = socket(af, SOCK_DGRAM, proto);
	if (fd < 0) {
		fr_strerror_printf("Failed opening socket: %s", fr_syserror(errno));
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
	if (fr_event_fd_insert(t, el, fd,
			       mod_icmp_read,
			       NULL,
			       mod_icmp_error,
			       t) < 0) {
		fr_strerror_printf("Failed adding socket to event loop - %s", fr_strerror());
		close(fd);
		return -1;
	}
	t->fd = fd;

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_icmp;
module_t rlm_icmp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "icmp",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_icmp_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,

	.thread_inst_size = sizeof(rlm_icmp_thread_t),
	.thread_inst_type = "rlm_icmp_thread_t",
	.thread_instantiate = mod_thread_instantiate,
	.thread_detach	= mod_thread_detach,
};
