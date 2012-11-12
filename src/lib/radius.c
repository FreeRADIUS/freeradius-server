/**
 * @file radius.c
 * @brief Functions to send/receive radius packets.
 *
 * Version:	$Id$
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000-2003,2006  The FreeRADIUS server project
 */

#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/libradius.h>
#include	<freeradius-devel/md5.h>

#include	<fcntl.h>
#include	<ctype.h>

#ifdef WITH_UDPFROMTO
#include	<freeradius-devel/udpfromto.h>
#endif

#ifdef HAVE_MALLOC_H
#include	<malloc.h>
#endif

#if 0
#define VP_TRACE if (fr_debug_flag) printf
#else
#define VP_TRACE(_x, ...)
#endif


/*
 *  The RFC says 4096 octets max, and most packets are less than 256.
 */
#define MAX_PACKET_LEN 4096

/*
 *	The maximum number of attributes which we allow in an incoming
 *	request.  If there are more attributes than this, the request
 *	is rejected.
 *
 *	This helps to minimize the potential for a DoS, when an
 *	attacker spoofs Access-Request packets, which don't have a
 *	Message-Authenticator attribute.  This means that the packet
 *	is unsigned, and the attacker can use resources on the server,
 *	even if the end request is rejected.
 */
int fr_max_attributes = 0;
FILE *fr_log_fp = NULL;

typedef struct radius_packet_t {
  uint8_t	code;
  uint8_t	id;
  uint8_t	length[2];
  uint8_t	vector[AUTH_VECTOR_LEN];
  uint8_t	data[1];
} radius_packet_t;

static fr_randctx fr_rand_pool;	/* across multiple calls */
static int fr_rand_initialized = 0;
static unsigned int salt_offset = 0;
static uint8_t nullvector[AUTH_VECTOR_LEN] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; /* for CoA decode */

const char *fr_packet_codes[FR_MAX_PACKET_CODE] = {
  "",
  "Access-Request",
  "Access-Accept",
  "Access-Reject",
  "Accounting-Request",
  "Accounting-Response",
  "Accounting-Status",
  "Password-Request",
  "Password-Accept",
  "Password-Reject",
  "Accounting-Message",
  "Access-Challenge",
  "Status-Server",
  "Status-Client",
  "14",
  "15",
  "16",
  "17",
  "18",
  "19",
  "20",
  "Resource-Free-Request",
  "Resource-Free-Response",
  "Resource-Query-Request",
  "Resource-Query-Response",
  "Alternate-Resource-Reclaim-Request",
  "NAS-Reboot-Request",
  "NAS-Reboot-Response",
  "28",
  "Next-Passcode",
  "New-Pin",
  "Terminate-Session",
  "Password-Expired",
  "Event-Request",
  "Event-Response",
  "35",
  "36",
  "37",
  "38",
  "39",
  "Disconnect-Request",
  "Disconnect-ACK",
  "Disconnect-NAK",
  "CoA-Request",
  "CoA-ACK",
  "CoA-NAK",
  "46",
  "47",
  "48",
  "49",
  "IP-Address-Allocate",
  "IP-Address-Release"
};


void fr_printf_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if ((fr_debug_flag == 0) || !fr_log_fp) {
		va_end(ap);
		return;
	}

	vfprintf(fr_log_fp, fmt, ap);
	va_end(ap);

	return;
}

static const char *tabs = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

static void print_hex_data(const uint8_t *ptr, int attrlen, int depth)
{
	int i;

	for (i = 0; i < attrlen; i++) {
		if ((i > 0) && ((i & 0x0f) == 0x00))
			fprintf(fr_log_fp, "%.*s", depth, tabs);
		fprintf(fr_log_fp, "%02x ", ptr[i]);
		if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");
	}
	if ((i & 0x0f) != 0) fprintf(fr_log_fp, "\n");
}


void rad_print_hex(RADIUS_PACKET *packet)
{
	int i;

	if (!packet->data || !fr_log_fp) return;

	fprintf(fr_log_fp, "  Code:\t\t%u\n", packet->data[0]);
	fprintf(fr_log_fp, "  Id:\t\t%u\n", packet->data[1]);
	fprintf(fr_log_fp, "  Length:\t%u\n", ((packet->data[2] << 8) |
				   (packet->data[3])));
	fprintf(fr_log_fp, "  Vector:\t");
	for (i = 4; i < 20; i++) {
		fprintf(fr_log_fp, "%02x", packet->data[i]);
	}
	fprintf(fr_log_fp, "\n");

	if (packet->data_len > 20) {
		int total;
		const uint8_t *ptr;
		fprintf(fr_log_fp, "  Data:");

		total = packet->data_len - 20;
		ptr = packet->data + 20;

		while (total > 0) {
			int attrlen;
			unsigned int vendor = 0;

			fprintf(fr_log_fp, "\t\t");
			if (total < 2) { /* too short */
				fprintf(fr_log_fp, "%02x\n", *ptr);
				break;
			}

			if (ptr[1] > total) { /* too long */
				for (i = 0; i < total; i++) {
					fprintf(fr_log_fp, "%02x ", ptr[i]);
				}
				break;
			}

			fprintf(fr_log_fp, "%02x  %02x  ", ptr[0], ptr[1]);
			attrlen = ptr[1] - 2;

			if ((ptr[0] == PW_VENDOR_SPECIFIC) &&
			    (attrlen > 4)) {
				vendor = (ptr[3] << 16) | (ptr[4] << 8) | ptr[5];
				fprintf(fr_log_fp, "%02x%02x%02x%02x (%u)  ",
				       ptr[2], ptr[3], ptr[4], ptr[5], vendor);
				attrlen -= 4;
				ptr += 6;
				total -= 6;

			} else {
				ptr += 2;
				total -= 2;
			}

			print_hex_data(ptr, attrlen, 3);

			ptr += attrlen;
			total -= attrlen;
		}
	}
	fflush(stdout);
}

/**
 * @brief Wrapper for sendto which handles sendfromto, IPv6, and all
 *	possible combinations.
 */
static int rad_sendto(int sockfd, void *data, size_t data_len, int flags,
		      fr_ipaddr_t *src_ipaddr, int src_port,
		      fr_ipaddr_t *dst_ipaddr, int dst_port)
{
	int rcode;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_dst;

#ifdef WITH_UDPFROMTO
	struct sockaddr_storage	src;
	socklen_t		sizeof_src;

	fr_ipaddr2sockaddr(src_ipaddr, src_port, &src, &sizeof_src);
#else
	src_port = src_port;	/* -Wunused */
#endif

	if (!fr_ipaddr2sockaddr(dst_ipaddr, dst_port, &dst, &sizeof_dst)) {
		return -1;
	}

#ifdef WITH_UDPFROMTO
	/*
	 *	And if they don't specify a source IP address, don't
	 *	use udpfromto.
	 */
	if (((dst_ipaddr->af == AF_INET) || (dst_ipaddr->af == AF_INET6)) &&
	    (src_ipaddr->af != AF_UNSPEC) &&
	    !fr_inaddr_any(src_ipaddr)) {
		rcode = sendfromto(sockfd, data, data_len, flags,
				   (struct sockaddr *)&src, sizeof_src,
				   (struct sockaddr *)&dst, sizeof_dst);
		goto done;
	}
#else
	src_ipaddr = src_ipaddr; /* -Wunused */
#endif

	/*
	 *	No udpfromto, fail gracefully.
	 */
	rcode = sendto(sockfd, data, data_len, flags,
		       (struct sockaddr *) &dst, sizeof_dst);
#ifdef WITH_UDPFROMTO
done:
#endif
	if (rcode < 0) {
		DEBUG("rad_send() failed: %s\n", strerror(errno));
	}

	return rcode;
}


void rad_recv_discard(int sockfd)
{
	uint8_t			header[4];
	struct sockaddr_storage	src;
	socklen_t		sizeof_src = sizeof(src);

	recvfrom(sockfd, header, sizeof(header), 0,
		 (struct sockaddr *)&src, &sizeof_src);
}


ssize_t rad_recv_header(int sockfd, fr_ipaddr_t *src_ipaddr, int *src_port,
			int *code)
{
	ssize_t			data_len, packet_len;
	uint8_t			header[4];
	struct sockaddr_storage	src;
	socklen_t		sizeof_src = sizeof(src);

	data_len = recvfrom(sockfd, header, sizeof(header), MSG_PEEK,
			    (struct sockaddr *)&src, &sizeof_src);
	if (data_len < 0) {
		if ((errno == EAGAIN) || (errno == EINTR)) return 0;
		return -1;
	}

	/*
	 *	Too little data is available, discard the packet.
	 */
	if (data_len < 4) {
		recvfrom(sockfd, header, sizeof(header), 0,
			 (struct sockaddr *)&src, &sizeof_src);
		return 1;

	} else {		/* we got 4 bytes of data. */
		/*
		 *	See how long the packet says it is.
		 */
		packet_len = (header[2] * 256) + header[3];

		/*
		 *	The length in the packet says it's less than
		 *	a RADIUS header length: discard it.
		 */
		if (packet_len < AUTH_HDR_LEN) {
			recvfrom(sockfd, header, sizeof(header), 0,
				 (struct sockaddr *)&src, &sizeof_src);
			return 1;

			/*
			 *	Enforce RFC requirements, for sanity.
			 *	Anything after 4k will be discarded.
			 */
		} else if (packet_len > MAX_PACKET_LEN) {
			recvfrom(sockfd, header, sizeof(header), 0,
				 (struct sockaddr *)&src, &sizeof_src);
			return 1;
		}
	}

	/*
	 *	Convert AF.  If unknown, discard packet.
	 */
	if (!fr_sockaddr2ipaddr(&src, sizeof_src, src_ipaddr, src_port)) {
		recvfrom(sockfd, header, sizeof(header), 0,
			 (struct sockaddr *)&src, &sizeof_src);
		return 1;
	}

	*code = header[0];

	/*
	 *	The packet says it's this long, but the actual UDP
	 *	size could still be smaller.
	 */
	return packet_len;
}


/**
 * @brief wrapper for recvfrom, which handles recvfromto, IPv6, and all
 *	possible combinations.
 */
static ssize_t rad_recvfrom(int sockfd, uint8_t **pbuf, int flags,
			    fr_ipaddr_t *src_ipaddr, uint16_t *src_port,
			    fr_ipaddr_t *dst_ipaddr, uint16_t *dst_port)
{
	struct sockaddr_storage	src;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_src = sizeof(src);
	socklen_t	        sizeof_dst = sizeof(dst);
	ssize_t			data_len;
	uint8_t			header[4];
	void			*buf;
	size_t			len;
	int			port;

	memset(&src, 0, sizeof_src);
	memset(&dst, 0, sizeof_dst);

	/*
	 *	Get address family, etc. first, so we know if we
	 *	need to do udpfromto.
	 *
	 *	FIXME: udpfromto also does this, but it's not
	 *	a critical problem.
	 */
	if (getsockname(sockfd, (struct sockaddr *)&dst,
			&sizeof_dst) < 0) return -1;

	/*
	 *	Read the length of the packet, from the packet.
	 *	This lets us allocate the buffer to use for
	 *	reading the rest of the packet.
	 */
	data_len = recvfrom(sockfd, header, sizeof(header), MSG_PEEK,
			    (struct sockaddr *)&src, &sizeof_src);
	if (data_len < 0) {
		if ((errno == EAGAIN) || (errno == EINTR)) return 0;
		return -1;
	}

	/*
	 *	Too little data is available, discard the packet.
	 */
	if (data_len < 4) {
		recvfrom(sockfd, header, sizeof(header), flags,
			 (struct sockaddr *)&src, &sizeof_src);
		return 0;

	} else {		/* we got 4 bytes of data. */
		/*
		 *	See how long the packet says it is.
		 */
		len = (header[2] * 256) + header[3];

		/*
		 *	The length in the packet says it's less than
		 *	a RADIUS header length: discard it.
		 */
		if (len < AUTH_HDR_LEN) {
			recvfrom(sockfd, header, sizeof(header), flags,
				 (struct sockaddr *)&src, &sizeof_src);
			return 0;

			/*
			 *	Enforce RFC requirements, for sanity.
			 *	Anything after 4k will be discarded.
			 */
		} else if (len > MAX_PACKET_LEN) {
			recvfrom(sockfd, header, sizeof(header), flags,
				 (struct sockaddr *)&src, &sizeof_src);
			return len;
		}
	}

	buf = malloc(len);
	if (!buf) return -1;

	/*
	 *	Receive the packet.  The OS will discard any data in the
	 *	packet after "len" bytes.
	 */
#ifdef WITH_UDPFROMTO
	if ((dst.ss_family == AF_INET) || (dst.ss_family == AF_INET6)) {
		data_len = recvfromto(sockfd, buf, len, flags,
				      (struct sockaddr *)&src, &sizeof_src,
				      (struct sockaddr *)&dst, &sizeof_dst);
	} else
#endif
		/*
		 *	No udpfromto, fail gracefully.
		 */
		data_len = recvfrom(sockfd, buf, len, flags,
				    (struct sockaddr *)&src, &sizeof_src);
	if (data_len < 0) {
		free(buf);
		return data_len;
	}

	if (!fr_sockaddr2ipaddr(&src, sizeof_src, src_ipaddr, &port)) {
		free(buf);
		return -1;	/* Unknown address family, Die Die Die! */
	}
	*src_port = port;

	fr_sockaddr2ipaddr(&dst, sizeof_dst, dst_ipaddr, &port);
	*dst_port = port;

	/*
	 *	Different address families should never happen.
	 */
	if (src.ss_family != dst.ss_family) {
		free(buf);
		return -1;
	}

	/*
	 *	Tell the caller about the data
	 */
	*pbuf = buf;

	return data_len;
}


#define AUTH_PASS_LEN (AUTH_VECTOR_LEN)
/**
 * @brief Build an encrypted secret value to return in a reply packet
 * 
 *               The secret is hidden by xoring with a MD5 digest
 *               created from the shared secret and the authentication
 *               vector.  We put them into MD5 in the reverse order from
 *               that used when encrypting passwords to RADIUS.
 *
 */
static void make_secret(uint8_t *digest, const uint8_t *vector,
			const char *secret, const uint8_t *value)
{
	FR_MD5_CTX context;
        int             i;

	fr_MD5Init(&context);
	fr_MD5Update(&context, vector, AUTH_VECTOR_LEN);
	fr_MD5Update(&context, (const uint8_t *) secret, strlen(secret));
	fr_MD5Final(digest, &context);

        for ( i = 0; i < AUTH_VECTOR_LEN; i++ ) {
		digest[i] ^= value[i];
        }
}

#define MAX_PASS_LEN (128)
static void make_passwd(uint8_t *output, ssize_t *outlen,
			const uint8_t *input, size_t inlen,
			const char *secret, const uint8_t *vector)
{
	FR_MD5_CTX context, old;
	uint8_t	digest[AUTH_VECTOR_LEN];
	uint8_t passwd[MAX_PASS_LEN];
	size_t	i, n;
	size_t	len;

	/*
	 *	If the length is zero, round it up.
	 */
	len = inlen;

	if (len > MAX_PASS_LEN) len = MAX_PASS_LEN;

	memcpy(passwd, input, len);
	if (len < sizeof(passwd)) memset(passwd + len, 0, sizeof(passwd) - len);

	if (len == 0) {
		len = AUTH_PASS_LEN;
	}

	else if ((len & 0x0f) != 0) {
		len += 0x0f;
		len &= ~0x0f;
	}
	*outlen = len;

	fr_MD5Init(&context);
	fr_MD5Update(&context, (const uint8_t *) secret, strlen(secret));
	old = context;

	/*
	 *	Do first pass.
	 */
	fr_MD5Update(&context, vector, AUTH_PASS_LEN);

	for (n = 0; n < len; n += AUTH_PASS_LEN) {
		if (n > 0) {
			context = old;
			fr_MD5Update(&context,
				       passwd + n - AUTH_PASS_LEN,
				       AUTH_PASS_LEN);
		}

		fr_MD5Final(digest, &context);
		for (i = 0; i < AUTH_PASS_LEN; i++) {
			passwd[i + n] ^= digest[i];
		}
	}

	memcpy(output, passwd, len);
}

static void make_tunnel_passwd(uint8_t *output, ssize_t *outlen,
			       const uint8_t *input, size_t inlen, size_t room,
			       const char *secret, const uint8_t *vector)
{
	FR_MD5_CTX context, old;
	uint8_t	digest[AUTH_VECTOR_LEN];
	uint8_t passwd[MAX_STRING_LEN + AUTH_VECTOR_LEN];
	int	i, n;
	int	len;

	/*
	 *	Be paranoid.
	 */
	if (room > 253) room = 253;

	/*
	 *	Account for 2 bytes of the salt, and round the room
	 *	available down to the nearest multiple of 16.  Then,
	 *	subtract one from that to account for the length byte,
	 *	and the resulting number is the upper bound on the data
	 *	to copy.
	 *
	 *	We could short-cut this calculation just be forcing
	 *	inlen to be no more than 239.  It would work for all
	 *	VSA's, as we don't pack multiple VSA's into one
	 *	attribute.
	 *
	 *	However, this calculation is more general, if a little
	 *	complex.  And it will work in the future for all possible
	 *	kinds of weird attribute packing.
	 */
	room -= 2;
	room -= (room & 0x0f);
	room--;

	if (inlen > room) inlen = room;

	/*
	 *	Length of the encrypted data is password length plus
	 *	one byte for the length of the password.
	 */
	len = inlen + 1;
	if ((len & 0x0f) != 0) {
		len += 0x0f;
		len &= ~0x0f;
	}
	*outlen = len + 2;	/* account for the salt */

	/*
	 *	Copy the password over.
	 */
	memcpy(passwd + 3, input, inlen);
	memset(passwd + 3 + inlen, 0, sizeof(passwd) - 3 - inlen);

	/*
	 *	Generate salt.  The RFC's say:
	 *
	 *	The high bit of salt[0] must be set, each salt in a
	 *	packet should be unique, and they should be random
	 *
	 *	So, we set the high bit, add in a counter, and then
	 *	add in some CSPRNG data.  should be OK..
	 */
	passwd[0] = (0x80 | ( ((salt_offset++) & 0x0f) << 3) |
		     (fr_rand() & 0x07));
	passwd[1] = fr_rand();
	passwd[2] = inlen;	/* length of the password string */

	fr_MD5Init(&context);
	fr_MD5Update(&context, (const uint8_t *) secret, strlen(secret));
	old = context;

	fr_MD5Update(&context, vector, AUTH_VECTOR_LEN);
	fr_MD5Update(&context, &passwd[0], 2);

	for (n = 0; n < len; n += AUTH_PASS_LEN) {
		if (n > 0) {
			context = old;
			fr_MD5Update(&context,
				       passwd + 2 + n - AUTH_PASS_LEN,
				       AUTH_PASS_LEN);
		}

		fr_MD5Final(digest, &context);

		for (i = 0; i < AUTH_PASS_LEN; i++) {
			passwd[i + 2 + n] ^= digest[i];
		}
	}
	memcpy(output, passwd, len + 2);
}

extern int fr_attr_max_tlv;
extern int fr_attr_shift[];
extern int fr_attr_mask[];

static int do_next_tlv(const VALUE_PAIR *vp, const VALUE_PAIR *next, int nest)
{
	unsigned int tlv1, tlv2;

	if (nest > fr_attr_max_tlv) return 0;

	if (!vp) return 0;

	/*
	 *	Keep encoding TLVs which have the same scope.
	 *	e.g. two attributes of:
	 *		ATTR.TLV1.TLV2.TLV3 = data1
	 *		ATTR.TLV1.TLV2.TLV4 = data2
	 *	both get put into a container of "ATTR.TLV1.TLV2"
	 */

	/*
	 *	Nothing to follow, we're done.
	 */
	if (!next) return 0;

	/*
	 *	Not from the same vendor, skip it.
	 */
	if (vp->vendor != next->vendor) return 0;

	/*
	 *	In a different TLV space, skip it.
	 */
	tlv1 = vp->attribute;
	tlv2 = next->attribute;
	
	tlv1 &= ((1 << fr_attr_shift[nest]) - 1);
	tlv2 &= ((1 << fr_attr_shift[nest]) - 1);
	
	if (tlv1 != tlv2) return 0;

	return 1;
}


static ssize_t vp2data_any(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   const char *secret, int nest,
			   const VALUE_PAIR **pvp,
			   uint8_t *start, size_t room);

static ssize_t vp2attr_rfc(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   const char *secret, const VALUE_PAIR **pvp,
			   unsigned int attribute, uint8_t *ptr, size_t room);

/**
 * @brief This is really a sub-function of vp2data_any().  It encodes
 *	the *data* portion of the TLV, and assumes that the encapsulating
 *	attribute has already been encoded.
 */
static ssize_t vp2data_tlvs(const RADIUS_PACKET *packet,
			    const RADIUS_PACKET *original,
			    const char *secret, int nest,
			    const VALUE_PAIR **pvp,
			    uint8_t *start, size_t room)
{
	ssize_t len;
	size_t my_room;
	uint8_t *ptr = start;
	const VALUE_PAIR *vp = *pvp;
	const VALUE_PAIR *svp = vp;

	if (!svp) return 0;

#ifndef NDEBUG
	if (nest > fr_attr_max_tlv) {
		fr_strerror_printf("vp2data_tlvs: attribute nesting overflow");
		return -1;
	}
#endif

	while (vp) {
		if (room < 2) return ptr - start;
		
		ptr[0] = (vp->attribute >> fr_attr_shift[nest]) & fr_attr_mask[nest];
		ptr[1] = 2;
		
		my_room = room;
		if (room > 255) my_room = 255;

		len = vp2data_any(packet, original, secret, nest,
				  &vp, ptr + 2, my_room - 2);
		if (len < 0) return len;
		if (len == 0) return ptr - start;
		/* len can NEVER be more than 253 */

		ptr[1] += len;

#ifndef NDEBUG
		if ((fr_debug_flag > 3) && fr_log_fp) {
			fprintf(fr_log_fp, "\t\t%02x %02x  ", ptr[0], ptr[1]);
			print_hex_data(ptr + 2, len, 3);
		}
#endif

		room -= ptr[1];
		ptr += ptr[1];
		*pvp = vp;
		
		if (!do_next_tlv(svp, vp, nest)) break;
	}

#ifndef NDEBUG
	if ((fr_debug_flag > 3) && fr_log_fp) {
		DICT_ATTR *da;
		
		da = dict_attrbyvalue(svp->attribute & ((1 << fr_attr_shift[nest ]) - 1), svp->vendor);
		if (da) fprintf(fr_log_fp, "\t%s = ...\n", da->name);
	}
#endif

	return ptr - start;
}

/**
 * @brief Encodes the data portion of an attribute.
 * @return -1 on error, or the length of the data portion.
 */
static ssize_t vp2data_any(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   const char *secret, int nest,
			   const VALUE_PAIR **pvp,
			   uint8_t *start, size_t room)
{
	uint32_t lvalue;
	ssize_t len;
	const uint8_t *data;
	uint8_t *ptr = start;
	uint8_t	array[4];
	uint64_t lvalue64;
	const VALUE_PAIR *vp = *pvp;

	/*
	 *	See if we need to encode a TLV.  The low portion of
	 *	the attribute has already been placed into the packer.
	 *	If there are still attribute bytes left, then go
	 *	encode them as TLVs.
	 *
	 *	If we cared about the stack, we could unroll the loop.
	 */
	if (vp->flags.is_tlv && (nest < fr_attr_max_tlv) &&
	    ((vp->attribute >> fr_attr_shift[nest + 1]) != 0)) {
		return vp2data_tlvs(packet, original, secret, nest + 1, pvp,
				    start, room);
	}

	debug_pair(vp);

	/*
	 *	Set up the default sources for the data.
	 */
	data = vp->vp_octets;
	len = vp->length;

	/*
	 *	Short-circuit it for long attributes.  They can't be
	 *	encrypted, tagged, etc.
	 */
	if ((vp->type & PW_FLAG_LONG) != 0) goto do_tlv;

	switch(vp->type) {
	case PW_TYPE_STRING:
	case PW_TYPE_OCTETS:
	case PW_TYPE_IFID:
	case PW_TYPE_IPV6ADDR:
	case PW_TYPE_IPV6PREFIX:
	case PW_TYPE_ABINARY:
		/* nothing more to do */
		break;

	case PW_TYPE_BYTE:
		len = 1;	/* just in case */
		array[0] = vp->vp_integer & 0xff;
		data = array;
		break;

	case PW_TYPE_SHORT:
		len = 2;	/* just in case */
		array[0] = (vp->vp_integer >> 8) & 0xff;
		array[1] = vp->vp_integer & 0xff;
		data = array;
		break;

	case PW_TYPE_INTEGER:
		len = 4;	/* just in case */
		lvalue = htonl(vp->vp_integer);
		memcpy(array, &lvalue, sizeof(lvalue));
		data = array;
		break;

	case PW_TYPE_INTEGER64:
		len = 8;	/* just in case */
		lvalue64 = htonll(vp->vp_integer64);
		data = (uint8_t *) &lvalue64;
		break;

	case PW_TYPE_IPADDR:
		data = (const uint8_t *) &vp->vp_ipaddr;
		len = 4;	/* just in case */
		break;

		/*
		 *  There are no tagged date attributes.
		 */
	case PW_TYPE_DATE:
		lvalue = htonl(vp->vp_date);
		data = (const uint8_t *) &lvalue;
		len = 4;	/* just in case */
		break;

	case PW_TYPE_SIGNED:
	{
		int32_t slvalue;

		len = 4;	/* just in case */
		slvalue = htonl(vp->vp_signed);
		memcpy(array, &slvalue, sizeof(slvalue));
		break;
	}

	case PW_TYPE_TLV:
	do_tlv:
		data = vp->vp_tlv;
		if (!data) {
			fr_strerror_printf("ERROR: Cannot encode NULL TLV");
			return -1;
		}
		break;

	default:		/* unknown type: ignore it */
		fr_strerror_printf("ERROR: Unknown attribute type %d", vp->type);
		return -1;
	}

	/*
	 *	No data: skip it.
	 */
	if (len == 0) {
		*pvp = vp->next;
		return 0;
	}

	/*
	 *	Bound the data to the calling size
	 */
	if (len > (ssize_t) room) len = room;

	/*
	 *	Encrypt the various password styles
	 *
	 *	Attributes with encrypted values MUST be less than
	 *	128 bytes long.
	 */
	switch (vp->flags.encrypt) {
	case FLAG_ENCRYPT_USER_PASSWORD:
		make_passwd(ptr, &len, data, len,
			    secret, packet->vector);
		break;

	case FLAG_ENCRYPT_TUNNEL_PASSWORD:
		lvalue = 0;
		if (vp->flags.has_tag) lvalue = 1;

		/*
		 *	Check if there's enough room.  If there isn't,
		 *	we discard the attribute.
		 *
		 *	This is ONLY a problem if we have multiple VSA's
		 *	in one Vendor-Specific, though.
		 */
		if (room < (18 + lvalue)) return 0;

        	switch (packet->code) {
	        case PW_AUTHENTICATION_ACK:
        	case PW_AUTHENTICATION_REJECT:
        	case PW_ACCESS_CHALLENGE:
        	default:
			if (!original) {
				fr_strerror_printf("ERROR: No request packet, cannot encrypt %s attribute in the vp.", vp->name);
				return -1;
			}

			if (lvalue) ptr[0] = vp->flags.tag;
			make_tunnel_passwd(ptr + lvalue, &len, data, len,
					   room - lvalue,
					   secret, original->vector);
                	break;
	        case PW_ACCOUNTING_REQUEST:
        	case PW_DISCONNECT_REQUEST:
	        case PW_COA_REQUEST:
			ptr[0] = vp->flags.tag;
			make_tunnel_passwd(ptr + 1, &len, data, len - 1, room,
					   secret, packet->vector);
	                break;
        	}
		break;

		/*
		 *	The code above ensures that this attribute
		 *	always fits.
		 */
	case FLAG_ENCRYPT_ASCEND_SECRET:
		make_secret(ptr, packet->vector, secret, data);
		len = AUTH_VECTOR_LEN;
		break;


	default:
		if (vp->flags.has_tag && TAG_VALID(vp->flags.tag)) {
			if (vp->type == PW_TYPE_STRING) {
				if (len > ((ssize_t) (room - 1))) len = room - 1;
				ptr[0] = vp->flags.tag;
				ptr++;
			} else if (vp->type == PW_TYPE_INTEGER) {
				array[0] = vp->flags.tag;
			} /* else it can't be any other type */
		}
		memcpy(ptr, data, len);
		break;
	} /* switch over encryption flags */

	*pvp = vp->next;
	return len + (ptr - start);
}

static ssize_t attr_shift(const uint8_t *start, const uint8_t *end,
			  uint8_t *ptr, int hdr_len, ssize_t len,
			  int flag_offset, int vsa_offset)
{
	int check_len = len - ptr[1];
	int total = len + hdr_len;
	
	/*
	 *	Pass 1: Check if the addition of the headers
	 *	overflows the available room.  If so, return
	 *	what we were capable of encoding.
	 */
	
	while (check_len > (255 - hdr_len)) {
		total += hdr_len;
		check_len -= (255 - hdr_len);
	}

	/*
	 *	Note that this results in a number of attributes maybe
	 *	being marked as "encoded", but which aren't in the
	 *	packet.  Oh well.  The solution is to fix the
	 *	"vp2data_any" function to take into account the header
	 *	lengths.
	 */
	if ((ptr + ptr[1] + total) > end) {
		return (ptr + ptr[1]) - start;
	}
	
	/*
	 *	Pass 2: Now that we know there's enough room,
	 *	re-arrange the data to form a set of valid
	 *	RADIUS attributes.
	 */
	while (1) {
		int sublen = 255 - ptr[1];
		
		if (len <= sublen) {
			break;
		}
		
		len -= sublen;
		memmove(ptr + 255 + hdr_len, ptr + 255, sublen);
		memcpy(ptr + 255, ptr, hdr_len);
		ptr[1] += sublen;
		if (vsa_offset) ptr[vsa_offset] += sublen;
		ptr[flag_offset] |= 0x80;
		
		ptr += 255;
		ptr[1] = hdr_len;
		if (vsa_offset) ptr[vsa_offset] = 3;
	}

	ptr[1] += len;
	if (vsa_offset) ptr[vsa_offset] += len;

	return (ptr + ptr[1]) - start;
}


/**
 * @brief Encode an "extended" attribute.
 */
int rad_vp2extended(const RADIUS_PACKET *packet,
		    const RADIUS_PACKET *original,
		    const char *secret, const VALUE_PAIR **pvp,
		    uint8_t *ptr, size_t room)
{
	int len;
	int hdr_len;
	int nest = 1;
	uint8_t *start = ptr;
	const VALUE_PAIR *vp = *pvp;

	if (vp->vendor < VENDORPEC_EXTENDED) {
		fr_strerror_printf("rad_vp2extended called for non-extended attribute");
		return -1;
	}

	if (room < 3) return 0;

	ptr[0] = vp->attribute & 0xff;
	ptr[1] = 3;

	if (vp->flags.extended) {
		ptr[2] = (vp->attribute & 0xff00) >> 8;

	} else if (vp->flags.long_extended) {
		if (room < 4) return 0;

		ptr[1] = 4;
		ptr[2] = (vp->attribute & 0xff00) >> 8;
		ptr[3] = 0;
	}

	/*
	 *	Only "flagged" attributes can be longer than one
	 *	attribute.
	 */
	if (!vp->flags.long_extended && (room > 255)) {
		room = 255;
	}

	/*
	 *	Handle EVS VSAs.
	 */
	if (vp->flags.evs) {
		uint8_t *evs = ptr + ptr[1];

		if (room < (size_t) (ptr[1] + 5)) return 0;

		/*
		 *	RADIUS Attribute Type is packed into the high byte
		 *	of the Vendor Id.  So over-write it in the packet.
		 *
		 *	And hard-code Extended-Type to Vendor-Specific.
		 */
		ptr[0] = (vp->vendor >> 24) & 0xff;
		ptr[2] = 26;

		evs[0] = 0;	/* always zero */
		evs[1] = (vp->vendor >> 16) & 0xff;
		evs[2] = (vp->vendor >> 8) & 0xff;
		evs[3] = vp->vendor & 0xff;
		evs[4] = vp->attribute & 0xff;		

		ptr[1] += 5;
		nest = 0;
	}
	hdr_len = ptr[1];

	len = vp2data_any(packet, original, secret, nest,
			  pvp, ptr + ptr[1], room - hdr_len);
	if (len <= 0) return len;

	/*
	 *	There may be more than 252 octets of data encoded in
	 *	the attribute.  If so, move the data up in the packet,
	 *	and copy the existing header over.  Set the "M" flag ONLY
	 *	after copying the rest of the data.
	 */
	if (vp->flags.long_extended && (len > (255 - ptr[1]))) {
		return attr_shift(start, start + room, ptr, 4, len, 3, 0);
	}

	ptr[1] += len;
	
#ifndef NDEBUG
	if ((fr_debug_flag > 3) && fr_log_fp) {
		int jump = 3;

		fprintf(fr_log_fp, "\t\t%02x %02x  ", ptr[0], ptr[1]);
		if (!vp->flags.long_extended) {
			fprintf(fr_log_fp, "%02x  ", ptr[2]);
			
		} else {
			fprintf(fr_log_fp, "%02x %02x  ", ptr[2], ptr[3]);
			jump = 4;
		}

		if (vp->flags.evs) {
			fprintf(fr_log_fp, "%02x%02x%02x%02x (%u)  %02x  ",
				ptr[jump], ptr[jump + 1],
				ptr[jump + 2], ptr[jump + 3],
				((ptr[jump + 1] << 16) |
				 (ptr[jump + 2] << 8) |
				 ptr[jump + 3]),
				ptr[jump + 4]);
			jump += 5;
		}

		print_hex_data(ptr + jump, len, 3);
	}
#endif

	return (ptr + ptr[1]) - start;
}


/**
 * @brief Encode a WiMAX attribute.
 */
int rad_vp2wimax(const RADIUS_PACKET *packet,
		 const RADIUS_PACKET *original,
		 const char *secret, const VALUE_PAIR **pvp,
		 uint8_t *ptr, size_t room)
{
	int len;
	uint32_t lvalue;
	int hdr_len;
	uint8_t *start = ptr;
	const VALUE_PAIR *vp = *pvp;

	/*
	 *	Double-check for WiMAX format.
	 */
	if (!vp->flags.wimax) {
		fr_strerror_printf("rad_vp2wimax called for non-WIMAX VSA");
		return -1;
	}

	/*
	 *	Not enough room for:
	 *		attr, len, vendor-id, vsa, vsalen, continuation
	 */
	if (room < 9) return 0;

	/*
	 *	Build the Vendor-Specific header
	 */
	ptr = start;
	ptr[0] = PW_VENDOR_SPECIFIC;
	ptr[1] = 9;
	lvalue = htonl(vp->vendor);
	memcpy(ptr + 2, &lvalue, 4);
	ptr[6] = (vp->attribute & fr_attr_mask[1]);
	ptr[7] = 3;
	ptr[8] = 0;		/* continuation byte */

	hdr_len = 9;

	len = vp2data_any(packet, original, secret, 0, pvp, ptr + ptr[1],
			  room - hdr_len);
	if (len <= 0) return len;

	/*
	 *	There may be more than 252 octets of data encoded in
	 *	the attribute.  If so, move the data up in the packet,
	 *	and copy the existing header over.  Set the "C" flag
	 *	ONLY after copying the rest of the data.
	 */
	if (len > (255 - ptr[1])) {
		return attr_shift(start, start + room, ptr, hdr_len, len, 8, 7);
	}

	ptr[1] += len;
	ptr[7] += len;

#ifndef NDEBUG
	if ((fr_debug_flag > 3) && fr_log_fp) {
		fprintf(fr_log_fp, "\t\t%02x %02x  %02x%02x%02x%02x (%u)  %02x %02x %02x   ",
		       ptr[0], ptr[1],
		       ptr[2], ptr[3], ptr[4], ptr[5],
		       (ptr[3] << 16) | (ptr[4] << 8) | ptr[5],
		       ptr[6], ptr[7], ptr[8]);
		print_hex_data(ptr + 9, len, 3);
	}
#endif

	return (ptr + ptr[1]) - start;
}

/**
 * @brief Encode an RFC format TLV.
 *
 * 	This could be a standard attribute,
 *	or a TLV data type.  If it's a standard attribute, then
 *	vp->attribute == attribute.  Otherwise, attribute may be
 *	something else.
 */
static ssize_t vp2attr_rfc(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   const char *secret, const VALUE_PAIR **pvp,
			   unsigned int attribute, uint8_t *ptr, size_t room)
{
	ssize_t len;

	if (room < 2) return 0;

	ptr[0] = attribute & 0xff;
	ptr[1] = 2;

	if (room > ((unsigned) 255 - ptr[1])) room = 255 - ptr[1];

	len = vp2data_any(packet, original, secret, 0, pvp, ptr + ptr[1], room);
	if (len <= 0) return len;

	ptr[1] += len;

#ifndef NDEBUG
	if ((fr_debug_flag > 3) && fr_log_fp) {
		fprintf(fr_log_fp, "\t\t%02x %02x  ", ptr[0], ptr[1]);
		print_hex_data(ptr + 2, len, 3);
	}
#endif

	return ptr[1];
}


/**
 * @brief Encode a VSA which is a TLV.  If it's in the RFC format, call
 *	vp2attr_rfc.  Otherwise, encode it here.
 */
static ssize_t vp2attr_vsa(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   const char *secret, const VALUE_PAIR **pvp,
			   unsigned int attribute, unsigned int vendor,
			   uint8_t *ptr, size_t room)
{
	ssize_t len;
	DICT_VENDOR *dv;
	const VALUE_PAIR *vp = *pvp;

	/*
	 *	Unknown vendor: RFC format.
	 *	Known vendor and RFC format: go do that.
	 */
	dv = dict_vendorbyvalue(vendor);
	if (!dv ||
	    (!vp->flags.is_tlv && (dv->type == 1) && (dv->length == 1))) {
		return vp2attr_rfc(packet, original, secret, pvp,
				   attribute, ptr, room);
	}

	switch (dv->type) {
	default:
		fr_strerror_printf("vp2attr_vsa: Internal sanity check failed,"
				   " type %u", (unsigned) dv->type);
		return -1;

	case 4:
		ptr[0] = 0;	/* attr must be 24-bit */
		ptr[1] = (attribute >> 16) & 0xff;
		ptr[2] = (attribute >> 8) & 0xff;
		ptr[3] = attribute & 0xff;
		break;

	case 2:
		ptr[0] = (attribute >> 8) & 0xff;
		ptr[1] = attribute & 0xff;
		break;

	case 1:
		ptr[0] = attribute & 0xff;
		break;
	}

	switch (dv->length) {
	default:
		fr_strerror_printf("vp2attr_vsa: Internal sanity check failed,"
				   " length %u", (unsigned) dv->length);
		return -1;

	case 0:
		break;

	case 2:
		ptr[dv->type] = 0;
		ptr[dv->type + 1] = dv->type + 2;
		break;

	case 1:
		ptr[dv->type] = dv->type + 1;
		break;

	}

	if (room > ((unsigned) 255 - (dv->type + dv->length))) {
		room = 255 - (dv->type + dv->length);
	}

	len = vp2data_any(packet, original, secret, 0, pvp,
			  ptr + dv->type + dv->length, room);
	if (len <= 0) return len;

	if (dv->length) ptr[dv->type + dv->length - 1] += len;

#ifndef NDEBUG
	if ((fr_debug_flag > 3) && fr_log_fp) {
		switch (dv->type) {
		default:
			break;

		case 4:
			if ((fr_debug_flag > 3) && fr_log_fp)
				fprintf(fr_log_fp, "\t\t%02x%02x%02x%02x ",
					ptr[0], ptr[1], ptr[2], ptr[3]);
			break;
			
		case 2:
			if ((fr_debug_flag > 3) && fr_log_fp)
				fprintf(fr_log_fp, "\t\t%02x%02x ",
					ptr[0], ptr[1]);
		break;
		
		case 1:
			if ((fr_debug_flag > 3) && fr_log_fp)
				fprintf(fr_log_fp, "\t\t%02x ", ptr[0]);
			break;
		}
		
		switch (dv->length) {
		default:
			break;

		case 0:
			fprintf(fr_log_fp, "  ");
			break;

		case 1:
			fprintf(fr_log_fp, "%02x  ",
				ptr[dv->type]);
			break;

		case 2:
			fprintf(fr_log_fp, "%02x%02x  ",
				ptr[dv->type], ptr[dv->type] + 1);
			break;
		}

		print_hex_data(ptr + dv->type + dv->length, len, 3);
	}
#endif

	return dv->type + dv->length + len;
}


/**
 * @brief Encode a Vendor-Specific attribute.
 */
int rad_vp2vsa(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
		const char *secret, const VALUE_PAIR **pvp, uint8_t *ptr,
		size_t room)
{
	ssize_t len;
	uint32_t lvalue;
	const VALUE_PAIR *vp = *pvp;

	/*
	 *	Double-check for WiMAX format.
	 */
	if (vp->flags.wimax) {
		return rad_vp2wimax(packet, original, secret, pvp,
				    ptr, room);
	}

	if (vp->vendor > FR_MAX_VENDOR) {
		fr_strerror_printf("rad_vp2vsa: Invalid arguments");
		return -1;
	}

	/*
	 *	Not enough room for:
	 *		attr, len, vendor-id
	 */
	if (room < 6) return 0;

	/*
	 *	Build the Vendor-Specific header
	 */
	ptr[0] = PW_VENDOR_SPECIFIC;
	ptr[1] = 6;
	lvalue = htonl(vp->vendor);
	memcpy(ptr + 2, &lvalue, 4);

	if (room > ((unsigned) 255 - ptr[1])) room = 255 - ptr[1];

	len = vp2attr_vsa(packet, original, secret, pvp,
			  vp->attribute, vp->vendor,
			  ptr + ptr[1], room);
	if (len < 0) return len;

#ifndef NDEBUG
	if ((fr_debug_flag > 3) && fr_log_fp) {
		fprintf(fr_log_fp, "\t\t%02x %02x  %02x%02x%02x%02x (%u)  ",
		       ptr[0], ptr[1],
		       ptr[2], ptr[3], ptr[4], ptr[5],
		       (ptr[3] << 16) | (ptr[4] << 8) | ptr[5]);
		print_hex_data(ptr + 6, len, 3);
	}
#endif

	ptr[1] += len;

	return ptr[1];
}


/**
 * @brief Encode an RFC standard attribute 1..255
 */
int rad_vp2rfc(const RADIUS_PACKET *packet,
	       const RADIUS_PACKET *original,
	       const char *secret, const VALUE_PAIR **pvp,
	       uint8_t *ptr, size_t room)
{
	const VALUE_PAIR *vp = *pvp;

	if (vp->vendor != 0) {
		fr_strerror_printf("rad_vp2rfc called with VSA");
		return -1;
	}

	if ((vp->attribute == 0) || (vp->attribute > 255)) {
		fr_strerror_printf("rad_vp2rfc called with non-standard attribute %u", vp->attribute);
		return -1;
	}

	/*
	 *	Only CUI is allowed to have zero length.
	 *	Thank you, WiMAX!
	 */
	if ((vp->length == 0) &&
	    (vp->attribute == PW_CHARGEABLE_USER_IDENTITY)) {
		ptr[0] = PW_CHARGEABLE_USER_IDENTITY;
		ptr[1] = 2;

		*pvp = vp->next;
		return 2;
	}

	return vp2attr_rfc(packet, original, secret, pvp, vp->attribute,
			   ptr, room);
}


/**
 * @brief Parse a data structure into a RADIUS attribute.
 */
int rad_vp2attr(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
		const char *secret, const VALUE_PAIR **pvp, uint8_t *start,
		size_t room)
{
	const VALUE_PAIR *vp;

	if (!pvp || !*pvp || !start || (room <= 2)) return -1;

	vp = *pvp;

	/*
	 *	RFC format attributes take the fast path.
	 */
	if (vp->vendor == 0) {
		if (vp->attribute > 255) return 0;

		/*
		 *	Message-Authenticator is hard-coded.
		 */
		if (vp->attribute == PW_MESSAGE_AUTHENTICATOR) {
			if (room < 18) return -1;
			
			debug_pair(vp);
			start[0] = PW_MESSAGE_AUTHENTICATOR;
			start[1] = 18;
			memset(start + 2, 0, 16);
#ifndef NDEBUG
			if ((fr_debug_flag > 3) && fr_log_fp) {
				fprintf(fr_log_fp, "\t\t50 12 ...\n");
			}
#endif

			*pvp = (*pvp)->next;
			return 18;
		}

		return rad_vp2rfc(packet, original, secret, pvp,
				  start, room);
	}

	if (vp->vendor > FR_MAX_VENDOR) {
		return rad_vp2extended(packet, original, secret, pvp,
				       start, room);
	}

	if (vp->flags.wimax) {
		return rad_vp2wimax(packet, original, secret, pvp,
				    start, room);
	}

	return rad_vp2vsa(packet, original, secret, pvp,
			  start, room);
}


/**
 * @brief Encode a packet.
 */
int rad_encode(RADIUS_PACKET *packet, const RADIUS_PACKET *original,
	       const char *secret)
{
	radius_packet_t	*hdr;
	uint8_t	        *ptr;
	uint16_t	total_length;
	int		len;
	const VALUE_PAIR	*reply;
	const char	*what;
	char		ip_src_buffer[128];
	char		ip_dst_buffer[128];

	/*
	 *	A 4K packet, aligned on 64-bits.
	 */
	uint64_t	data[MAX_PACKET_LEN / sizeof(uint64_t)];

	if ((packet->code > 0) && (packet->code < FR_MAX_PACKET_CODE)) {
		what = fr_packet_codes[packet->code];
	} else {
		what = "Reply";
	}

	DEBUG("Sending %s of id %d from %s port %u to %s port %u\n",
	      what, packet->id,
	      inet_ntop(packet->src_ipaddr.af,
			&packet->src_ipaddr.ipaddr,
			ip_src_buffer, sizeof(ip_src_buffer)),
	      packet->src_port,
	      inet_ntop(packet->dst_ipaddr.af,
			&packet->dst_ipaddr.ipaddr,
			ip_dst_buffer, sizeof(ip_dst_buffer)),
	      packet->dst_port);

	/*
	 *	Double-check some things based on packet code.
	 */
	switch (packet->code) {
	case PW_AUTHENTICATION_ACK:
	case PW_AUTHENTICATION_REJECT:
	case PW_ACCESS_CHALLENGE:
		if (!original) {
			fr_strerror_printf("ERROR: Cannot sign response packet without a request packet.");
			return -1;
		}
		break;

		/*
		 *	These packet vectors start off as all zero.
		 */
	case PW_ACCOUNTING_REQUEST:
	case PW_DISCONNECT_REQUEST:
	case PW_COA_REQUEST:
		memset(packet->vector, 0, sizeof(packet->vector));
		break;

	default:
		break;
	}

	/*
	 *	Use memory on the stack, until we know how
	 *	large the packet will be.
	 */
	hdr = (radius_packet_t *) data;

	/*
	 *	Build standard header
	 */
	hdr->code = packet->code;
	hdr->id = packet->id;

	memcpy(hdr->vector, packet->vector, sizeof(hdr->vector));

	total_length = AUTH_HDR_LEN;

	/*
	 *	Load up the configuration values for the user
	 */
	ptr = hdr->data;
	packet->offset = 0;

	/*
	 *	FIXME: Loop twice over the reply list.  The first time,
	 *	calculate the total length of data.  The second time,
	 *	allocate the memory, and fill in the VP's.
	 *
	 *	Hmm... this may be slower than just doing a small
	 *	memcpy.
	 */

	/*
	 *	Loop over the reply attributes for the packet.
	 */
	reply = packet->vps;
	while (reply) {
		size_t last_len;
		const char *last_name = NULL;

		/*
		 *	Ignore non-wire attributes, but allow extended
		 *	attributes.
		 */
		if ((reply->vendor == 0) &&
		    ((reply->attribute & 0xFFFF) >= 256) &&
		    !reply->flags.extended && !reply->flags.long_extended) {
#ifndef NDEBUG
			/*
			 *	Permit the admin to send BADLY formatted
			 *	attributes with a debug build.
			 */
			if (reply->attribute == PW_RAW_ATTRIBUTE) {
				memcpy(ptr, reply->vp_octets, reply->length);
				len = reply->length;
				reply = reply->next;
				goto next;
			}
#endif
			reply = reply->next;
			continue;
		}

		/*
		 *	Set the Message-Authenticator to the correct
		 *	length and initial value.
		 */
		if (reply->attribute == PW_MESSAGE_AUTHENTICATOR) {
			/*
			 *	Cache the offset to the
			 *	Message-Authenticator
			 */
			packet->offset = total_length;
			last_len = 16;
		} else {
			last_len = reply->length;
		}
		last_name = reply->name;

		len = rad_vp2attr(packet, original, secret, &reply, ptr,
				  ((uint8_t *) data) + sizeof(data) - ptr);
		if (len < 0) return -1;

		/*
		 *	Failed to encode the attribute, likely because
		 *	the packet is full.
		 */
		if (len == 0) {
			if (last_len != 0) {
				DEBUG("WARNING: Failed encoding attribute %s\n", last_name);
			} else {
				DEBUG("WARNING: Skipping zero-length attribute %s\n", last_name);
			}
		}

#ifndef NDEBUG
	next:			/* Used only for Raw-Attribute */
#endif
		ptr += len;
		total_length += len;
	} /* done looping over all attributes */

	/*
	 *	Fill in the rest of the fields, and copy the data over
	 *	from the local stack to the newly allocated memory.
	 *
	 *	Yes, all this 'memcpy' is slow, but it means
	 *	that we only allocate the minimum amount of
	 *	memory for a request.
	 */
	packet->data_len = total_length;
	packet->data = (uint8_t *) malloc(packet->data_len);
	if (!packet->data) {
		fr_strerror_printf("Out of memory");
		return -1;
	}

	memcpy(packet->data, hdr, packet->data_len);
	hdr = (radius_packet_t *) packet->data;

	total_length = htons(total_length);
	memcpy(hdr->length, &total_length, sizeof(total_length));

	return 0;
}


/**
 * @brief Sign a previously encoded packet.
 */
int rad_sign(RADIUS_PACKET *packet, const RADIUS_PACKET *original,
	     const char *secret)
{
	radius_packet_t	*hdr = (radius_packet_t *)packet->data;

	/*
	 *	It wasn't assigned an Id, this is bad!
	 */
	if (packet->id < 0) {
		fr_strerror_printf("ERROR: RADIUS packets must be assigned an Id.");
		return -1;
	}

	if (!packet->data || (packet->data_len < AUTH_HDR_LEN) ||
	    (packet->offset < 0)) {
		fr_strerror_printf("ERROR: You must call rad_encode() before rad_sign()");
		return -1;
	}

	/*
	 *	If there's a Message-Authenticator, update it
	 *	now, BEFORE updating the authentication vector.
	 */
	if (packet->offset > 0) {
		uint8_t calc_auth_vector[AUTH_VECTOR_LEN];

		switch (packet->code) {
		case PW_ACCOUNTING_RESPONSE:
			if (original && original->code == PW_STATUS_SERVER) {
				goto do_ack;
			}

		case PW_ACCOUNTING_REQUEST:
		case PW_DISCONNECT_REQUEST:
		case PW_DISCONNECT_ACK:
		case PW_DISCONNECT_NAK:
		case PW_COA_REQUEST:
		case PW_COA_ACK:
		case PW_COA_NAK:
			memset(hdr->vector, 0, AUTH_VECTOR_LEN);
			break;

		do_ack:
		case PW_AUTHENTICATION_ACK:
		case PW_AUTHENTICATION_REJECT:
		case PW_ACCESS_CHALLENGE:
			if (!original) {
				fr_strerror_printf("ERROR: Cannot sign response packet without a request packet.");
				return -1;
			}
			memcpy(hdr->vector, original->vector,
			       AUTH_VECTOR_LEN);
			break;

		default:	/* others have vector already set to zero */
			break;

		}

		/*
		 *	Set the authentication vector to zero,
		 *	calculate the HMAC, and put it
		 *	into the Message-Authenticator
		 *	attribute.
		 */
		fr_hmac_md5(packet->data, packet->data_len,
			    (const uint8_t *) secret, strlen(secret),
			    calc_auth_vector);
		memcpy(packet->data + packet->offset + 2,
		       calc_auth_vector, AUTH_VECTOR_LEN);

		/*
		 *	Copy the original request vector back
		 *	to the raw packet.
		 */
		memcpy(hdr->vector, packet->vector, AUTH_VECTOR_LEN);
	}

	/*
	 *	Switch over the packet code, deciding how to
	 *	sign the packet.
	 */
	switch (packet->code) {
		/*
		 *	Request packets are not signed, bur
		 *	have a random authentication vector.
		 */
	case PW_AUTHENTICATION_REQUEST:
	case PW_STATUS_SERVER:
		break;

		/*
		 *	Reply packets are signed with the
		 *	authentication vector of the request.
		 */
	default:
		{
			uint8_t digest[16];

			FR_MD5_CTX	context;
			fr_MD5Init(&context);
			fr_MD5Update(&context, packet->data, packet->data_len);
			fr_MD5Update(&context, (const uint8_t *) secret,
				     strlen(secret));
			fr_MD5Final(digest, &context);

			memcpy(hdr->vector, digest, AUTH_VECTOR_LEN);
			memcpy(packet->vector, digest, AUTH_VECTOR_LEN);
			break;
		}
	}/* switch over packet codes */

	return 0;
}

/**
 * @brief Reply to the request.  Also attach
 *	reply attribute value pairs and any user message provided.
 */
int rad_send(RADIUS_PACKET *packet, const RADIUS_PACKET *original,
	     const char *secret)
{
	VALUE_PAIR		*reply;
	const char		*what;
	char			ip_src_buffer[128];
	char			ip_dst_buffer[128];

	/*
	 *	Maybe it's a fake packet.  Don't send it.
	 */
	if (!packet || (packet->sockfd < 0)) {
		return 0;
	}

	if ((packet->code > 0) && (packet->code < FR_MAX_PACKET_CODE)) {
		what = fr_packet_codes[packet->code];
	} else {
		what = "Reply";
	}

	/*
	 *  First time through, allocate room for the packet
	 */
	if (!packet->data) {
		/*
		 *	Encode the packet.
		 */
		if (rad_encode(packet, original, secret) < 0) {
			return -1;
		}

		/*
		 *	Re-sign it, including updating the
		 *	Message-Authenticator.
		 */
		if (rad_sign(packet, original, secret) < 0) {
			return -1;
		}

		/*
		 *	If packet->data points to data, then we print out
		 *	the VP list again only for debugging.
		 */
	} else if (fr_debug_flag) {
	  	DEBUG("Sending %s of id %d from %s port %u to %s port %u\n", what,
	  	      packet->id,
	  	      inet_ntop(packet->src_ipaddr.af,
				&packet->src_ipaddr.ipaddr,
				ip_src_buffer, sizeof(ip_src_buffer)),
		      packet->src_port,
		      inet_ntop(packet->dst_ipaddr.af,
				&packet->dst_ipaddr.ipaddr,
				ip_dst_buffer, sizeof(ip_dst_buffer)),
		      packet->dst_port);

		for (reply = packet->vps; reply; reply = reply->next) {
			if ((reply->vendor == 0) &&
			    ((reply->attribute & 0xFFFF) > 0xff)) continue;
			debug_pair(reply);
		}
	}

#ifndef NDEBUG
	if ((fr_debug_flag > 3) && fr_log_fp) rad_print_hex(packet);
#endif

	/*
	 *	And send it on it's way.
	 */
	return rad_sendto(packet->sockfd, packet->data, packet->data_len, 0,
			  &packet->src_ipaddr, packet->src_port,
			  &packet->dst_ipaddr, packet->dst_port);
}

/**
 * @brief Do a comparison of two authentication digests by comparing
 *	the FULL digest.
 *
 *	Otherwise, the server can be subject to
 *	timing attacks that allow attackers find a valid message
 *	authenticator.
 *
 *	http://www.cs.rice.edu/~dwallach/pub/crosby-timing2009.pdf
 */
int rad_digest_cmp(const uint8_t *a, const uint8_t *b, size_t length)
{
	int result = 0;
	size_t i;

	for (i = 0; i < length; i++) {
		result |= a[i] ^ b[i];
	}

	return result;		/* 0 is OK, !0 is !OK, just like memcmp */
}


/**
 * @brief Validates the requesting client NAS.  Calculates the
 *	Request Authenticator based on the clients private key.
 */
static int calc_acctdigest(RADIUS_PACKET *packet, const char *secret)
{
	uint8_t		digest[AUTH_VECTOR_LEN];
	FR_MD5_CTX		context;

	/*
	 *	Zero out the auth_vector in the received packet.
	 *	Then append the shared secret to the received packet,
	 *	and calculate the MD5 sum. This must be the same
	 *	as the original MD5 sum (packet->vector).
	 */
	memset(packet->data + 4, 0, AUTH_VECTOR_LEN);

	/*
	 *  MD5(packet + secret);
	 */
	fr_MD5Init(&context);
	fr_MD5Update(&context, packet->data, packet->data_len);
	fr_MD5Update(&context, (const uint8_t *) secret, strlen(secret));
	fr_MD5Final(digest, &context);

	/*
	 *	Return 0 if OK, 2 if not OK.
	 */
	if (rad_digest_cmp(digest, packet->vector, AUTH_VECTOR_LEN) != 0) return 2;
	return 0;
}


/**
 * @brief Validates the requesting client NAS.  Calculates the
 *	Response Authenticator based on the clients private key.
 */
static int calc_replydigest(RADIUS_PACKET *packet, RADIUS_PACKET *original,
			    const char *secret)
{
	uint8_t		calc_digest[AUTH_VECTOR_LEN];
	FR_MD5_CTX		context;

	/*
	 *	Very bad!
	 */
	if (original == NULL) {
		return 3;
	}

	/*
	 *  Copy the original vector in place.
	 */
	memcpy(packet->data + 4, original->vector, AUTH_VECTOR_LEN);

	/*
	 *  MD5(packet + secret);
	 */
	fr_MD5Init(&context);
	fr_MD5Update(&context, packet->data, packet->data_len);
	fr_MD5Update(&context, (const uint8_t *) secret, strlen(secret));
	fr_MD5Final(calc_digest, &context);

	/*
	 *  Copy the packet's vector back to the packet.
	 */
	memcpy(packet->data + 4, packet->vector, AUTH_VECTOR_LEN);

	/*
	 *	Return 0 if OK, 2 if not OK.
	 */
	if (rad_digest_cmp(packet->vector, calc_digest, AUTH_VECTOR_LEN) != 0) return 2;
	return 0;
}


/**
 * @brief Check if a set of RADIUS formatted TLVs are OK.
 */
int rad_tlv_ok(const uint8_t *data, size_t length,
	       size_t dv_type, size_t dv_length)
{
	const uint8_t *end = data + length;

	if ((dv_length > 2) || (dv_type == 0) || (dv_type > 4)) {
		fr_strerror_printf("rad_tlv_ok: Invalid arguments");
		return -1;
	}

	while (data < end) {
		size_t attrlen;

		if ((data + dv_type + dv_length) > end) {
			fr_strerror_printf("Attribute header overflow");
			return -1;
		}

		switch (dv_type) {
		case 4:
			if ((data[0] == 0) && (data[1] == 0) &&
			    (data[2] == 0) && (data[3] == 0)) {
			zero:
				fr_strerror_printf("Invalid attribute 0");
				return -1;
			}

			if (data[0] != 0) {
				fr_strerror_printf("Invalid attribute > 2^24");
				return -1;
			}
			break;

		case 2:
			if ((data[1] == 0) && (data[1] == 0)) goto zero;
			break;

		case 1:
			if (data[0] == 0) goto zero;
			break;

		default:
			fr_strerror_printf("Internal sanity check failed");
			return -1;
		}

		switch (dv_length) {
		case 0:
			return 0;

		case 2:
			if (data[dv_type + 1] != 0) {
				fr_strerror_printf("Attribute is longer than 256 octets");
				return -1;
			}
			/* FALL-THROUGH */
		case 1:
			attrlen = data[dv_type + dv_length - 1];
			break;


		default:
			fr_strerror_printf("Internal sanity check failed");
			return -1;
		}

		if (attrlen < (dv_type + dv_length)) {
			fr_strerror_printf("Attribute header has invalid length");
			return -1;
		}

		if (attrlen > length) {
			fr_strerror_printf("Attribute overflows container");
			return -1;
		}

		data += attrlen;
		length -= attrlen;
	}

	return 0;
}


/**
 * @brief See if the data pointed to by PTR is a valid RADIUS packet.
 *
 *	packet is not 'const * const' because we may update data_len,
 *	if there's more data in the UDP packet than in the RADIUS packet.
 */
int rad_packet_ok(RADIUS_PACKET *packet, int flags)
{
	uint8_t			*attr;
	size_t			totallen;
	int			count;
	radius_packet_t		*hdr;
	char			host_ipaddr[128];
	int			require_ma = 0;
	int			seen_ma = 0;
	int			num_attributes;

	/*
	 *	Check for packets smaller than the packet header.
	 *
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"The minimum length is 20 ..."
	 */
	if (packet->data_len < AUTH_HDR_LEN) {
		fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: too short (received %zu < minimum %d)",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
				     packet->data_len, AUTH_HDR_LEN);
		return 0;
	}

	/*
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	" ... and maximum length is 4096."
	 */
	if (packet->data_len > MAX_PACKET_LEN) {
		fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: too long (received %zu > maximum %d)",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
				     packet->data_len, MAX_PACKET_LEN);
		return 0;
	}

	/*
	 *	Check for packets with mismatched size.
	 *	i.e. We've received 128 bytes, and the packet header
	 *	says it's 256 bytes long.
	 */
	totallen = (packet->data[2] << 8) | packet->data[3];
	hdr = (radius_packet_t *)packet->data;

	/*
	 *	Code of 0 is not understood.
	 *	Code of 16 or greate is not understood.
	 */
	if ((hdr->code == 0) ||
	    (hdr->code >= FR_MAX_PACKET_CODE)) {
		fr_strerror_printf("WARNING: Bad RADIUS packet from host %s: unknown packet code%d ",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
			   hdr->code);
		return 0;
	}

	/*
	 *	Message-Authenticator is required in Status-Server
	 *	packets, otherwise they can be trivially forged.
	 */
	if (hdr->code == PW_STATUS_SERVER) require_ma = 1;

	/*
	 *	It's also required if the caller asks for it.
	 */
	if (flags) require_ma = 1;

	/*
	 *	Repeat the length checks.  This time, instead of
	 *	looking at the data we received, look at the value
	 *	of the 'length' field inside of the packet.
	 *
	 *	Check for packets smaller than the packet header.
	 *
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"The minimum length is 20 ..."
	 */
	if (totallen < AUTH_HDR_LEN) {
		fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: too short (length %zu < minimum %d)",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
				     totallen, AUTH_HDR_LEN);
		return 0;
	}

	/*
	 *	And again, for the value of the 'length' field.
	 *
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	" ... and maximum length is 4096."
	 */
	if (totallen > MAX_PACKET_LEN) {
		fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: too long (length %zu > maximum %d)",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
			             totallen, MAX_PACKET_LEN);
		return 0;
	}

	/*
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"If the packet is shorter than the Length field
	 *	indicates, it MUST be silently discarded."
	 *
	 *	i.e. No response to the NAS.
	 */
	if (packet->data_len < totallen) {
		fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: received %zu octets, packet length says %zu",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
				     packet->data_len, totallen);
		return 0;
	}

	/*
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"Octets outside the range of the Length field MUST be
	 *	treated as padding and ignored on reception."
	 */
	if (packet->data_len > totallen) {
		/*
		 *	We're shortening the packet below, but just
		 *	to be paranoid, zero out the extra data.
		 */
		memset(packet->data + totallen, 0, packet->data_len - totallen);
		packet->data_len = totallen;
	}

	/*
	 *	Walk through the packet's attributes, ensuring that
	 *	they add up EXACTLY to the size of the packet.
	 *
	 *	If they don't, then the attributes either under-fill
	 *	or over-fill the packet.  Any parsing of the packet
	 *	is impossible, and will result in unknown side effects.
	 *
	 *	This would ONLY happen with buggy RADIUS implementations,
	 *	or with an intentional attack.  Either way, we do NOT want
	 *	to be vulnerable to this problem.
	 */
	attr = hdr->data;
	count = totallen - AUTH_HDR_LEN;
	num_attributes = 0;

	while (count > 0) {
		/*
		 *	We need at least 2 bytes to check the
		 *	attribute header.
		 */
		if (count < 2) {
			fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: attribute header overflows the packet",
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
					     host_ipaddr, sizeof(host_ipaddr)));
			return 0;
		}

		/*
		 *	Attribute number zero is NOT defined.
		 */
		if (attr[0] == 0) {
			fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: Invalid attribute 0",
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
					     host_ipaddr, sizeof(host_ipaddr)));
			return 0;
		}

		/*
		 *	Attributes are at LEAST as long as the ID & length
		 *	fields.  Anything shorter is an invalid attribute.
		 */
       		if (attr[1] < 2) {
			fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: attribute %u too short",
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
					     host_ipaddr, sizeof(host_ipaddr)),
				   attr[0]);
			return 0;
		}

		/*
		 *	If there are fewer bytes in the packet than in the
		 *	attribute, it's a bad packet.
		 */
		if (count < attr[1]) {
			fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: attribute %u data overflows the packet",
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
					     host_ipaddr, sizeof(host_ipaddr)),
					   attr[0]);
			return 0;
		}

		/*
		 *	Sanity check the attributes for length.
		 */
		switch (attr[0]) {
		default:	/* don't do anything by default */
			break;

			/*
			 *	If there's an EAP-Message, we require
			 *	a Message-Authenticator.
			 */
		case PW_EAP_MESSAGE:
			require_ma = 1;
			break;

		case PW_MESSAGE_AUTHENTICATOR:
			if (attr[1] != 2 + AUTH_VECTOR_LEN) {
				fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: Message-Authenticator has invalid length %d",
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     host_ipaddr, sizeof(host_ipaddr)),
					   attr[1] - 2);
				return 0;
			}
			seen_ma = 1;
			break;
		}

		/*
		 *	FIXME: Look up the base 255 attributes in the
		 *	dictionary, and switch over their type.  For
		 *	integer/date/ip, the attribute length SHOULD
		 *	be 6.
		 */
		count -= attr[1];	/* grab the attribute length */
		attr += attr[1];
		num_attributes++;	/* seen one more attribute */
	}

	/*
	 *	If the attributes add up to a packet, it's allowed.
	 *
	 *	If not, we complain, and throw the packet away.
	 */
	if (count != 0) {
		fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: packet attributes do NOT exactly fill the packet",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)));
		return 0;
	}

	/*
	 *	If we're configured to look for a maximum number of
	 *	attributes, and we've seen more than that maximum,
	 *	then throw the packet away, as a possible DoS.
	 */
	if ((fr_max_attributes > 0) &&
	    (num_attributes > fr_max_attributes)) {
		fr_strerror_printf("WARNING: Possible DoS attack from host %s: Too many attributes in request (received %d, max %d are allowed).",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
			   num_attributes, fr_max_attributes);
		return 0;
	}

	/*
	 * 	http://www.freeradius.org/rfc/rfc2869.html#EAP-Message
	 *
	 *	A packet with an EAP-Message attribute MUST also have
	 *	a Message-Authenticator attribute.
	 *
	 *	A Message-Authenticator all by itself is OK, though.
	 *
	 *	Similarly, Status-Server packets MUST contain
	 *	Message-Authenticator attributes.
	 */
	if (require_ma && ! seen_ma) {
		fr_strerror_printf("WARNING: Insecure packet from host %s:  Packet does not contain required Message-Authenticator attribute",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)));
		return 0;
	}

	/*
	 *	Fill RADIUS header fields
	 */
	packet->code = hdr->code;
	packet->id = hdr->id;
	memcpy(packet->vector, hdr->vector, AUTH_VECTOR_LEN);

	return 1;
}


/**
 * @brief Receive UDP client requests, and fill in
 *	the basics of a RADIUS_PACKET structure.
 */
RADIUS_PACKET *rad_recv(int fd, int flags)
{
	int sock_flags = 0;
	ssize_t data_len;
	RADIUS_PACKET		*packet;

	/*
	 *	Allocate the new request data structure
	 */
	if ((packet = malloc(sizeof(*packet))) == NULL) {
		fr_strerror_printf("out of memory");
		return NULL;
	}
	memset(packet, 0, sizeof(*packet));

	if (flags & 0x02) {
		sock_flags = MSG_PEEK;
		flags &= ~0x02;
	}

	data_len = rad_recvfrom(fd, &packet->data, sock_flags,
					&packet->src_ipaddr, &packet->src_port,
					&packet->dst_ipaddr, &packet->dst_port);

	/*
	 *	Check for socket errors.
	 */
	if (data_len < 0) {
		fr_strerror_printf("Error receiving packet: %s", strerror(errno));
		/* packet->data is NULL */
		free(packet);
		return NULL;
	}
	packet->data_len = data_len; /* unsigned vs signed */

	/*
	 *	If the packet is too big, then rad_recvfrom did NOT
	 *	allocate memory.  Instead, it just discarded the
	 *	packet.
	 */
	if (packet->data_len > MAX_PACKET_LEN) {
		fr_strerror_printf("Discarding packet: Larger than RFC limitation of 4096 bytes.");
		/* packet->data is NULL */
		free(packet);
		return NULL;
	}

	/*
	 *	Read no data.  Continue.
	 *	This check is AFTER the MAX_PACKET_LEN check above, because
	 *	if the packet is larger than MAX_PACKET_LEN, we also have
	 *	packet->data == NULL
	 */
	if ((packet->data_len == 0) || !packet->data) {
		fr_strerror_printf("Empty packet: Socket is not ready.");
		free(packet);
		return NULL;
	}

	/*
	 *	See if it's a well-formed RADIUS packet.
	 */
	if (!rad_packet_ok(packet, flags)) {
		rad_free(&packet);
		return NULL;
	}

	/*
	 *	Remember which socket we read the packet from.
	 */
	packet->sockfd = fd;

	/*
	 *	FIXME: Do even more filtering by only permitting
	 *	certain IP's.  The problem is that we don't know
	 *	how to do this properly for all possible clients...
	 */

	/*
	 *	Explicitely set the VP list to empty.
	 */
	packet->vps = NULL;

	if (fr_debug_flag) {
		char host_ipaddr[128];

		if ((packet->code > 0) && (packet->code < FR_MAX_PACKET_CODE)) {
			DEBUG("rad_recv: %s packet from host %s port %d",
			      fr_packet_codes[packet->code],
			      inet_ntop(packet->src_ipaddr.af,
					&packet->src_ipaddr.ipaddr,
					host_ipaddr, sizeof(host_ipaddr)),
			      packet->src_port);
		} else {
			DEBUG("rad_recv: Packet from host %s port %d code=%d",
			      inet_ntop(packet->src_ipaddr.af,
					&packet->src_ipaddr.ipaddr,
					host_ipaddr, sizeof(host_ipaddr)),
			      packet->src_port,
			      packet->code);
		}
		DEBUG(", id=%d, length=%d\n",
		      packet->id, (int) packet->data_len);
	}

#ifndef NDEBUG
	if ((fr_debug_flag > 3) && fr_log_fp) rad_print_hex(packet);
#endif

	return packet;
}


/**
 * @brief Verify the Request/Response Authenticator
 * 	(and Message-Authenticator if present) of a packet.
 */
int rad_verify(RADIUS_PACKET *packet, RADIUS_PACKET *original,
	       const char *secret)
{
	uint8_t			*ptr;
	int			length;
	int			attrlen;

	if (!packet || !packet->data) return -1;

	/*
	 *	Before we allocate memory for the attributes, do more
	 *	sanity checking.
	 */
	ptr = packet->data + AUTH_HDR_LEN;
	length = packet->data_len - AUTH_HDR_LEN;
	while (length > 0) {
		uint8_t	msg_auth_vector[AUTH_VECTOR_LEN];
		uint8_t calc_auth_vector[AUTH_VECTOR_LEN];

		attrlen = ptr[1];

		switch (ptr[0]) {
		default:	/* don't do anything. */
			break;

			/*
			 *	Note that more than one Message-Authenticator
			 *	attribute is invalid.
			 */
		case PW_MESSAGE_AUTHENTICATOR:
			memcpy(msg_auth_vector, &ptr[2], sizeof(msg_auth_vector));
			memset(&ptr[2], 0, AUTH_VECTOR_LEN);

			switch (packet->code) {
			default:
				break;

			case PW_ACCOUNTING_RESPONSE:
				if (original &&
				    (original->code == PW_STATUS_SERVER)) {
					goto do_ack;
				}

			case PW_ACCOUNTING_REQUEST:
			case PW_DISCONNECT_REQUEST:
			case PW_DISCONNECT_ACK:
			case PW_DISCONNECT_NAK:
			case PW_COA_REQUEST:
			case PW_COA_ACK:
			case PW_COA_NAK:
			  	memset(packet->data + 4, 0, AUTH_VECTOR_LEN);
				break;

			do_ack:
			case PW_AUTHENTICATION_ACK:
			case PW_AUTHENTICATION_REJECT:
			case PW_ACCESS_CHALLENGE:
				if (!original) {
					fr_strerror_printf("ERROR: Cannot validate Message-Authenticator in response packet without a request packet.");
					return -1;
				}
				memcpy(packet->data + 4, original->vector, AUTH_VECTOR_LEN);
				break;
			}

			fr_hmac_md5(packet->data, packet->data_len,
				    (const uint8_t *) secret, strlen(secret),
				    calc_auth_vector);
			if (rad_digest_cmp(calc_auth_vector, msg_auth_vector,
				   sizeof(calc_auth_vector)) != 0) {
				char buffer[32];
				fr_strerror_printf("Received packet from %s with invalid Message-Authenticator!  (Shared secret is incorrect.)",
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     buffer, sizeof(buffer)));
				/* Silently drop packet, according to RFC 3579 */
				return -1;
			} /* else the message authenticator was good */

			/*
			 *	Reinitialize Authenticators.
			 */
			memcpy(&ptr[2], msg_auth_vector, AUTH_VECTOR_LEN);
			memcpy(packet->data + 4, packet->vector, AUTH_VECTOR_LEN);
			break;
		} /* switch over the attributes */

		ptr += attrlen;
		length -= attrlen;
	} /* loop over the packet, sanity checking the attributes */

	/*
	 *	It looks like a RADIUS packet, but we don't know what it is
	 *	so can't validate the authenticators.
	 */
	if ((packet->code == 0) || (packet->code >= FR_MAX_PACKET_CODE)) {
		char buffer[32];
		fr_strerror_printf("Received Unknown packet code %d "
			   "from client %s port %d: Cannot validate Request/Response Authenticator.",
			   packet->code,
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     buffer, sizeof(buffer)),
			   packet->src_port);
		return -1;
	}

	/*
	 *	Calculate and/or verify Request or Response Authenticator.
	 */
	switch(packet->code) {
		int rcode;
		char buffer[32];

		case PW_AUTHENTICATION_REQUEST:
		case PW_STATUS_SERVER:
			/*
			 *	The authentication vector is random
			 *	nonsense, invented by the client.
			 */
			break;

		case PW_COA_REQUEST:
		case PW_DISCONNECT_REQUEST:
		case PW_ACCOUNTING_REQUEST:
			if (calc_acctdigest(packet, secret) > 1) {
				fr_strerror_printf("Received %s packet "
					   "from client %s with invalid Request Authenticator!  (Shared secret is incorrect.)",
					   fr_packet_codes[packet->code],
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     buffer, sizeof(buffer)));
				return -1;
			}
			break;

			/* Verify the reply digest */
		case PW_AUTHENTICATION_ACK:
		case PW_AUTHENTICATION_REJECT:
		case PW_ACCESS_CHALLENGE:
		case PW_ACCOUNTING_RESPONSE:
		case PW_DISCONNECT_ACK:
		case PW_DISCONNECT_NAK:
		case PW_COA_ACK:
		case PW_COA_NAK:
			rcode = calc_replydigest(packet, original, secret);
			if (rcode > 1) {
				fr_strerror_printf("Received %s packet "
					   "from home server %s port %d with invalid Response Authenticator!  (Shared secret is incorrect.)",
					   fr_packet_codes[packet->code],
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     buffer, sizeof(buffer)),
					   packet->src_port);
				return -1;
			}
			break;

		default:
			fr_strerror_printf("Received Unknown packet code %d "
				   "from client %s port %d: Cannot validate Request/Response Authenticator",
				   packet->code,
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
						     buffer, sizeof(buffer)),
				   packet->src_port);
			return -1;
	}

	return 0;
}


/**
 * @brief Create a "raw" attribute from the attribute contents.
 */
static ssize_t data2vp_raw(UNUSED const RADIUS_PACKET *packet,
			   UNUSED const RADIUS_PACKET *original,
			   UNUSED const char *secret,
			   unsigned int attribute, unsigned int vendor,
			   const uint8_t *data, size_t length,
			   VALUE_PAIR **pvp)
{
	VALUE_PAIR *vp;

	/*
	 *	Keep the next function happy.
	 */
	vp = pairalloc(NULL);
	vp = paircreate_raw(attribute, vendor, PW_TYPE_OCTETS, vp);
	if (!vp) {
		fr_strerror_printf("data2vp_raw: Failed creating attribute");
		return -1;
	}

	vp->length = length;

	/*
	 *	If it's short, put it into the array.  If it's too
	 *	long, flag it as such, and put it somewhere else;
	 */
	if (length <= sizeof(vp->vp_octets)) {
		memcpy(vp->vp_octets, data, length);
	} else {
		vp->type |= PW_FLAG_LONG;
		vp->vp_tlv = malloc(length);
		if (!vp->vp_tlv) {
			pairfree(&vp);
			return -1;
		}
		memcpy(vp->vp_tlv, data, length);
	}

	*pvp = vp;

	return length;
}


static ssize_t data2vp_tlvs(const RADIUS_PACKET *packet,
			    const RADIUS_PACKET *original,
			    const char *secret,
			    unsigned int attribute, unsigned int vendor,
			    int nest,
			    const uint8_t *start, size_t length,
			    VALUE_PAIR **pvp);

/**
 * @brief Create any kind of VP from the attribute contents.
 * @return -1 on error, or "length".
 */
static ssize_t data2vp_any(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   const char *secret, int nest,
			   unsigned int attribute, unsigned int vendor,
			   const uint8_t *data, size_t length,
			   VALUE_PAIR **pvp)
{
	int data_offset = 0;
	DICT_ATTR *da;
	VALUE_PAIR *vp = NULL;
	uint8_t buffer[256];

	if (length == 0) {
		/*
		 *	Hacks for CUI.  The WiMAX spec says that it
		 *	can be zero length, even though this is
		 *	forbidden by the RADIUS specs.  So... we make
		 *	a special case for it.
		 */
		if ((vendor == 0) &&
		    (attribute == PW_CHARGEABLE_USER_IDENTITY)) {
			data = (const uint8_t *) "";
			length = 1;
		} else {
			*pvp = NULL;
			return 0;
		}
	}

	da = dict_attrbyvalue(attribute, vendor);

	/*
	 *	Unknown attribute.  Create it as a "raw" attribute.
	 */
	if (!da) {
		VP_TRACE("Not found %u.%u\n", vendor, attribute);
	raw:
		if (vp) pairfree(&vp);
		return data2vp_raw(packet, original, secret,
				   attribute, vendor, data, length, pvp);
	}

	/*
	 *	TLVs are handled first.  They can't be tagged, and
	 *	they can't be encrypted.
	 */
	if (da->type == PW_TYPE_TLV) {
		VP_TRACE("Found TLV %u.%u\n", vendor, attribute);
		return data2vp_tlvs(packet, original, secret,
				    attribute, vendor, nest,
				    data, length, pvp);
	}

	/*
	 *	The data is very long.
	 */
	if (length > sizeof(vp->vp_octets)) {
		/*
		 *	Long encrypted attributes are forbidden.
		 */
		if (da->flags.encrypt != FLAG_ENCRYPT_NONE) goto raw;

#ifndef NDEBUG
		/*
		 *	Catch programming errors.
		 */
		if ((da->type != PW_TYPE_STRING) &&
		    (da->type != PW_TYPE_OCTETS)) goto raw;

#endif

		/*
		 *	FIXME: Figure out how to deal with long
		 *	strings and binary data!
		 */
		goto raw;
	}

	/*
	 *	The attribute is known, and well formed.  We can now
	 *	create it.  The main failure from here on in is being
	 *	out of memory.
	 */
	vp = pairalloc(da);
	if (!vp) return -1;

	/*
	 *	Handle tags.
	 */
	if (vp->flags.has_tag) {
		if (TAG_VALID(data[0]) ||
		    (vp->flags.encrypt == FLAG_ENCRYPT_TUNNEL_PASSWORD)) {
			/*
			 *	Tunnel passwords REQUIRE a tag, even
			 *	if don't have a valid tag.
			 */
			vp->flags.tag = data[0];

			if ((vp->type == PW_TYPE_STRING) ||
			    (vp->type == PW_TYPE_OCTETS)) {
				if (length == 0) goto raw;
				data_offset = 1;
			}
		}
	}

	/*
	 *	Copy the data to be decrypted
	 */
	vp->length = length - data_offset;	
	memcpy(buffer, data + data_offset, vp->length);

	/*
	 *	Decrypt the attribute.
	 */
	if (secret && packet) switch (vp->flags.encrypt) {
		/*
		 *  User-Password
		 */
	case FLAG_ENCRYPT_USER_PASSWORD:
		if (original) {
			rad_pwdecode((char *) buffer,
				     vp->length, secret,
				     original->vector);
		} else {
			rad_pwdecode((char *) buffer,
				     vp->length, secret,
				     packet->vector);
		}
		buffer[253] = '\0';
		if (vp->attribute == PW_USER_PASSWORD) {
			vp->length = strlen((char *) buffer);
		}
		break;

		/*
		 *	Tunnel-Password's may go ONLY
		 *	in response packets.
		 */
	case FLAG_ENCRYPT_TUNNEL_PASSWORD:
		if (rad_tunnel_pwdecode(buffer, &vp->length, secret,
					original ? original->vector : nullvector) < 0)
			goto raw;
		break;

		/*
		 *  Ascend-Send-Secret
		 *  Ascend-Receive-Secret
		 */
	case FLAG_ENCRYPT_ASCEND_SECRET:
		if (!original) {
			goto raw;
		} else {
			uint8_t my_digest[AUTH_VECTOR_LEN];
			make_secret(my_digest,
				    original->vector,
				    secret, data);
			memcpy(buffer, my_digest,
			       AUTH_VECTOR_LEN );
			buffer[AUTH_VECTOR_LEN] = '\0';
			vp->length = strlen((char *) buffer);
		}
		break;

	default:
		break;
	} /* switch over encryption flags */


	switch (vp->type) {
	case PW_TYPE_STRING:
		memcpy(vp->vp_strvalue, buffer, vp->length);
		vp->vp_strvalue[vp->length] = '\0';
		break;

	case PW_TYPE_OCTETS:
	case PW_TYPE_ABINARY:
		memcpy(vp->vp_octets, buffer, vp->length);
		break;

	case PW_TYPE_BYTE:
		if (vp->length != 1) goto raw;

		vp->vp_integer = buffer[0];
		break;


	case PW_TYPE_SHORT:
		if (vp->length != 2) goto raw;

		vp->vp_integer = (buffer[0] << 8) | buffer[1];
		break;

	case PW_TYPE_INTEGER:
		if (vp->length != 4) goto raw;

		memcpy(&vp->vp_integer, buffer, 4);
		vp->vp_integer = ntohl(vp->vp_integer);

		if (vp->flags.has_tag) vp->vp_integer &= 0x00ffffff;
		break;

	case PW_TYPE_INTEGER64:
		if (vp->length != 8) goto raw;

		/* vp_integer64 is a union with vp_octets */
		memcpy(&vp->vp_integer64, buffer, 8);
		vp->vp_integer64 = ntohll(vp->vp_integer64);
		break;

	case PW_TYPE_DATE:
		if (vp->length != 4) goto raw;

		memcpy(&vp->vp_date, buffer, 4);
		vp->vp_date = ntohl(vp->vp_date);
		break;


	case PW_TYPE_IPADDR:
		if (vp->length != 4) goto raw;

		memcpy(&vp->vp_ipaddr, buffer, 4);
		break;

		/*
		 *	IPv6 interface ID is 8 octets long.
		 */
	case PW_TYPE_IFID:
		if (vp->length != 8) goto raw;
		memcpy(&vp->vp_ifid, buffer, 8);
		break;

		/*
		 *	IPv6 addresses are 16 octets long
		 */
	case PW_TYPE_IPV6ADDR:
		if (vp->length != 16) goto raw;
		memcpy(&vp->vp_ipv6addr, buffer, 16);
		break;

		/*
		 *	IPv6 prefixes are 2 to 18 octets long.
		 *
		 *	RFC 3162: The first octet is unused.
		 *	The second is the length of the prefix
		 *	the rest are the prefix data.
		 *
		 *	The prefix length can have value 0 to 128.
		 */
	case PW_TYPE_IPV6PREFIX:
		if (vp->length < 2 || vp->length > 18) goto raw;
		if (buffer[1] > 128) goto raw;

		/*
		 *	FIXME: double-check that
		 *	(vp->vp_octets[1] >> 3) matches vp->length + 2
		 */
		memcpy(&vp->vp_ipv6prefix, buffer, vp->length);
		if (vp->length < 18) {
			memset(((uint8_t *)vp->vp_ipv6prefix) + vp->length, 0,
			       18 - vp->length);
		}
		break;

	case PW_TYPE_SIGNED:
		if (vp->length != 4) goto raw;

		/*
		 *	Overload vp_integer for ntohl, which takes
		 *	uint32_t, not int32_t
		 */
		memcpy(&vp->vp_integer, buffer, 4);
		vp->vp_integer = ntohl(vp->vp_integer);
		break;

	case PW_TYPE_TLV:
		pairfree(&vp);
		fr_strerror_printf("data2vp_any: Internal sanity check failed");
		return -1;

	case PW_TYPE_COMBO_IP:
		if (vp->length == 4) {
			vp->type = PW_TYPE_IPADDR;
			memcpy(&vp->vp_ipaddr, buffer, 4);
			break;

		} else if (vp->length == 16) {
			vp->type = PW_TYPE_IPV6ADDR;
			memcpy(&vp->vp_ipv6addr, buffer, 16);
			break;

		}
		/* FALL-THROUGH */

	default:
		goto raw;
	}

	*pvp = vp;

	return length;
}


/**
 * @brief Convert a top-level VSA to a VP.
 */
static ssize_t attr2vp_vsa(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   const char *secret, unsigned int vendor,
			   size_t dv_type, size_t dv_length,
			   const uint8_t *data, size_t length,
			   VALUE_PAIR **pvp)
{
	unsigned int attribute;
	ssize_t attrlen, my_len;

#ifndef NDEBUG
	if (length <= (dv_type + dv_length)) {
		fr_strerror_printf("attr2vp_vsa: Failure to call rad_tlv_ok");
		return -1;
	}
#endif	

	switch (dv_type) {
	case 4:
		/* data[0] must be zero */
		attribute = data[1] << 16;
		attribute |= data[2] << 8;
		attribute |= data[3];
		break;

	case 2:
		attribute = data[0] << 8;
		attribute |= data[1];
		break;

	case 1:
		attribute = data[0];
		break;

	default:
		fr_strerror_printf("attr2vp_vsa: Internal sanity check failed");
		return -1;
	}

	switch (dv_length) {
	case 2:
		/* data[dv_type] must be zero */
		attrlen = data[dv_type + 1];
		break;

	case 1:
		attrlen = data[dv_type];
		break;

	case 0:
		attrlen = length;
		break;

	default:
		fr_strerror_printf("attr2vp_vsa: Internal sanity check failed");
		return -1;
	}

#ifndef NDEBUG
	if (attrlen <= (ssize_t) (dv_type + dv_length)) {
		fr_strerror_printf("attr2vp_vsa: Failure to call rad_tlv_ok");
		return -1;
	}
#endif

	attrlen -= (dv_type + dv_length);
	
	my_len = data2vp_any(packet, original, secret, 0,
			     attribute, vendor,
			     data + dv_type + dv_length, attrlen, pvp);
	if (my_len < 0) return my_len;

#ifndef NDEBUG
	if (my_len != attrlen) {
		pairfree(pvp);
		fr_strerror_printf("attr2vp_vsa: Incomplete decode %d != %d",
				   (int) my_len, (int) attrlen);
		return -1;
	}
#endif

	return dv_type + dv_length + attrlen;
}

/**
 * @brief Convert one or more TLVs to VALUE_PAIRs.  This function can
 *	be called recursively...
 */
static ssize_t data2vp_tlvs(const RADIUS_PACKET *packet,
			    const RADIUS_PACKET *original,
			    const char *secret,
			    unsigned int attribute, unsigned int vendor,
			    int nest,
			    const uint8_t *start, size_t length,
			    VALUE_PAIR **pvp)
{
	size_t dv_type, dv_length;
	const uint8_t *data, *end;
	VALUE_PAIR *head, **last, *vp;

	data = start;

	/*
	 *	The default format for a VSA is the RFC recommended
	 *	format.
	 */
	dv_type = 1;
	dv_length = 1;

	/*
	 *	Top-level TLVs can be of a weird format.  TLVs
	 *	encapsulated in a TLV can only be in the RFC format.
	 */
	if (nest == 1) {
		DICT_VENDOR *dv;
		dv = dict_vendorbyvalue(vendor);	
		if (dv) {
			dv_type = dv->type;
			dv_length = dv->length;
			/* dict.c enforces sane values on the above fields */
		}
	}

	if (nest >= fr_attr_max_tlv) {
		fr_strerror_printf("data2vp_tlvs: Internal sanity check failed in recursion");
		return -1;
	}

	/*
	 *	The VSAs do not exactly fill the data,
	 *	The *entire* TLV is malformed.
	 */
	if (rad_tlv_ok(data, length, dv_type, dv_length) < 0) {
		VP_TRACE("TLV malformed %u.%u\n", vendor, attribute);
		return data2vp_raw(packet, original, secret,
				   attribute, vendor, data, length, pvp);
	}

	end = data + length;
	head = NULL;
	last = &head;

	while (data < end) {
		unsigned int my_attr;
		unsigned int my_len;

#ifndef NDEBUG
		if ((data + dv_type + dv_length) > end) {
			fr_strerror_printf("data2vp_tlvs: Internal sanity check failed in tlvs: Insufficient data");
			pairfree(&head);
			return -1;
		}
#endif

		switch (dv_type) {
		case 1:
			my_attr = attribute;
			my_attr |= ((data[0] & fr_attr_mask[nest + 1])
				    << fr_attr_shift[nest + 1]);
			break;
		case 2:
			my_attr = (data[0] << 8) | data[1];
			break;

		case 4:
			my_attr = (data[1] << 16) | (data[1] << 8) | data[3];
			break;

		default:
			fr_strerror_printf("data2vp_tlvs: Internal sanity check failed");
			return -1;
		}

		switch (dv_length) {
		case 0:
			my_len = length;
			break;

		case 1:
		case 2:
			my_len = data[dv_type + dv_length - 1];
			break;

		default:
			fr_strerror_printf("data2vp_tlvs: Internal sanity check failed");
			return -1;
		}
		
#ifndef NDEBUG
		if (my_len < (dv_type + dv_length)) {
			fr_strerror_printf("data2vp_tlvs: Internal sanity check failed in tlvs: underflow");
			pairfree(&head);
			return -1;
		}

		if ((data + my_len) > end) {
			fr_strerror_printf("data2vp_tlvs: Internal sanity check failed in tlvs: overflow");
			pairfree(&head);
			return -1;
		}
#endif

		my_len -= dv_type + dv_length;

		/*
		 *	If this returns > 0, it returns "my_len"
		 */
		if (data2vp_any(packet, original, secret, nest + 1,
				my_attr, vendor,
				data + dv_type + dv_length, my_len, &vp) < 0) {
			pairfree(&head);
			return -1;
		}

		data += my_len + dv_type + dv_length;
		*last = vp;

		while (vp) {
			last = &(vp->next);
			vp = vp->next;
		}
	}

	*pvp = head;
	return data - start;
}


/**
 * @brief Group "continued" attributes together, and create VPs from them.
 *
 *	The caller ensures that the RADIUS packet is OK, and that the
 *	continuations have all been checked.
 */
static ssize_t data2vp_continued(const RADIUS_PACKET *packet,
				 const RADIUS_PACKET *original,
				 const char *secret,
				 const uint8_t *start, size_t length,
				 VALUE_PAIR **pvp, int nest,
				 unsigned int attribute, unsigned int vendor,
				 int first_offset, int later_offset,
				 ssize_t attrlen)
{
	ssize_t left;
	uint8_t *attr, *ptr;
	const uint8_t *data;

	attr = malloc(attrlen);
	if (!attr) {
		fr_strerror_printf("Out of memory");
		return -1;
	}

	left = attrlen;
	ptr = attr;
	data = start;

	/*
	 *	Do the first one.
	 */
	memcpy(ptr, data + first_offset, data[1] - first_offset);
	ptr += data[1] - first_offset;
	left -= data[1] - first_offset;
	data += data[1];

	while (left > 0) {
#ifndef NDEBUG
		if (data >= (start + length)) {
			free(attr);
			fr_strerror_printf("data2vp_continued: Internal sanity check failed");
			return -1;
		}
#endif
		memcpy(ptr, data + later_offset, data[1] - later_offset);
		ptr += data[1] - later_offset;
		left -= data[1] - later_offset;
		data += data[1];
	}

	left = data2vp_any(packet, original, secret, nest,
			   attribute, vendor,
			   attr, attrlen, pvp);
	free(attr);
	if (left < 0) return left;

	return data - start;
}


/**
 * @brief Create a "raw" VALUE_PAIR from a RADIUS attribute.
 */
ssize_t rad_attr2vp_raw(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const char *secret,
			const uint8_t *data, size_t length,
			VALUE_PAIR **pvp)
{
	ssize_t my_len;

	if ((length < 2) || (data[1] < 2) || (data[1] > length)) {
		fr_strerror_printf("rad_attr2vp_raw: Invalid length");
		return -1;
	}

	my_len = data2vp_raw(packet, original, secret, data[0], 0,
			     data + 2, data[1] - 2, pvp);
	if (my_len < 0) return my_len;
	
	return data[1];
}


/**
 * @brief Get the length of the data portion of all of the contiguous
 *	continued attributes.
 * @return
 *	0 for "no continuation"
 *	-1 on malformed packets (continuation followed by non-wimax, etc.)
 */
static ssize_t wimax_attrlen(uint32_t vendor,
			     const uint8_t *start, const uint8_t *end)
{
	ssize_t total;
	const uint8_t *data = start;

	if ((data[8] & 0x80) == 0) return 0;
	total = data[7] - 3;
	data += data[1];

	while (data < end) {
		
		if ((data + 9) > end) return -1;

		if ((data[0] != PW_VENDOR_SPECIFIC) ||
		    (data[1] < 9) ||
		    (memcmp(data + 2, &vendor, 4) != 0) ||
		    (data[6] != start[6]) ||
		    ((data[7] + 6) != data[1])) return -1;

		total += data[7] - 3;
		if ((data[8] & 0x80) == 0) break;
		data += data[1];
	}

	return total;
}


/**
 * @brief Get the length of the data portion of all of the contiguous
 *	continued attributes.
 *
 * @return
 * 	0 for "no continuation"
 *	-1 on malformed packets (continuation followed by non-wimax, etc.)
 */
static ssize_t extended_attrlen(const uint8_t *start, const uint8_t *end)
{
	ssize_t total;
	const uint8_t *data = start;

	if ((data[3] & 0x80) == 0) return 0;
	total = data[1] - 4;
	data += data[1];
	
	while (data < end) {
		if ((data + 4) > end) return -1;

		if ((data[0] != start[0]) ||
		    (data[1] < 4) ||
		    (data[2] != start[2])) return -1;

		total += data[1] - 4;
		if ((data[3] & 0x80) == 0) break;
		data += data[1];
	}

	return total;
}


/**
 * @brief Create WiMAX VALUE_PAIRs from a RADIUS attribute.
 */
ssize_t rad_attr2vp_wimax(const RADIUS_PACKET *packet,
			  const RADIUS_PACKET *original,
			  const char *secret,
			  const uint8_t *data,  size_t length,
			  VALUE_PAIR **pvp)
{
	ssize_t my_len;
	unsigned int attribute;
	uint32_t lvalue;

	if ((length < 2) || (data[1] < 2) || (data[1] > length)) {
		fr_strerror_printf("rad_attr2vp_wimax: Invalid length");
		return -1;
	}

	if (data[0] != PW_VENDOR_SPECIFIC) {
		fr_strerror_printf("rad_attr2vp_wimax: Invalid attribute");
		return -1;
	}

	/*
	 *	Not enough room for a Vendor-Id. + WiMAX header
	 */
	if (data[1] < 9) {
		return rad_attr2vp_raw(packet, original, secret,
				       data, length, pvp);
	}

	memcpy(&lvalue, data + 2, 4);
	lvalue = ntohl(lvalue);

	/*
	 *	Not WiMAX format.
	 */
	if (lvalue != VENDORPEC_WIMAX) {
		DICT_VENDOR *dv;

		dv = dict_vendorbyvalue(lvalue);
		if (!dv || !dv->flags) {
			fr_strerror_printf("rad_attr2vp_wimax: Not a WiMAX attribute");
			return -1;
		}
	}

	/*
	 *	The WiMAX attribute is encapsulated in a VSA.  If the
	 *	WiMAX length disagrees with the VSA length, it's malformed.
	 */
	if ((data[7] + 6) != data[1]) {
		return rad_attr2vp_raw(packet, original, secret,
				       data, length, pvp);
	}

	attribute = data[6];

	/*
	 *	Attribute is continued.  Do some more work.
	 */
	if (data[8] != 0) {
		my_len = wimax_attrlen(htonl(lvalue), data, data + length);
		if (my_len < 0) {
			return rad_attr2vp_raw(packet, original, secret,
					       data, length, pvp);
		}

		return data2vp_continued(packet, original, secret,
					 data, length, pvp, 0,
					 data[6], lvalue,
					 9, 9, my_len);
	}

	my_len = data2vp_any(packet, original, secret, 0, attribute, lvalue,
			     data + 9, data[1] - 9, pvp);
	if (my_len < 0) return my_len;

	return data[1];
}

/**
 * @brief Create Vendor-Specifc VALUE_PAIRs from a RADIUS attribute.
 */
ssize_t rad_attr2vp_vsa(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const char *secret,
			const uint8_t *data, size_t length,
			VALUE_PAIR **pvp)
{
	size_t dv_type, dv_length;
	ssize_t my_len;
	uint32_t lvalue;
	DICT_VENDOR *dv;

	if ((length < 2) || (data[1] < 2) || (data[1] > length)) {
		fr_strerror_printf("rad_attr2vp_vsa: Invalid length");
		return -1;
	}

	if (data[0] != PW_VENDOR_SPECIFIC) {
		fr_strerror_printf("rad_attr2vp_vsa: Invalid attribute");
		return -1;
	}

	/*
	 *	Not enough room for a Vendor-Id.
	 *	Or the high octet of the Vendor-Id is set.
	 */
	if ((data[1] < 6) || (data[2] != 0)) {
		return rad_attr2vp_raw(packet, original, secret,
				       data, length, pvp);
	}

	memcpy(&lvalue, data + 2, 4);
	lvalue = ntohl(lvalue);

	/*
	 *	WiMAX gets its own set of magic.
	 */
	if (lvalue == VENDORPEC_WIMAX) {
	wimax:
		return rad_attr2vp_wimax(packet, original, secret,
					 data, length, pvp);
	}

	dv_type = dv_length = 1;
	dv = dict_vendorbyvalue(lvalue);
	if (dv) {
		dv_type = dv->type;
		dv_length = dv->length;

		if (dv->flags) goto wimax;
	}

	/*
	 *	Attribute is not in the correct form.
	 */
	if (rad_tlv_ok(data + 6, data[1] - 6, dv_type, dv_length) < 0) {
		return rad_attr2vp_raw(packet, original, secret,
				       data, length, pvp);
	}

	my_len = attr2vp_vsa(packet, original, secret,
			     lvalue, dv_type, dv_length,
			     data + 6, data[1] - 6, pvp);
	if (my_len < 0) return my_len;

	/*
	 *	Incomplete decode means that something is wrong
	 *	with the attribute.  Back up, and make it "raw".
	 */
	if (my_len != (data[1] - 6)) {
		pairfree(pvp);
		return rad_attr2vp_raw(packet, original, secret,
				       data, length, pvp);
	}

	return data[1];
}

/**
 * @brief Create an "extended" VALUE_PAIR from a RADIUS attribute.
 */
ssize_t rad_attr2vp_extended(const RADIUS_PACKET *packet,
			     const RADIUS_PACKET *original,
			     const char *secret,
			     const uint8_t *start, size_t length,
			     VALUE_PAIR **pvp)
{
	unsigned int attribute;
	int shift = 1;
	int continued = 0;
	unsigned int vendor = VENDORPEC_EXTENDED;
	size_t data_len = length;
	const uint8_t *data;
	DICT_ATTR *da;

	data = start;

	if ((length < 2) || (data[1] < 2) || (data[1] > length)) {
		fr_strerror_printf("rad_attr2vp_extended: Invalid length");
		return -1;
	}

	da = dict_attrbyvalue(data[0], vendor);
	if (!da ||
	    (!da->flags.extended && !da->flags.long_extended)) {
		fr_strerror_printf("rad_attr2vp_extended: Attribute is not extended format");
		return -1;
	}

	data = start;

	/*
	 *	No Extended-Type.  It's a raw attribute.
	 *	Also, if there's no data following the Extended-Type,
	 *	it's a raw attribute.
	 */
	if (data[1] <= 3) {
	raw:
		return rad_attr2vp_raw(packet, original, secret, start,
				       length, pvp);
	}

	/*
	 *	The attribute is "241.1", for example.  Go look that
	 *	up to see what type it is.
	 */
	attribute = data[0];
	attribute |= (data[2] << fr_attr_shift[1]);

	da = dict_attrbyvalue(attribute, vendor);
	if (!da) goto raw;

	vendor = VENDORPEC_EXTENDED;

	data_len = length;
	if (data[1] < length) data_len = data[1];

	data += 3;
	data_len -= 3;

	/*
	 *	If there's supposed to be a flag octet.  If not, it's
	 *	a raw attribute.  If the flag is set, it's supposed to
	 *	be continued.
	 */
	if (da->flags.long_extended) {
		if (data_len == 0) goto raw;

		continued = ((data[0] & 0x80) != 0);
		data++;
		data_len--;
	}
	
	/*
	 *	Extended VSAs have 4 octets of
	 *	Vendor-Id followed by one octet of
	 *	Vendor-Type.
	 */
	if (da->flags.evs) {
		if (data_len < 5) goto raw;
		
		/*
		 *	Vendor Ids can only be 24-bit.
		 */
		if (data[0] != 0) goto raw;
		
		vendor = ((data[1] << 16) |
			  (data[2] << 8) |
			  data[3]);
		
		/*
		 *	Pack the *encapsulating* attribute number into
		 *	the vendor id.  This number should be >= 241.
		 */
		vendor |= start[0] * FR_MAX_VENDOR;
		shift = 0;
		
		/*
		 *	Over-write the attribute with the
		 *	VSA.
		 */
		attribute = data[4];
		data += 5;
		data_len -= 5;
	}

	if (continued) {
		int first_offset = 4;
		ssize_t my_len;

		if (vendor != VENDORPEC_EXTENDED) first_offset += 5;

		my_len = extended_attrlen(start, start + length);
		if (my_len < 0) goto raw;

		if (vendor != VENDORPEC_EXTENDED) my_len -= 5;

		return data2vp_continued(packet, original, secret,
					 start, length, pvp, shift,
					 attribute, vendor,
					 first_offset, 4, my_len);
	}

	if (data2vp_any(packet, original, secret, shift,
			attribute, vendor, data, data_len, pvp) < 0) {
		return -1;
	}

	return (data + data_len) - start;
}


/**
 * @brief Create a "standard" RFC VALUE_PAIR from the given data.
 */
ssize_t rad_attr2vp_rfc(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const char *secret,
			const uint8_t *data, size_t length,
			VALUE_PAIR **pvp)
{
	if ((length < 2) || (data[1] < 2) || (data[1] > length)) {
		fr_strerror_printf("rad_attr2vp_rfc: Insufficient data");
		return -1;
	}
	
	if (data2vp_any(packet, original, secret, 0,
			data[0], 0, data + 2, data[1] - 2, pvp) < 0) {
		return -1;
	}

	return data[1];
}	

/**
 * @brief Create a "normal" VALUE_PAIR from the given data.
 */
ssize_t rad_attr2vp(const RADIUS_PACKET *packet,
		    const RADIUS_PACKET *original,
		    const char *secret,
		    const uint8_t *data, size_t length,
		    VALUE_PAIR **pvp)
{
	if ((length < 2) || (data[1] < 2) || (data[1] > length)) {
		fr_strerror_printf("rad_attr2vp: Insufficient data");
		return -1;
	}

	/*
	 *	VSAs get their own handler.
	 */
	if (data[0] == PW_VENDOR_SPECIFIC) {
		return rad_attr2vp_vsa(packet, original, secret,
				       data, length, pvp);
	}

	/*
	 *	Extended attribute format gets their own handler.
	 */
	if (dict_attrbyvalue(data[0], VENDORPEC_EXTENDED) != NULL) {
		return rad_attr2vp_extended(packet, original, secret,
					    data, length, pvp);
	}

	return rad_attr2vp_rfc(packet, original, secret, data, length, pvp);
}


/**
 * @brief Converts data in network byte order to a VP
 * @return -1 on error, or the length of the data read
 */
ssize_t  rad_data2vp(unsigned int attribute, unsigned int vendor,
		     const uint8_t *data, size_t length,
		     VALUE_PAIR **pvp)
{
	if (!data || (length == 0) || !pvp) return -1;

	return data2vp_any(NULL, NULL, NULL, 0,
			   attribute, vendor, data, length, pvp);
}


/**
 * @brief Converts vp_data to network byte order
 * @return -1 on error, or the length of the value
 */
ssize_t rad_vp2data(const VALUE_PAIR *vp, uint8_t *out, size_t outlen)
{
	size_t		len = 0;
	uint32_t	lvalue;
	uint64_t	lvalue64;

	len = vp->length;
	if (outlen < len) {
		fr_strerror_printf("ERROR: rad_vp2data buffer passed too small");
		return -1;
	}
	
	/*
	 *	Short-circuit it for long attributes.
	 */
	if ((vp->type & PW_FLAG_LONG) != 0) goto do_raw;

	switch(vp->type) {
		case PW_TYPE_STRING:
		case PW_TYPE_OCTETS:
		case PW_TYPE_IFID:
		case PW_TYPE_IPADDR:
		case PW_TYPE_IPV6ADDR:
		case PW_TYPE_IPV6PREFIX:
		case PW_TYPE_ABINARY:
		case PW_TYPE_TLV:
			do_raw:
			memcpy(out, vp->vp_octets, len);
			break;
		case PW_TYPE_BYTE:
			out[0] = vp->vp_integer & 0xff;
			break;
	
		case PW_TYPE_SHORT:
			out[0] = (vp->vp_integer >> 8) & 0xff;
			out[1] = vp->vp_integer & 0xff;
			break;
	
		case PW_TYPE_INTEGER:
			lvalue = htonl(vp->vp_integer);
			memcpy(out, &lvalue, sizeof(lvalue));
			break;
	
		case PW_TYPE_INTEGER64:
			lvalue64 = htonll(vp->vp_integer64);
			memcpy(out, &lvalue64, sizeof(lvalue64));
			break;

		case PW_TYPE_DATE:
			lvalue = htonl(vp->vp_date);
			memcpy(out, &lvalue, sizeof(lvalue));
			break;
	
		case PW_TYPE_SIGNED:
		{
			int32_t slvalue;
			
			slvalue = htonl(vp->vp_signed);
			memcpy(out, &slvalue, sizeof(slvalue));
			break;
		}
		/* unknown type: ignore it */
		default:		
			fr_strerror_printf("ERROR: Unknown attribute type %d",
					   vp->type);
			return -1;
	}
	
	return len;
}

/**
 * @brief Calculate/check digest, and decode radius attributes.
 * @return -1 on decoding error, 0 on success
 */
int rad_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original,
	       const char *secret)
{
	int			packet_length;
	int			num_attributes;
	uint8_t			*ptr;
	radius_packet_t		*hdr;
	VALUE_PAIR *head, **tail, *vp;

	/*
	 *	Extract attribute-value pairs
	 */
	hdr = (radius_packet_t *)packet->data;
	ptr = hdr->data;
	packet_length = packet->data_len - AUTH_HDR_LEN;

	head = NULL;
	tail = &head;
	num_attributes = 0;

	/*
	 *	Loop over the attributes, decoding them into VPs.
	 */
	while (packet_length > 0) {
		ssize_t my_len;

		/*
		 *	This may return many VPs
		 */
		my_len = rad_attr2vp(packet, original, secret,
				     ptr, packet_length, &vp);
		if (my_len < 0) {
			pairfree(&head);
			return -1;
		}

		*tail = vp;
		while (vp) {
			num_attributes++;
			debug_pair(vp);
			tail = &(vp->next);
			vp = vp->next;
		}

		/*
		 *	VSA's may not have been counted properly in
		 *	rad_packet_ok() above, as it is hard to count
		 *	then without using the dictionary.  We
		 *	therefore enforce the limits here, too.
		 */
		if ((fr_max_attributes > 0) &&
		    (num_attributes > fr_max_attributes)) {
			char host_ipaddr[128];

			pairfree(&head);
			fr_strerror_printf("WARNING: Possible DoS attack from host %s: Too many attributes in request (received %d, max %d are allowed).",
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
					     host_ipaddr, sizeof(host_ipaddr)),
				   num_attributes, fr_max_attributes);
			return -1;
		}

		ptr += my_len;
		packet_length -= my_len;
	}

	/*
	 *	Merge information from the outside world into our
	 *	random pool.
	 */
	fr_rand_seed(packet->data, AUTH_HDR_LEN);
	
	/*
	 *	There may be VP's already in the packet.  Don't
	 *	destroy them.  Instead, add the decoded attributes to
	 *	the tail of the list.
	 */
	for (tail = &packet->vps; *tail != NULL; tail = &((*tail)->next)) {
		/* nothing */
	}
	*tail = head;

	return 0;
}


/**
 * @brief Encode password.
 *
 *	We assume that the passwd buffer passed is big enough.
 *	RFC2138 says the password is max 128 chars, so the size
 *	of the passwd buffer must be at least 129 characters.
 *	Preferably it's just MAX_STRING_LEN.
 *
 *	int *pwlen is updated to the new length of the encrypted
 *	password - a multiple of 16 bytes.
 */
int rad_pwencode(char *passwd, size_t *pwlen, const char *secret,
		 const uint8_t *vector)
{
	FR_MD5_CTX context, old;
	uint8_t	digest[AUTH_VECTOR_LEN];
	int	i, n, secretlen;
	int	len;

	/*
	 *	RFC maximum is 128 bytes.
	 *
	 *	If length is zero, pad it out with zeros.
	 *
	 *	If the length isn't aligned to 16 bytes,
	 *	zero out the extra data.
	 */
	len = *pwlen;

	if (len > 128) len = 128;

	if (len == 0) {
		memset(passwd, 0, AUTH_PASS_LEN);
		len = AUTH_PASS_LEN;
	} else if ((len % AUTH_PASS_LEN) != 0) {
		memset(&passwd[len], 0, AUTH_PASS_LEN - (len % AUTH_PASS_LEN));
		len += AUTH_PASS_LEN - (len % AUTH_PASS_LEN);
	}
	*pwlen = len;

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = strlen(secret);

	fr_MD5Init(&context);
	fr_MD5Update(&context, (const uint8_t *) secret, secretlen);
	old = context;		/* save intermediate work */

	/*
	 *	Encrypt it in place.  Don't bother checking
	 *	len, as we've ensured above that it's OK.
	 */
	for (n = 0; n < len; n += AUTH_PASS_LEN) {
		if (n == 0) {
			fr_MD5Update(&context, vector, AUTH_PASS_LEN);
			fr_MD5Final(digest, &context);
		} else {
			context = old;
			fr_MD5Update(&context,
				     (uint8_t *) passwd + n - AUTH_PASS_LEN,
				     AUTH_PASS_LEN);
			fr_MD5Final(digest, &context);
		}

		for (i = 0; i < AUTH_PASS_LEN; i++) {
			passwd[i + n] ^= digest[i];
		}
	}

	return 0;
}

/**
 * @brief Decode password.
 */
int rad_pwdecode(char *passwd, size_t pwlen, const char *secret,
		 const uint8_t *vector)
{
	FR_MD5_CTX context, old;
	uint8_t	digest[AUTH_VECTOR_LEN];
	int	i;
	size_t	n, secretlen;

	/*
	 *	The RFC's say that the maximum is 128.
	 *	The buffer we're putting it into above is 254, so
	 *	we don't need to do any length checking.
	 */
	if (pwlen > 128) pwlen = 128;

	/*
	 *	Catch idiots.
	 */
	if (pwlen == 0) goto done;

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = strlen(secret);

	fr_MD5Init(&context);
	fr_MD5Update(&context, (const uint8_t *) secret, secretlen);
	old = context;		/* save intermediate work */

	/*
	 *	The inverse of the code above.
	 */
	for (n = 0; n < pwlen; n += AUTH_PASS_LEN) {
		if (n == 0) {
			fr_MD5Update(&context, vector, AUTH_VECTOR_LEN);
			fr_MD5Final(digest, &context);

			context = old;
			if (pwlen > AUTH_PASS_LEN) {
				fr_MD5Update(&context, (uint8_t *) passwd,
					     AUTH_PASS_LEN);
			}
		} else {
			fr_MD5Final(digest, &context);

			context = old;
			if (pwlen > (n + AUTH_PASS_LEN)) {
				fr_MD5Update(&context, (uint8_t *) passwd + n,
					     AUTH_PASS_LEN);
			}
		}

		for (i = 0; i < AUTH_PASS_LEN; i++) {
			passwd[i + n] ^= digest[i];
		}
	}

 done:
	passwd[pwlen] = '\0';
	return strlen(passwd);
}


/**
 * @brief Encode Tunnel-Password attributes when sending them out on the wire.
 *
 *	int *pwlen is updated to the new length of the encrypted
 *	password - a multiple of 16 bytes.
 *
 *      This is per RFC-2868 which adds a two char SALT to the initial intermediate
 *      value MD5 hash.
 */
int rad_tunnel_pwencode(char *passwd, size_t *pwlen, const char *secret,
			const uint8_t *vector)
{
	uint8_t	buffer[AUTH_VECTOR_LEN + MAX_STRING_LEN + 3];
	unsigned char	digest[AUTH_VECTOR_LEN];
	char*   salt;
	int	i, n, secretlen;
	unsigned len, n2;

	len = *pwlen;

	if (len > 127) len = 127;

	/*
	 * Shift the password 3 positions right to place a salt and original
	 * length, tag will be added automatically on packet send
	 */
	for (n=len ; n>=0 ; n--) passwd[n+3] = passwd[n];
	salt = passwd;
	passwd += 2;
	/*
	 * save original password length as first password character;
	 */
	*passwd = len;
	len += 1;


	/*
	 *	Generate salt.  The RFC's say:
	 *
	 *	The high bit of salt[0] must be set, each salt in a
	 *	packet should be unique, and they should be random
	 *
	 *	So, we set the high bit, add in a counter, and then
	 *	add in some CSPRNG data.  should be OK..
	 */
	salt[0] = (0x80 | ( ((salt_offset++) & 0x0f) << 3) |
		   (fr_rand() & 0x07));
	salt[1] = fr_rand();

	/*
	 *	Padd password to multiple of AUTH_PASS_LEN bytes.
	 */
	n = len % AUTH_PASS_LEN;
	if (n) {
		n = AUTH_PASS_LEN - n;
		for (; n > 0; n--, len++)
			passwd[len] = 0;
	}
	/* set new password length */
	*pwlen = len + 2;

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = strlen(secret);
	memcpy(buffer, secret, secretlen);

	for (n2 = 0; n2 < len; n2+=AUTH_PASS_LEN) {
		if (!n2) {
			memcpy(buffer + secretlen, vector, AUTH_VECTOR_LEN);
			memcpy(buffer + secretlen + AUTH_VECTOR_LEN, salt, 2);
			fr_md5_calc(digest, buffer, secretlen + AUTH_VECTOR_LEN + 2);
		} else {
			memcpy(buffer + secretlen, passwd + n2 - AUTH_PASS_LEN, AUTH_PASS_LEN);
			fr_md5_calc(digest, buffer, secretlen + AUTH_PASS_LEN);
		}

		for (i = 0; i < AUTH_PASS_LEN; i++) {
			passwd[i + n2] ^= digest[i];
		}
	}
	passwd[n2] = 0;
	return 0;
}

/**
 * @brief Decode Tunnel-Password encrypted attributes.
 *
 *      Defined in RFC-2868, this uses a two char SALT along with the
 *      initial intermediate value, to differentiate it from the
 *      above.
 */
int rad_tunnel_pwdecode(uint8_t *passwd, size_t *pwlen, const char *secret,
			const uint8_t *vector)
{
	FR_MD5_CTX  context, old;
	uint8_t		digest[AUTH_VECTOR_LEN];
	int		secretlen;
	unsigned	i, n, len, reallen;

	len = *pwlen;

	/*
	 *	We need at least a salt.
	 */
	if (len < 2) {
		fr_strerror_printf("tunnel password is too short");
		return -1;
	}

	/*
	 *	There's a salt, but no password.  Or, there's a salt
	 *	and a 'data_len' octet.  It's wrong, but at least we
	 *	can figure out what it means: the password is empty.
	 *
	 *	Note that this means we ignore the 'data_len' field,
	 *	if the attribute length tells us that there's no
	 *	more data.  So the 'data_len' field may be wrong,
	 *	but that's ok...
	 */
	if (len <= 3) {
		passwd[0] = 0;
		*pwlen = 0;
		return 0;
	}

	len -= 2;		/* discount the salt */

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = strlen(secret);

	fr_MD5Init(&context);
	fr_MD5Update(&context, (const uint8_t *) secret, secretlen);
	old = context;		/* save intermediate work */

	/*
	 *	Set up the initial key:
	 *
	 *	 b(1) = MD5(secret + vector + salt)
	 */
	fr_MD5Update(&context, vector, AUTH_VECTOR_LEN);
	fr_MD5Update(&context, passwd, 2);

	reallen = 0;
	for (n = 0; n < len; n += AUTH_PASS_LEN) {
		int base = 0;

		if (n == 0) {
			fr_MD5Final(digest, &context);

			context = old;

			/*
			 *	A quick check: decrypt the first octet
			 *	of the password, which is the
			 *	'data_len' field.  Ensure it's sane.
			 */
			reallen = passwd[2] ^ digest[0];
			if (reallen >= len) {
				fr_strerror_printf("tunnel password is too long for the attribute");
				return -1;
			}

			fr_MD5Update(&context, passwd + 2, AUTH_PASS_LEN);

			base = 1;
		} else {
			fr_MD5Final(digest, &context);

			context = old;
			fr_MD5Update(&context, passwd + n + 2, AUTH_PASS_LEN);
		}

		for (i = base; i < AUTH_PASS_LEN; i++) {
			passwd[n + i - 1] = passwd[n + i + 2] ^ digest[i];
		}
	}

	/*
	 *	See make_tunnel_password, above.
	 */
	if (reallen > 239) reallen = 239;

	*pwlen = reallen;
	passwd[reallen] = 0;

	return reallen;
}

/**
 * @brief Encode a CHAP password
 *
 *	@bug FIXME: might not work with Ascend because
 *	we use vp->length, and Ascend gear likes
 *	to send an extra '\0' in the string!
 */
int rad_chap_encode(RADIUS_PACKET *packet, uint8_t *output, int id,
		    VALUE_PAIR *password)
{
	int		i;
	uint8_t		*ptr;
	uint8_t		string[MAX_STRING_LEN * 2 + 1];
	VALUE_PAIR	*challenge;

	/*
	 *	Sanity check the input parameters
	 */
	if ((packet == NULL) || (password == NULL)) {
		return -1;
	}

	/*
	 *	Note that the password VP can be EITHER
	 *	a User-Password attribute (from a check-item list),
	 *	or a CHAP-Password attribute (the client asking
	 *	the library to encode it).
	 */

	i = 0;
	ptr = string;
	*ptr++ = id;

	i++;
	memcpy(ptr, password->vp_strvalue, password->length);
	ptr += password->length;
	i += password->length;

	/*
	 *	Use Chap-Challenge pair if present,
	 *	Request Authenticator otherwise.
	 */
	challenge = pairfind(packet->vps, PW_CHAP_CHALLENGE, 0);
	if (challenge) {
		memcpy(ptr, challenge->vp_strvalue, challenge->length);
		i += challenge->length;
	} else {
		memcpy(ptr, packet->vector, AUTH_VECTOR_LEN);
		i += AUTH_VECTOR_LEN;
	}

	*output = id;
	fr_md5_calc((uint8_t *)output + 1, (uint8_t *)string, i);

	return 0;
}


/**
 * @brief Seed the random number generator.
 *
 *	May be called any number of times.
 */
void fr_rand_seed(const void *data, size_t size)
{
	uint32_t hash;

	/*
	 *	Ensure that the pool is initialized.
	 */
	if (!fr_rand_initialized) {
		int fd;

		memset(&fr_rand_pool, 0, sizeof(fr_rand_pool));

		fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0) {
			size_t total;
			ssize_t this;

			total = 0;
			while (total < sizeof(fr_rand_pool.randrsl)) {
				this = read(fd, fr_rand_pool.randrsl,
					    sizeof(fr_rand_pool.randrsl) - total);
				if ((this < 0) && (errno != EINTR)) break;
				if (this > 0) total += this;
 			}
			close(fd);
		} else {
			fr_rand_pool.randrsl[0] = fd;
			fr_rand_pool.randrsl[1] = time(NULL);
			fr_rand_pool.randrsl[2] = errno;
		}

		fr_randinit(&fr_rand_pool, 1);
		fr_rand_pool.randcnt = 0;
		fr_rand_initialized = 1;
	}

	if (!data) return;

	/*
	 *	Hash the user data
	 */
	hash = fr_rand();
	if (!hash) hash = fr_rand();
	hash = fr_hash_update(data, size, hash);

	fr_rand_pool.randmem[fr_rand_pool.randcnt] ^= hash;
}


/**
 * @brief Return a 32-bit random number.
 */
uint32_t fr_rand(void)
{
	uint32_t num;

	/*
	 *	Ensure that the pool is initialized.
	 */
	if (!fr_rand_initialized) {
		fr_rand_seed(NULL, 0);
	}

	num = fr_rand_pool.randrsl[fr_rand_pool.randcnt++];
	if (fr_rand_pool.randcnt >= 256) {
		fr_rand_pool.randcnt = 0;
		fr_isaac(&fr_rand_pool);
	}

	return num;
}


/**
 * @brief Allocate a new RADIUS_PACKET
 */
RADIUS_PACKET *rad_alloc(int newvector)
{
	RADIUS_PACKET	*rp;

	if ((rp = malloc(sizeof(RADIUS_PACKET))) == NULL) {
		fr_strerror_printf("out of memory");
		return NULL;
	}
	memset(rp, 0, sizeof(*rp));
	rp->id = -1;
	rp->offset = -1;

	if (newvector) {
		int i;
		uint32_t hash, base;

		/*
		 *	Don't expose the actual contents of the random
		 *	pool.
		 */
		base = fr_rand();
		for (i = 0; i < AUTH_VECTOR_LEN; i += sizeof(uint32_t)) {
			hash = fr_rand() ^ base;
			memcpy(rp->vector + i, &hash, sizeof(hash));
		}
	}
	fr_rand();		/* stir the pool again */

	return rp;
}

RADIUS_PACKET *rad_alloc_reply(RADIUS_PACKET *packet)
{
	RADIUS_PACKET *reply;

	if (!packet) return NULL;

	reply = rad_alloc(0);
	if (!reply) return NULL;

	/*
	 *	Initialize the fields from the request.
	 */
	reply->sockfd = packet->sockfd;
	reply->dst_ipaddr = packet->src_ipaddr;
	reply->src_ipaddr = packet->dst_ipaddr;
	reply->dst_port = packet->src_port;
	reply->src_port = packet->dst_port;
	reply->id = packet->id;
	reply->code = 0; /* UNKNOWN code */
	memcpy(reply->vector, packet->vector,
	       sizeof(reply->vector));
	reply->vps = NULL;
	reply->data = NULL;
	reply->data_len = 0;

	return reply;
}


/**
 * @brief Free a RADIUS_PACKET
 */
void rad_free(RADIUS_PACKET **radius_packet_ptr)
{
	RADIUS_PACKET *radius_packet;

	if (!radius_packet_ptr || !*radius_packet_ptr) return;
	radius_packet = *radius_packet_ptr;

	free(radius_packet->data);

	pairfree(&radius_packet->vps);

	free(radius_packet);

	*radius_packet_ptr = NULL;
}
