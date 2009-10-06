/*
 * radius.c	Functions to send/receive radius packets.
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

static void print_hex(RADIUS_PACKET *packet)
{
	int i;

	if (!packet->data) return;

	printf("  Code:\t\t%u\n", packet->data[0]);
	printf("  Id:\t\t%u\n", packet->data[1]);
	printf("  Length:\t%u\n", ((packet->data[2] << 8) |
				   (packet->data[3])));
	printf("  Vector:\t");
	for (i = 4; i < 20; i++) {
		printf("%02x", packet->data[i]);
	}
	printf("\n");

	if (packet->data_len > 20) {
		int total;
		const uint8_t *ptr;
		printf("  Data:");

		total = packet->data_len - 20;
		ptr = packet->data + 20;

		while (total > 0) {
			int attrlen;

			printf("\t\t");
			if (total < 2) { /* too short */
				printf("%02x\n", *ptr);
				break;
			}

			if (ptr[1] > total) { /* too long */
				for (i = 0; i < total; i++) {
					printf("%02x ", ptr[i]);
				}
				break;
			}

			printf("%02x  %02x  ", ptr[0], ptr[1]);
			attrlen = ptr[1] - 2;
			ptr += 2;
			total -= 2;

			for (i = 0; i < attrlen; i++) {
				if ((i > 0) && ((i & 0x0f) == 0x00))
					printf("\t\t\t");
				printf("%02x ", ptr[i]);
				if ((i & 0x0f) == 0x0f) printf("\n");
			}

			if ((attrlen & 0x0f) != 0x00) printf("\n");

			ptr += attrlen;
			total -= attrlen;
		}
	}
	fflush(stdout);
}


/*
 *	Wrapper for sendto which handles sendfromto, IPv6, and all
 *	possible combinations.
 */
static int rad_sendto(int sockfd, void *data, size_t data_len, int flags,
		      fr_ipaddr_t *src_ipaddr, int src_port,
		      fr_ipaddr_t *dst_ipaddr, int dst_port)
{
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
	 *	Only IPv4 is supported for udpfromto.
	 *
	 *	And if they don't specify a source IP address, don't
	 *	use udpfromto.
	 */
	if ((dst_ipaddr->af == AF_INET) ||
	    (src_ipaddr->af != AF_UNSPEC)) {
		return sendfromto(sockfd, data, data_len, flags,
				  (struct sockaddr *)&src, sizeof_src,
				  (struct sockaddr *)&dst, sizeof_dst);
	}
#else
	src_ipaddr = src_ipaddr; /* -Wunused */
#endif

	/*
	 *	No udpfromto, OR an IPv6 socket, fail gracefully.
	 */
	return sendto(sockfd, data, data_len, flags,
		      (struct sockaddr *) &dst, sizeof_dst);
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


/*
 *	wrapper for recvfrom, which handles recvfromto, IPv6, and all
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
	if (dst.ss_family == AF_INET) {
		data_len = recvfromto(sockfd, buf, len, flags,
				      (struct sockaddr *)&src, &sizeof_src,
				      (struct sockaddr *)&dst, &sizeof_dst);
	} else
#endif
		/*
		 *	No udpfromto, OR an IPv6 socket.  Fail gracefully.
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
/*************************************************************************
 *
 *      Function: make_secret
 *
 *      Purpose: Build an encrypted secret value to return in a reply
 *               packet.  The secret is hidden by xoring with a MD5 digest
 *               created from the shared secret and the authentication
 *               vector.  We put them into MD5 in the reverse order from
 *               that used when encrypting passwords to RADIUS.
 *
 *************************************************************************/
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
static void make_passwd(uint8_t *output, size_t *outlen,
			const uint8_t *input, size_t inlen,
			const char *secret, const uint8_t *vector)
{
	FR_MD5_CTX context, old;
	uint8_t	digest[AUTH_VECTOR_LEN];
	uint8_t passwd[MAX_PASS_LEN];
	int	i, n;
	int	len;

	/*
	 *	If the length is zero, round it up.
	 */
	len = inlen;

	if (len > MAX_PASS_LEN) len = MAX_PASS_LEN;

	memcpy(passwd, input, len);
	memset(passwd + len, 0, sizeof(passwd) - len);

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

static void make_tunnel_passwd(uint8_t *output, size_t *outlen,
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

/*
 *	Returns the end of the data.
 */
static uint8_t *vp2data(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const char *secret, const VALUE_PAIR *vp, uint8_t *ptr,
			size_t room)
{
	uint32_t lvalue;
	size_t len;
	const uint8_t *data;
	uint8_t	array[4];

	/*
	 *	Set up the default sources for the data.
	 */
	data = vp->vp_octets;
	len = vp->length;

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
		data = vp->vp_tlv;
		if (!data) {
			fr_strerror_printf("ERROR: Cannot encode NULL TLV");
			return NULL;
		}
		if (vp->length > room) return 0; /* can't chop TLVs to fit */
		break;

	default:		/* unknown type: ignore it */
		fr_strerror_printf("ERROR: Unknown attribute type %d", vp->type);
		return NULL;
	}

	/*
	 *	Bound the data to the calling size
	 */
	if (len > room) len = room;

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
		/*
		 *	Check if there's enough room.  If there isn't,
		 *	we discard the attribute.
		 *
		 *	This is ONLY a problem if we have multiple VSA's
		 *	in one Vendor-Specific, though.
		 */
		if (room < 18) return ptr;

        	switch (packet->code) {
	        case PW_AUTHENTICATION_ACK:
        	case PW_AUTHENTICATION_REJECT:
        	case PW_ACCESS_CHALLENGE:
        	default:
			if (!original) {
				fr_strerror_printf("ERROR: No request packet, cannot encrypt %s attribute in the vp.", vp->name);
				return NULL;
			}
			make_tunnel_passwd(ptr, &len, data, len, room,
					   secret, original->vector);
                	break;
	        case PW_ACCOUNTING_REQUEST:
        	case PW_DISCONNECT_REQUEST:
	        case PW_COA_REQUEST:
			make_tunnel_passwd(ptr, &len, data, len, room,
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
		/*
		 *	Just copy the data over
		 */
		memcpy(ptr, data, len);
		break;
	} /* switch over encryption flags */

	return ptr + len;
}


static VALUE_PAIR *rad_vp2tlv(VALUE_PAIR *vps, uint32_t mask)
{
	int maxattr = 0;
	int length;
	unsigned int attribute;
	uint8_t *ptr, *end;
	VALUE_PAIR *vp, *tlv;

	attribute = vps->attribute & ~mask;
	maxattr = vps->attribute & mask;

	tlv = paircreate(attribute, vps->vendor, PW_TYPE_TLV);
	if (!tlv) return NULL;

	tlv->length = 0;
	vp = vps;
	while (vp != NULL) {
		tlv->length += vp->length + 2;

		/*
		 *	Group the attributes ONLY until we see a
		 *	non-TLV attribute.
		 */
		if (!vp->flags.is_tlv ||
		    vp->flags.encoded ||
		    (vp->flags.encrypt != FLAG_ENCRYPT_NONE) ||
		    (vp->vendor != vps->vendor) ||
		    ((vp->attribute & ~mask) != attribute) ||
		    ((vp->attribute & mask) <= maxattr)) {
			break;
		}

		maxattr = vp->attribute & mask;
		vp = vp->next;
	}

	if (!tlv->length) {
		pairfree(&tlv);
		return NULL;
	}

	tlv->vp_tlv = malloc(tlv->length);
	if (!tlv->vp_tlv) {
		pairfree(&tlv);
		return NULL;
	}

	ptr = tlv->vp_tlv;
	maxattr = vps->attribute & 0x0ff;
	for (vp = vps; vp != NULL; vp = vp->next) {
		if (!vp->flags.is_tlv ||
		    vp->flags.encoded ||
		    (vp->flags.encrypt != FLAG_ENCRYPT_NONE) ||
		    ((vp->attribute & 0xffff00ff) != attribute) ||
		    ((vp->attribute & 0x0000ff00) <= maxattr)) {
			break;
		}

		maxattr = vp->attribute & 0xff00;
		end = vp2data(NULL, NULL, NULL, vp, ptr + 2,
			      tlv->vp_tlv + tlv->length - ptr);
		if (!end) {
			vp->length = ptr - vp->vp_tlv;
			return tlv; /* should be a more serious error... */
		}

		length = (end - ptr);
		if (length > 255) return NULL;

		/*
		 *	Pack the attribute.
		 */
		ptr[0] = (vp->attribute & 0xff00) >> 8;
		ptr[1] = (length & 0xff);

		ptr += ptr[1];
		vp->flags.encoded = 1;
	}

	return tlv;
}


/*
 *	Parse a data structure into a RADIUS attribute.
 */
int rad_vp2attr(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
		const char *secret, const VALUE_PAIR *vp, uint8_t *start,
		size_t room)
{
	int		vendorcode;
	int		len, total_length;
	uint32_t	lvalue;
	uint8_t		*ptr, *length_ptr, *vsa_length_ptr, *tlv_length_ptr;
	uint8_t		*end;

	ptr = start;
	vendorcode = total_length = 0;
	length_ptr = vsa_length_ptr = tlv_length_ptr = NULL;

	/*
	 *	For interoperability, always put vendor attributes
	 *	into their own VSA.
	 */
	if ((vendorcode = vp->vendor) == 0) {
		if (room < 2) return 0;
		room -= 2;

		*(ptr++) = vp->attribute & 0xff;
		length_ptr = ptr;
		*(ptr++) = 2;
		total_length += 2;

	} else {
		int vsa_tlen = 1;
		int vsa_llen = 1;
		int vsa_offset = 0;
		DICT_VENDOR *dv = dict_vendorbyvalue(vendorcode);

		/*
		 *	This must be an RFC-format attribute.  If it
		 *	wasn't, then the "decode" function would have
		 *	made a Vendor-Specific attribute (i.e. type
		 *	26), and we would have "vendorcode == 0" here.
		 */
		if (dv) {
			vsa_tlen = dv->type;
			vsa_llen = dv->length;
			if (dv->flags) vsa_offset = 1;
		}

		if (room < (6 + vsa_tlen + vsa_llen + vsa_offset)) return 0;
		room -= 6 + vsa_tlen + vsa_llen + vsa_offset;

		/*
		 *	Build a VSA header.
		 */
		*ptr++ = PW_VENDOR_SPECIFIC;
		vsa_length_ptr = ptr;
		*ptr++ = 6;
		lvalue = htonl(vendorcode);
		memcpy(ptr, &lvalue, 4);
		ptr += 4;
		total_length += 6;

		switch (vsa_tlen) {
		case 1:
			ptr[0] = (vp->attribute & 0xFF);
			break;

		case 2:
			ptr[0] = ((vp->attribute >> 8) & 0xFF);
			ptr[1] = (vp->attribute & 0xFF);
			break;

		case 4:
			ptr[0] = 0;
			ptr[1] = 0;
			ptr[2] = ((vp->attribute >> 8) & 0xFF);
			ptr[3] = (vp->attribute & 0xFF);
			break;

		default:
			return 0; /* silently discard it */
		}
		ptr += vsa_tlen;

		switch (vsa_llen) {
		case 0:
			length_ptr = vsa_length_ptr;
			vsa_length_ptr = NULL;
			break;
		case 1:
			ptr[0] = 0;
			length_ptr = ptr;
			break;
		case 2:
			ptr[0] = 0;
			ptr[1] = 0;
			length_ptr = ptr + 1;
			break;

		default:
			return 0; /* silently discard it */
		}
		ptr += vsa_llen;

		/*
		 *	Allow for some continuation.
		 */
		if (vsa_offset) {
			ptr[0] = 0x00;
			ptr++;

			/*
			 *	Ignore TLVs that don't have data, OR
			 *	have too much data to fit in the
			 *	packet, OR have too much data to fit
			 *	in the attribute.
			 */
			if (vp->flags.has_tlv &&
			    (!vp->vp_tlv || (vp->length > room) ||

			     /*
			      *		6 + 1 (vsa_tlen) + 1 (vsa_llen)
			      *		+ 1 (vsa_offset).
			      */
			     (vp->length > (255 - 9)))) return 0;


			/*
			 *	sub-TLV's can only be in one format.
			 */
			if (vp->flags.is_tlv) {
				if (room < 2) return 0;
				room -= 2;

				*(ptr++) = (vp->attribute & 0xff00) >> 8;
				tlv_length_ptr = ptr;
				*(ptr++) = 2;
				vsa_offset += 2;
			}
		}

		total_length += vsa_tlen + vsa_llen + vsa_offset;
		if (vsa_length_ptr) *vsa_length_ptr += vsa_tlen + vsa_llen + vsa_offset;
		*length_ptr += vsa_tlen + vsa_llen + vsa_offset;
	}

	/*
	 *	Insert tags for string attributes.  They go BEFORE
	 *	the string.
	 */
	if (vp->flags.has_tag && (vp->type == PW_TYPE_STRING) &&
	    (TAG_VALID(vp->flags.tag) ||
	     (vp->flags.encrypt == FLAG_ENCRYPT_TUNNEL_PASSWORD))) {
		if (room < (1 + vp->length)) return 0;

		ptr[0] = vp->flags.tag;
		end = vp2data(packet, original, secret, vp, ptr + 1,
			      (end - ptr) - 1);
	} else {
		if (room < vp->length) return 0;
		end = vp2data(packet, original, secret, vp, ptr,
			      (end - ptr));
	}
	if (!end) return -1;

	/*
	 *	Insert tags for integer attributes.  They go at the START
	 *	of the integer, and over-write the first byte.
	 */
	if (vp->flags.has_tag && (vp->type == PW_TYPE_INTEGER)) {
		ptr[0] = vp->flags.tag;
	}

	/*
	 *	RFC 2865 section 5 says that zero-length attributes
	 *	MUST NOT be sent.
	 *
	 *	... and the WiMAX forum ignores this... because of
	 *	one vendor.  Don't they have anything better to do
	 *	with their time?
	 */
	if ((end == ptr) &&
	    (vp->attribute != PW_CHARGEABLE_USER_IDENTITY)) return 0;

	len = (end - ptr);

	/*
	 *	Update the various lengths.
	 */
	*length_ptr += len;
	if (vsa_length_ptr) *vsa_length_ptr += len;
	if (tlv_length_ptr) *tlv_length_ptr += len;
	ptr += len;
	total_length += len;

	return total_length;	/* of attribute */
}


/*
 *	Encode a packet.
 */
int rad_encode(RADIUS_PACKET *packet, const RADIUS_PACKET *original,
	       const char *secret)
{
	radius_packet_t	*hdr;
	uint8_t	        *ptr;
	uint16_t	total_length;
	int		len;
	VALUE_PAIR	*reply;
	const char	*what;
	char		ip_buffer[128];

	/*
	 *	A 4K packet, aligned on 64-bits.
	 */
	uint64_t	data[MAX_PACKET_LEN / sizeof(uint64_t)];

	if ((packet->code > 0) && (packet->code < FR_MAX_PACKET_CODE)) {
		what = fr_packet_codes[packet->code];
	} else {
		what = "Reply";
	}

	DEBUG("Sending %s of id %d to %s port %d\n",
	      what, packet->id,
	      inet_ntop(packet->dst_ipaddr.af,
			&packet->dst_ipaddr.ipaddr,
			ip_buffer, sizeof(ip_buffer)),
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
	for (reply = packet->vps; reply; reply = reply->next) {
		/*
		 *	Ignore non-wire attributes
		 */
		if ((reply->vendor == 0) &&
		    ((reply->attribute & 0xFFFF) > 0xff)) {
#ifndef NDEBUG
			/*
			 *	Permit the admin to send BADLY formatted
			 *	attributes with a debug build.
			 */
			if (reply->attribute == PW_RAW_ATTRIBUTE) {
				memcpy(ptr, reply->vp_octets, reply->length);
				len = reply->length;
				goto next;
			}
#endif
			continue;
		}

		/*
		 *	Set the Message-Authenticator to the correct
		 *	length and initial value.
		 */
		if (reply->attribute == PW_MESSAGE_AUTHENTICATOR) {
			reply->length = AUTH_VECTOR_LEN;
			memset(reply->vp_strvalue, 0, AUTH_VECTOR_LEN);

			/*
			 *	Cache the offset to the
			 *	Message-Authenticator
			 */
			packet->offset = total_length;
		}

		/*
		 *	Print out ONLY the attributes which
		 *	we're sending over the wire, and print
		 *	them out BEFORE they're encrypted.
		 */
		debug_pair(reply);

		/*
		 *	Print them in order, even if they were encoded
		 *	already.
		 */
		len = 0;
		if (reply->flags.encoded) goto next;

		if (reply->flags.is_tlv) {
			VALUE_PAIR *tlv = rad_vp2tlv(reply, 0xff00);
			if (tlv) {
				tlv->next = reply->next;
				reply->next = tlv;
			}

			/*
			 *	The encoded flag MUST be set in reply!
			 */
			reply = reply->next;
		}

		len = rad_vp2attr(packet, original, secret, reply, ptr,
				  ((uint8_t *) data) + sizeof(data) - ptr);

		if (len < 0) return -1;

		/*
		 *	Check that the packet is no more than 4k in
		 *	size, AFTER writing the attribute past the 4k
		 *	boundary, but BEFORE deciding to increase the
		 *	size of the packet. Note that the 'data'
		 *	buffer, above, is one attribute longer than
		 *	necessary, in order to permit this overflow.
		 */
		if ((total_length + len) > MAX_PACKET_LEN) {
			break;
		}

	next:
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


/*
 *	Sign a previously encoded packet.
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
		case PW_ACCOUNTING_REQUEST:
		case PW_ACCOUNTING_RESPONSE:
		case PW_DISCONNECT_REQUEST:
		case PW_DISCONNECT_ACK:
		case PW_DISCONNECT_NAK:
		case PW_COA_REQUEST:
		case PW_COA_ACK:
		case PW_COA_NAK:
			memset(hdr->vector, 0, AUTH_VECTOR_LEN);
			break;

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
		 *	calculate the signature, and put it
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

/*
 *	Reply to the request.  Also attach
 *	reply attribute value pairs and any user message provided.
 */
int rad_send(RADIUS_PACKET *packet, const RADIUS_PACKET *original,
	     const char *secret)
{
	VALUE_PAIR		*reply;
	const char		*what;
	char			ip_buffer[128];

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
	  	DEBUG("Sending %s of id %d to %s port %d\n", what, packet->id,
		      inet_ntop(packet->dst_ipaddr.af,
				&packet->dst_ipaddr.ipaddr,
				ip_buffer, sizeof(ip_buffer)),
		      packet->dst_port);

		for (reply = packet->vps; reply; reply = reply->next) {
			if ((reply->vendor == 0) &&
			    ((reply->attribute & 0xFFFF) > 0xff)) continue;
			debug_pair(reply);
		}
	}

	/*
	 *	And send it on it's way.
	 */
	return rad_sendto(packet->sockfd, packet->data, packet->data_len, 0,
			  &packet->src_ipaddr, packet->src_port,
			  &packet->dst_ipaddr, packet->dst_port);
}

/*
 *	Do a comparison of two authentication digests by comparing
 *	the FULL digest.  Otehrwise, the server can be subject to
 *	timing attacks that allow attackers find a valid message
 *	authenticator.
 *
 *	http://www.cs.rice.edu/~dwallach/pub/crosby-timing2009.pdf
 */
static int digest_cmp(const uint8_t *a, const uint8_t *b, size_t length)
{
	int result = 0;
	size_t i;

	for (i = 0; i < length; i++) {
		result |= a[i] ^ b[i];
	}

	return result;		/* 0 is OK, !0 is !OK, just like memcmp */
}


/*
 *	Validates the requesting client NAS.  Calculates the
 *	signature based on the clients private key.
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
	if (digest_cmp(digest, packet->vector, AUTH_VECTOR_LEN) != 0) return 2;
	return 0;
}


/*
 *	Validates the requesting client NAS.  Calculates the
 *	signature based on the clients private key.
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
	if (digest_cmp(packet->vector, calc_digest, AUTH_VECTOR_LEN) != 0) return 2;
	return 0;
}


/*
 *	See if the data pointed to by PTR is a valid RADIUS packet.
 *
 *	packet is not 'const * const' because we may update data_len,
 *	if there's more data in the UDP packet than in the RADIUS packet.
 */
int rad_packet_ok(RADIUS_PACKET *packet, int flags)
{
	uint8_t			*attr;
	int			totallen;
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
		fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: too short (received %d < minimum %d)",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
				   (int) packet->data_len, AUTH_HDR_LEN);
		return 0;
	}

	/*
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	" ... and maximum length is 4096."
	 */
	if (packet->data_len > MAX_PACKET_LEN) {
		fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: too long (received %d > maximum %d)",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
				   (int) packet->data_len, MAX_PACKET_LEN);
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
		fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: too short (length %d < minimum %d)",
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
		fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: too long (length %d > maximum %d)",
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
		fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: received %d octets, packet length says %d",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
				   (int) packet->data_len, totallen);
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
			fr_strerror_printf("WARNING: Malformed RADIUS packet from host %s: attribute %d too short",
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


/*
 *	Receive UDP client requests, and fill in
 *	the basics of a RADIUS_PACKET structure.
 */
RADIUS_PACKET *rad_recv(int fd, int flags)
{
	int sock_flags = 0;
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

	packet->data_len = rad_recvfrom(fd, &packet->data, sock_flags,
					&packet->src_ipaddr, &packet->src_port,
					&packet->dst_ipaddr, &packet->dst_port);

	/*
	 *	Check for socket errors.
	 */
	if (packet->data_len < 0) {
		fr_strerror_printf("Error receiving packet: %s", strerror(errno));
		/* packet->data is NULL */
		free(packet);
		return NULL;
	}

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

	return packet;
}


/*
 *	Verify the signature of a packet.
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

			case PW_ACCOUNTING_REQUEST:
			case PW_ACCOUNTING_RESPONSE:
			case PW_DISCONNECT_REQUEST:
			case PW_DISCONNECT_ACK:
			case PW_DISCONNECT_NAK:
			case PW_COA_REQUEST:
			case PW_COA_ACK:
			case PW_COA_NAK:
			  	memset(packet->data + 4, 0, AUTH_VECTOR_LEN);
				break;

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
			if (digest_cmp(calc_auth_vector, msg_auth_vector,
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
	 *	It looks like a RADIUS packet, but we can't validate
	 *	the signature.
	 */
	if ((packet->code == 0) || (packet->code >= FR_MAX_PACKET_CODE)) {
		char buffer[32];
		fr_strerror_printf("Received Unknown packet code %d "
			   "from client %s port %d: Cannot validate signature.",
			   packet->code,
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     buffer, sizeof(buffer)),
			   packet->src_port);
		return -1;
	}

	/*
	 *	Calculate and/or verify digest.
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
					   "from %s with invalid signature!  (Shared secret is incorrect.)",
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
					   "from client %s port %d with invalid signature (err=%d)!  (Shared secret is incorrect.)",
					   fr_packet_codes[packet->code],
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     buffer, sizeof(buffer)),
					   packet->src_port,
					   rcode);
				return -1;
			}
			break;

		default:
			fr_strerror_printf("Received Unknown packet code %d "
				   "from client %s port %d: Cannot validate signature",
				   packet->code,
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
						     buffer, sizeof(buffer)),
				   packet->src_port);
			return -1;
	}

	return 0;
}


static VALUE_PAIR *data2vp(const RADIUS_PACKET *packet,
			   const RADIUS_PACKET *original,
			   const char *secret, size_t length,
			   const uint8_t *data, VALUE_PAIR *vp)
{
	int offset = 0;

	/*
	 *	If length is greater than 253, something is SERIOUSLY
	 *	wrong.
	 */
	if (length > 253) length = 253;	/* paranoia (pair-anoia?) */

	vp->length = length;
	vp->operator = T_OP_EQ;
	vp->next = NULL;

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
			    (vp->type == PW_TYPE_OCTETS)) offset = 1;
		}
	}

	/*
	 *	Copy the data to be decrypted
	 */
	memcpy(&vp->vp_octets[0], data + offset, length - offset);
	vp->length -= offset;

	/*
	 *	Decrypt the attribute.
	 */
	switch (vp->flags.encrypt) {
		/*
		 *  User-Password
		 */
	case FLAG_ENCRYPT_USER_PASSWORD:
		if (original) {
			rad_pwdecode((char *)vp->vp_strvalue,
				     vp->length, secret,
				     original->vector);
		} else {
			rad_pwdecode((char *)vp->vp_strvalue,
				     vp->length, secret,
				     packet->vector);
		}
		if (vp->attribute == PW_USER_PASSWORD) {
			vp->length = strlen(vp->vp_strvalue);
		}
		break;

		/*
		 *	Tunnel-Password's may go ONLY
		 *	in response packets.
		 */
	case FLAG_ENCRYPT_TUNNEL_PASSWORD:
		if (!original) goto raw;

		if (rad_tunnel_pwdecode(vp->vp_octets, &vp->length,
					secret, original->vector) < 0) {
			goto raw;
		}
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
			memcpy(vp->vp_strvalue, my_digest,
			       AUTH_VECTOR_LEN );
			vp->vp_strvalue[AUTH_VECTOR_LEN] = '\0';
			vp->length = strlen(vp->vp_strvalue);
		}
		break;

	default:
		break;
	} /* switch over encryption flags */


	switch (vp->type) {
	case PW_TYPE_STRING:
	case PW_TYPE_OCTETS:
	case PW_TYPE_ABINARY:
		/* nothing more to do */
		break;

	case PW_TYPE_BYTE:
		if (vp->length != 1) goto raw;

		vp->vp_integer = vp->vp_octets[0];
		break;


	case PW_TYPE_SHORT:
		if (vp->length != 2) goto raw;

		vp->vp_integer = (vp->vp_octets[0] << 8) | vp->vp_octets[1];
		break;

	case PW_TYPE_INTEGER:
		if (vp->length != 4) goto raw;

		memcpy(&vp->vp_integer, vp->vp_octets, 4);
		vp->vp_integer = ntohl(vp->vp_integer);

		if (vp->flags.has_tag) vp->vp_integer &= 0x00ffffff;

		/*
		 *	Try to get named VALUEs
		 */
		{
			DICT_VALUE *dval;
			dval = dict_valbyattr(vp->attribute, vp->vendor,
					      vp->vp_integer);
			if (dval) {
				strlcpy(vp->vp_strvalue,
					dval->name,
					sizeof(vp->vp_strvalue));
			}
		}
		break;

	case PW_TYPE_DATE:
		if (vp->length != 4) goto raw;

		memcpy(&vp->vp_date, vp->vp_octets, 4);
		vp->vp_date = ntohl(vp->vp_date);
		break;


	case PW_TYPE_IPADDR:
		if (vp->length != 4) goto raw;

		memcpy(&vp->vp_ipaddr, vp->vp_octets, 4);
		break;

		/*
		 *	IPv6 interface ID is 8 octets long.
		 */
	case PW_TYPE_IFID:
		if (vp->length != 8) goto raw;
		/* vp->vp_ifid == vp->vp_octets */
		break;

		/*
		 *	IPv6 addresses are 16 octets long
		 */
	case PW_TYPE_IPV6ADDR:
		if (vp->length != 16) goto raw;
		/* vp->vp_ipv6addr == vp->vp_octets */
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
		if (vp->vp_octets[1] > 128) goto raw;

		/*
		 *	FIXME: double-check that
		 *	(vp->vp_octets[1] >> 3) matches vp->length + 2
		 */
		if (vp->length < 18) {
			memset(vp->vp_octets + vp->length, 0,
			       18 - vp->length);
		}
		break;

	case PW_TYPE_SIGNED:
		if (vp->length != 4) goto raw;

		/*
		 *	Overload vp_integer for ntohl, which takes
		 *	uint32_t, not int32_t
		 */
		memcpy(&vp->vp_integer, vp->vp_octets, 4);
		vp->vp_integer = ntohl(vp->vp_integer);
		memcpy(&vp->vp_signed, &vp->vp_integer, 4);
		break;

	case PW_TYPE_TLV:
		vp->length = length;
		vp->vp_tlv = malloc(length);
		if (!vp->vp_tlv) {
			pairfree(&vp);
			fr_strerror_printf("No memory");
			return NULL;
		}
		memcpy(vp->vp_tlv, data, length);
		break;

	case PW_TYPE_COMBO_IP:
		if (vp->length == 4) {
			vp->type = PW_TYPE_IPADDR;
			memcpy(&vp->vp_ipaddr, vp->vp_octets, 4);
			break;

		} else if (vp->length == 16) {
			vp->type = PW_TYPE_IPV6ADDR;
			/* vp->vp_ipv6addr == vp->vp_octets */
			break;

		}
		/* FALL-THROUGH */

	default:
	raw:
		vp->type = PW_TYPE_OCTETS;
		vp->length = length;
		memcpy(vp->vp_octets, data, length);


		/*
		 *	Ensure there's no encryption or tag stuff,
		 *	we just pass the attribute as-is.
		 */
		memset(&vp->flags, 0, sizeof(vp->flags));
	}

	return vp;
}

static void rad_sortvp(VALUE_PAIR **head)
{
	int swapped;
	VALUE_PAIR *vp, **tail;

	/*
	 *	Walk over the VP's, sorting them in order.  Did I
	 *	mention that I hate WiMAX continuations?
	 *
	 *	And bubble sort!  WTF is up with that?
	 */
	do {
		swapped = 0;
		tail = head;
		while (*tail) {
			vp = *tail;
			if (!vp->next) break;

			if (vp->attribute > vp->next->attribute) {
				*tail = vp->next;
				vp->next = (*tail)->next;
				(*tail)->next = vp;
				swapped = 1;
			}
			tail = &(vp->next);
		}
	} while (swapped);
}


/*
 *	Walk the packet, looking for continuations of this attribute.
 *
 *	This is (worst-case) O(N^2) in the number of RADIUS
 *	attributes.  That happens only when perverse clients create
 *	continued attributes, AND separate the fragmented portions
 *	with a lot of other attributes.
 *
 *	Sane clients should put the fragments next to each other, in
 *	which case this is O(N), in the number of fragments.
 */
static uint8_t *rad_coalesce(unsigned int attribute, int vendor,
			     size_t length, uint8_t *data,
			     size_t packet_length, size_t *ptlv_length)
			     
{
	uint32_t lvalue;
	size_t tlv_length = length;
	uint8_t *ptr, *tlv, *tlv_data;

	for (ptr = data + length;
	     ptr != (data + packet_length);
	     ptr += ptr[1]) {
		/* FIXME: Check that there are 6 bytes of data here... */
		if ((ptr[0] != PW_VENDOR_SPECIFIC) ||
		    (ptr[1] < (2 + 4 + 3)) || /* WiMAX VSA with continuation */
		    (ptr[2] != 0) || (ptr[3] != 0) ||  /* our requirement */
		    (ptr[4] != ((vendor >> 8) & 0xff)) ||
		    (ptr[5] != (vendor & 0xff))) {
			continue;
		}

		memcpy(&lvalue, ptr + 2, 4); /* Vendor Id */
		lvalue = ntohl(lvalue);
		lvalue <<= 16;
		lvalue |= ptr[2 + 4]; /* add in VSA number */
		if (lvalue != attribute) continue;

		/*
		 *	If the vendor-length is too small, it's badly
		 *	formed, so we stop.
		 */
		if ((ptr[2 + 4 + 1]) < 3) break;

		tlv_length += ptr[2 + 4 + 1] - 3;
		if ((ptr[2 + 4 + 1 + 1] & 0x80) == 0) break;
	}

	tlv = tlv_data = malloc(tlv_length);
	if (!tlv_data) return NULL;

	memcpy(tlv, data, length);
	tlv += length;

	/*
	 *	Now we walk the list again, copying the data over to
	 *	our newly created memory.
	 */
	for (ptr = data + length;
	     ptr != (data + packet_length);
	     ptr += ptr[1]) {
		int this_length;

		if ((ptr[0] != PW_VENDOR_SPECIFIC) ||
		    (ptr[1] < (2 + 4 + 3)) || /* WiMAX VSA with continuation */
		    (ptr[2] != 0) || (ptr[3] != 0)) { /* our requirement */
			continue;
		}

		memcpy(&lvalue, ptr + 2, 4);
		lvalue = ntohl(lvalue);
		lvalue <<= 16;
		lvalue |= ptr[2 + 4];
		if (lvalue != attribute) continue;

		/*
		 *	If the vendor-length is too small, it's badly
		 *	formed, so we stop.
		 */
		if ((ptr[2 + 4 + 1]) < 3) break;

		this_length = ptr[2 + 4 + 1] - 3;
		memcpy(tlv, ptr + 2 + 4 + 3, this_length);
		tlv += this_length;

		ptr[2 + 4] = 0;	/* What a hack! */
		if ((ptr[2 + 4 + 1 + 1] & 0x80) == 0) break;
	}

	*ptlv_length = tlv_length;
	return tlv_data;
}

/*
 *	Walk over Evil WIMAX Hell, creating attributes.
 *
 *	Won't someone think of the children?  What if they read this code?
 */
static VALUE_PAIR *recurse_evil(const RADIUS_PACKET *packet,
				const RADIUS_PACKET *original,
				const char *secret,
				int attribute, int vendor,
				uint8_t *ptr, size_t len)
{
	VALUE_PAIR *head = NULL;
	VALUE_PAIR **tail = &head;
	VALUE_PAIR *vp;
	uint8_t *y;		/* why do I need to do this? */

	/*
	 *	Sanity check the attribute.
	 */
	for (y = ptr; y < (ptr + len); y += y[1]) {
		if ((y[0] == 0) || ((y + 2) > (ptr + len)) ||
		    (y[1] < 2) || ((y + y[1]) > (ptr + len))) {
			return NULL;
		}
	}

	for (y = ptr; y < (ptr + len); y += y[1]) {
		vp = paircreate(attribute | (ptr[0] << 16), vendor,
				PW_TYPE_OCTETS);
		if (!vp) {
		error:
			pairfree(&head);
			return NULL;
		}

		if (!data2vp(packet, original, secret,
			     y[1] - 2, y + 2, vp)) {
			goto error;
		}

		*tail = vp;
		tail = &(vp->next);
	}

	return head;
}

/*
 *	Start at the *data* portion of a continued attribute.  search
 *	through the rest of the attributes to find a matching one, and
 *	add it's contents to our contents.
 */
static VALUE_PAIR *rad_continuation2vp(const RADIUS_PACKET *packet,
				       const RADIUS_PACKET *original,
				       const char *secret, int attribute,
				       int vendor,
				       int length, /* CANNOT be zero */
				       uint8_t *data, size_t packet_length,
				       int flag, DICT_ATTR *da)
{
	size_t tlv_length, left;
	uint8_t *ptr;
	uint8_t *tlv_data;
	VALUE_PAIR *vp, *head, **tail;
	DICT_ATTR *tlv_da;

	/*
	 *	Ensure we have data that hasn't been split across
	 *	multiple attributes.
	 */
	if (flag) {
		tlv_data = rad_coalesce(attribute, vendor, length,
					data, packet_length, &tlv_length);
		if (!tlv_data) return NULL;
	} else {
		tlv_data = data;
		tlv_length = length;
	}

	/*
	 *	Non-TLV types cannot be continued across multiple
	 *	attributes.  This is true even of keys that are
	 *	encrypted with the tunnel-password method.  The spec
	 *	says that they can be continued... but also that the
	 *	keys are 160 bits, which means that they CANNOT be
	 *	continued.  <sigh>
	 *
	 *	Note that we don't check "flag" here.  The calling
	 *	code ensures that 
	 */
	if (!da || (da->type != PW_TYPE_TLV)) {
	not_well_formed:
		if (tlv_data == data) {	/* true if we had 'goto' */
			tlv_data = malloc(tlv_length);
			if (!tlv_data) return NULL;
			memcpy(tlv_data, data, tlv_length);
		}
		
		vp = paircreate(attribute, vendor, PW_TYPE_OCTETS);
		if (!vp) return NULL;
			
		vp->type = PW_TYPE_TLV;
		vp->flags.encrypt = FLAG_ENCRYPT_NONE;
		vp->flags.has_tag = 0;
		vp->flags.is_tlv = 0;
		vp->vp_tlv = tlv_data;
		vp->length = tlv_length;
		return vp;
	} /* else it WAS a TLV, go decode the sub-tlv's */

	/*
	 *	Now (sigh) we walk over the TLV, seeing if it is
	 *	well-formed.
	 */
	left = tlv_length;
	for (ptr = tlv_data;
	     ptr != (tlv_data + tlv_length);
	     ptr += ptr[1]) {
		if ((left < 2) ||
		    (ptr[1] < 2) ||
		    (ptr[1] > left)) {
			goto not_well_formed;
		}

		left -= ptr[1];
	}

	/*
	 *	Now we walk over the TLV *again*, creating sub-tlv's.
	 */
	head = NULL;
	tail = &head;

	for (ptr = tlv_data;
	     ptr != (tlv_data + tlv_length);
	     ptr += ptr[1]) {

		tlv_da = dict_attrbyvalue(attribute | (ptr[0] << 8), vendor);
		if (tlv_da && (tlv_da->type == PW_TYPE_TLV)) {
			vp = recurse_evil(packet, original, secret,
					  attribute | (ptr[0] << 8),
					  vendor, ptr + 2, ptr[1] - 2);

			if (!vp) {
				pairfree(&head);
				goto not_well_formed;
			}
		} else {
			vp = paircreate(attribute | (ptr[0] << 8), vendor,
					PW_TYPE_OCTETS);
			if (!vp) {
				pairfree(&head);
				goto not_well_formed;
			}

			if (!data2vp(packet, original, secret,
				     ptr[1] - 2, ptr + 2, vp)) {
				pairfree(&head);
				goto not_well_formed;
			}
		}

		*tail = vp;
		while ((*tail)->next) tail = &((*tail)->next);
	}

	/*
	 *	TLV's MAY be continued, but sometimes they're not.
	 */
	if (tlv_data != data) free(tlv_data);

	if (head->next) rad_sortvp(&head);

	return head;
}


/*
 *	Parse a RADIUS attribute into a data structure.
 */
VALUE_PAIR *rad_attr2vp(const RADIUS_PACKET *packet,
			const RADIUS_PACKET *original,
			const char *secret, int attribute, int vendor,
			int length, const uint8_t *data)
{
	VALUE_PAIR *vp;

	vp = paircreate(attribute, vendor, PW_TYPE_OCTETS);
	if (!vp) return NULL;

	return data2vp(packet, original, secret, length, data, vp);
}


/*
 *	Calculate/check digest, and decode radius attributes.
 *	Returns:
 *	-1 on decoding error
 *	0 on success
 */
int rad_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original,
	       const char *secret)
{
	uint32_t		lvalue;
	uint32_t		vendorcode;
	VALUE_PAIR		**tail;
	VALUE_PAIR		*pair;
	uint8_t			*ptr, *vsa_ptr;
	int			packet_length;
	int			attribute;
	int			attrlen;
	int			vendorlen;
	radius_packet_t		*hdr;
	int			vsa_tlen, vsa_llen, vsa_offset;
	DICT_VENDOR		*dv = NULL;
	int			num_attributes = 0;

	/*
	 *	Extract attribute-value pairs
	 */
	hdr = (radius_packet_t *)packet->data;
	ptr = hdr->data;
	packet_length = packet->data_len - AUTH_HDR_LEN;

	/*
	 *	There may be VP's already in the packet.  Don't
	 *	destroy them.
	 */
	for (tail = &packet->vps; *tail != NULL; tail = &((*tail)->next)) {
		/* nothing */
	}

	vendorcode = 0;
	vendorlen  = 0;
	vsa_tlen = vsa_llen = 1;
	vsa_offset = 0;

	/*
	 *	We have to read at least two bytes.
	 *
	 *	rad_recv() above ensures that this is OK.
	 */
	while (packet_length > 0) {
		attribute = -1;
		attrlen = -1;

		/*
		 *	Normal attribute, handle it like normal.
		 */
		if (vendorcode == 0) {
			/*
			 *	No room to read attr/length,
			 *	or bad attribute, or attribute is
			 *	too short, or attribute is too long,
			 *	stop processing the packet.
			 */
			if ((packet_length < 2) ||
			    (ptr[0] == 0) ||  (ptr[1] < 2) ||
			    (ptr[1] > packet_length)) break;

			attribute = *ptr++;
			attrlen   = *ptr++;

			attrlen -= 2;
			packet_length  -= 2;

			if (attribute != PW_VENDOR_SPECIFIC) goto create_pair;

			/*
			 *	No vendor code, or ONLY vendor code.
			 */
			if (attrlen <= 4) goto create_pair;

			vendorlen = 0;
		}

		/*
		 *	Handle Vendor-Specific
		 */
		if (vendorlen == 0) {
			uint8_t *subptr;
			int sublen;
			int myvendor;

			/*
			 *	attrlen was checked above.
			 */
			memcpy(&lvalue, ptr, 4);
			myvendor = ntohl(lvalue);

			/*
			 *	Zero isn't allowed.
			 */
			if (myvendor == 0) goto create_pair;

			/*
			 *	This is an implementation issue.
			 *	We currently pack vendor into the upper
			 *	16 bits of a 32-bit attribute number,
			 *	so we can't handle vendor numbers larger
			 *	than 16 bits.
			 */
			if (myvendor > 65535) goto create_pair;

			vsa_tlen = vsa_llen = 1;
			vsa_offset = 0;
			dv = dict_vendorbyvalue(myvendor);
			if (dv) {
				vsa_tlen = dv->type;
				vsa_llen = dv->length;
				if (dv->flags) vsa_offset = 1;
			}

			/*
			 *	Sweep through the list of VSA's,
			 *	seeing if they exactly fill the
			 *	outer Vendor-Specific attribute.
			 *
			 *	If not, create a raw Vendor-Specific.
			 */
			subptr = ptr + 4;
			sublen = attrlen - 4;

			/*
			 *	See if we can parse it.
			 */
			do {
				int myattr = 0;

				/*
				 *	Not enough room for one more
				 *	attribute.  Die!
				 */
				if (sublen < (vsa_tlen + vsa_llen + vsa_offset)) goto create_pair;

				/*
				 *	Ensure that the attribute number
				 *	is OK.
				 */
				switch (vsa_tlen) {
				case 1:
					myattr = subptr[0];
					break;

				case 2:
					myattr = (subptr[0] << 8) | subptr[1];
					break;

				case 4:
					if ((subptr[0] != 0) ||
					    (subptr[1] != 0)) goto create_pair;

					myattr = (subptr[2] << 8) | subptr[3];
					break;

					/*
					 *	Our dictionary is broken.
					 */
				default:
					goto create_pair;
				}

				switch (vsa_llen) {
				case 0:
					attribute = myattr;
					ptr += 4 + vsa_tlen;
					attrlen -= (4 + vsa_tlen);
					packet_length -= 4 + vsa_tlen;
					goto create_pair;

				case 1:
					if (subptr[vsa_tlen] < (vsa_tlen + vsa_llen + vsa_offset))
						goto create_pair;

					if (subptr[vsa_tlen] > sublen)
						goto create_pair;

					/*
					 *	WiMAX: 0bCrrrrrrr
					 *	Reserved bits MUST be
					 *	zero.
					 */
					if (vsa_offset &&
					    ((subptr[vsa_tlen + vsa_llen] & 0x7f) != 0))
						goto create_pair;

					sublen -= subptr[vsa_tlen];
					subptr += subptr[vsa_tlen];
					break;

				case 2:
					if (subptr[vsa_tlen] != 0) goto create_pair;
					if (subptr[vsa_tlen + 1] < (vsa_tlen + vsa_llen))
						goto create_pair;
					if (subptr[vsa_tlen + 1] > sublen)
						goto create_pair;
					sublen -= subptr[vsa_tlen + 1];
					subptr += subptr[vsa_tlen + 1];
					break;

					/*
					 *	Our dictionaries are
					 *	broken.
					 */
				default:
					goto create_pair;
				}
			} while (sublen > 0);

			vendorcode = myvendor;
			vendorlen = attrlen - 4;
			packet_length -= 4;

			ptr += 4;
		}

		/*
		 *	attrlen is the length of this attribute.
		 *	total_len is the length of the encompassing
		 *	attribute.
		 */
		switch (vsa_tlen) {
		case 1:
			attribute = ptr[0];
			break;

		case 2:
			attribute = (ptr[0] << 8) | ptr[1];
			break;

		default:	/* can't hit this. */
			return -1;
		}
		vsa_ptr = ptr;
		ptr += vsa_tlen;

		switch (vsa_llen) {
		case 1:
			attrlen = ptr[0] - (vsa_tlen + vsa_llen + vsa_offset);
			break;

		case 2:
			attrlen = ptr[1] - (vsa_tlen + vsa_llen);
			break;

		default:	/* can't hit this. */
			return -1;
		}

		ptr += vsa_llen + vsa_offset;
		vendorlen -= vsa_tlen + vsa_llen + vsa_offset + attrlen;
		packet_length -= (vsa_tlen + vsa_llen + vsa_offset);

		/*
		 *	Ignore VSAs that have no data.
		 */
		if (attrlen == 0) goto next;

		/*
		 *	WiMAX attributes of type 0 are ignored.  They
		 *	are a secret flag to us that the attribute has
		 *	already been dealt with.
		 */
		if ((vendorcode == VENDORPEC_WIMAX) && (attribute == 0)) {
			goto next;
		}

		if (vsa_offset) {
			DICT_ATTR *da;

			da = dict_attrbyvalue(attribute, vendorcode);

			/*
			 *	If it's NOT continued, AND we know
			 *	about it, AND it's not a TLV, we can
			 *	create a normal pair.
			 */
			if (((vsa_ptr[2] & 0x80) == 0) &&
			    da && (da->type != PW_TYPE_TLV)) goto create_pair;

			/*
			 *	Else it IS continued, or it's a TLV.
			 *	Go do a lot of work to find the stuff.
			 */
			pair = rad_continuation2vp(packet, original, secret,
						   attribute, vendorcode,
						   attrlen, ptr,
						   packet_length,
						   ((vsa_ptr[2] & 0x80) != 0),
						   da);
			goto created_pair;
		}

		/*
		 *	Create the attribute, setting the default type
		 *	to 'octets'.  If the type in the dictionary
		 *	is different, then the dictionary type will
		 *	over-ride this one.
		 *
		 *	If the attribute has no data, then discard it.
		 *
		 *	Unless it's CUI.  Damn you, CUI!
		 */
	create_pair:
		if (!attrlen &&
		    (attribute != PW_CHARGEABLE_USER_IDENTITY)) goto next;

		pair = rad_attr2vp(packet, original, secret,
				   attribute, vendorcode, attrlen, ptr);
		if (!pair) {
			pairfree(&packet->vps);
			fr_strerror_printf("out of memory");
			return -1;
		}

	created_pair:
		*tail = pair;
		while (pair) {
			num_attributes++;
			debug_pair(pair);
			tail = &pair->next;
			pair = pair->next;
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

			pairfree(&packet->vps);
			fr_strerror_printf("WARNING: Possible DoS attack from host %s: Too many attributes in request (received %d, max %d are allowed).",
				   inet_ntop(packet->src_ipaddr.af,
					     &packet->src_ipaddr.ipaddr,
					     host_ipaddr, sizeof(host_ipaddr)),
				   num_attributes, fr_max_attributes);
			return -1;
		}

	next:
		if (vendorlen == 0) vendorcode = 0;
		ptr += attrlen;
		packet_length -= attrlen;
	}

	/*
	 *	Merge information from the outside world into our
	 *	random pool.
	 */
	fr_rand_seed(packet->data, AUTH_HDR_LEN);

	return 0;
}


/*
 *	Encode password.
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

/*
 *	Decode password.
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


/*
 *	Encode Tunnel-Password attributes when sending them out on the wire.
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

/*
 *	Decode Tunnel-Password encrypted attributes.
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

/*
 *	Encode a CHAP password
 *
 *	FIXME: might not work with Ascend because
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
	 *	Request-Authenticator otherwise.
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


/*
 *	Seed the random number generator.
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

			total = this = 0;
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


/*
 *	Return a 32-bit random number.
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


/*
 *	Allocate a new RADIUS_PACKET
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


/*
 *	Free a RADIUS_PACKET
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
