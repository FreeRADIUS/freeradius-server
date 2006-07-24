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
 * Copyright 2000-2003  The FreeRADIUS server project
 */

static const char rcsid[] = "$Id$";

#include	<freeradius-devel/autoconf.h>
#include	<freeradius-devel/md5.h>

#include	<stdlib.h>

#ifdef HAVE_UNISTD_H
#include	<unistd.h>
#endif

#include	<fcntl.h>
#include	<string.h>
#include	<ctype.h>

#ifdef WITH_UDPFROMTO
#include	<freeradius-devel/udpfromto.h>
#endif

#include	<sys/socket.h>

#ifdef HAVE_MALLOC_H
#include	<malloc.h>
#endif

#ifdef WIN32
#include	<process.h>
#endif

#include	<freeradius-devel/missing.h>
#include	<freeradius-devel/libradius.h>

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
int librad_max_attributes = 0;

typedef struct radius_packet_t {
  uint8_t	code;
  uint8_t	id;
  uint8_t	length[2];
  uint8_t	vector[AUTH_VECTOR_LEN];
  uint8_t	data[1];
} radius_packet_t;

static lrad_randctx lrad_rand_pool;	/* across multiple calls */
static int lrad_rand_initialized = 0;
static unsigned int salt_offset = 0;


#define MAX_PACKET_CODE (52)
static const char *packet_codes[] = {
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


/*
 *	Wrapper for sendto which handles sendfromto, IPv6, and all
 *	possible combinations.
 */
static int rad_sendto(int sockfd, void *data, size_t data_len, int flags,
		      lrad_ipaddr_t *src_ipaddr, lrad_ipaddr_t *dst_ipaddr,
		      int dst_port)
{
	struct sockaddr_storage	dst;
	socklen_t		sizeof_dst = sizeof(dst);

#ifdef WITH_UDPFROMTO
	struct sockaddr_storage	src;
	socklen_t		sizeof_src = sizeof(src);

	memset(&src, 0, sizeof(src));
#endif
	memset(&dst, 0, sizeof(dst));

	/*
	 *	IPv4 is supported.
	 */
	if (dst_ipaddr->af == AF_INET) {
		struct sockaddr_in	*s4;

		s4 = (struct sockaddr_in *)&dst;
		sizeof_dst = sizeof(struct sockaddr_in);

		s4->sin_family = AF_INET;
		s4->sin_addr = dst_ipaddr->ipaddr.ip4addr;
		s4->sin_port = htons(dst_port);

#ifdef WITH_UDPFROMTO
		s4 = (struct sockaddr_in *)&src;
		sizeof_src = sizeof(struct sockaddr_in);

		s4->sin_family = AF_INET;
		s4->sin_addr = src_ipaddr->ipaddr.ip4addr;
#endif

	/*
	 *	IPv6 MAY be supported.
	 */
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (dst_ipaddr->af == AF_INET6) {
		struct sockaddr_in6	*s6;

		s6 = (struct sockaddr_in6 *)&dst;
		sizeof_dst = sizeof(struct sockaddr_in6);
		
		s6->sin6_family = AF_INET6;
		s6->sin6_addr = dst_ipaddr->ipaddr.ip6addr;
		s6->sin6_port = htons(dst_port);

#ifdef WITH_UDPFROMTO
		return -1;	/* UDPFROMTO && IPv6 are not supported */
#if 0
		s6 = (struct sockaddr_in6 *)&src;
		sizeof_src = sizeof(struct sockaddr_in6);

		s6->sin6_family = AF_INET6;
		s6->sin6_addr = src_ipaddr->ipaddr.ip6addr;
#endif /* #if 0 */
#endif /* WITH_UDPFROMTO */
#endif /* HAVE_STRUCT_SOCKADDR_IN6 */
	} else return -1;   /* Unknown address family, Die Die Die! */

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
		      (struct sockaddr *)&dst, sizeof_dst);
}


/*
 *	Wrapper for recvfrom, which handles recvfromto, IPv6, and all
 *	possible combinations.
 */
static ssize_t rad_recvfrom(int sockfd, uint8_t **pbuf, int flags,
			    lrad_ipaddr_t *src_ipaddr, uint16_t *src_port,
			    lrad_ipaddr_t *dst_ipaddr, uint16_t *dst_port)
{
	struct sockaddr_storage	src;
	struct sockaddr_storage	dst;
	socklen_t		sizeof_src = sizeof(src);
	socklen_t	        sizeof_dst = sizeof(dst);
	ssize_t			data_len;
	uint8_t			header[4];
	void			*buf;
	size_t			len;

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
	if (data_len < 0) return -1;

	/*
	 *	Too little data is available, round it up to 4 bytes.
	 */
	if (data_len < 4) {
		len = 4;
	} else {		/* we got 4 bytes of data. */
		/*
		 *	See how long the packet says it is.
		 */
		len = (header[2] * 256) + header[3];

		/*
		 *	Too short: read 4 bytes, and discard the rest.
		 */
		if (len < 4) {
			len = 4;

			/*
			 *	Enforce RFC requirements, for sanity.
			 *	Anything after 4k will be discarded.
			 */
		} else if (len > MAX_PACKET_LEN) {
			len = MAX_PACKET_LEN;
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

	/*
	 *	Check address families, and update src/dst ports, etc.
	 */
	if (src.ss_family == AF_INET) {
		struct sockaddr_in	*s4;

		s4 = (struct sockaddr_in *)&src;
		src_ipaddr->af = AF_INET;
		src_ipaddr->ipaddr.ip4addr = s4->sin_addr;
		*src_port = ntohs(s4->sin_port);

		s4 = (struct sockaddr_in *)&dst;
		dst_ipaddr->af = AF_INET;
		dst_ipaddr->ipaddr.ip4addr = s4->sin_addr;
		*dst_port = ntohs(s4->sin_port);

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (src.ss_family == AF_INET6) {
		struct sockaddr_in6	*s6;

		s6 = (struct sockaddr_in6 *)&src;
		src_ipaddr->af = AF_INET6;
		src_ipaddr->ipaddr.ip6addr = s6->sin6_addr;
		*src_port = ntohs(s6->sin6_port);

		s6 = (struct sockaddr_in6 *)&dst;
		dst_ipaddr->af = AF_INET6;
		dst_ipaddr->ipaddr.ip6addr = s6->sin6_addr;
		*dst_port = ntohs(s6->sin6_port);
#endif
	} else {
		free(buf);
		return -1;	/* Unknown address family, Die Die Die! */
	}
	
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
	lrad_MD5_CTX context;
        int             i;

	lrad_MD5Init(&context);
	lrad_MD5Update(&context, vector, AUTH_VECTOR_LEN);
	lrad_MD5Update(&context, secret, strlen(secret));
	lrad_MD5Final(digest, &context);

        for ( i = 0; i < AUTH_VECTOR_LEN; i++ ) {
		digest[i] ^= value[i];
        }
}

#define MAX_PASS_LEN (128)
static void make_passwd(uint8_t *output, int *outlen,
			const uint8_t *input, int inlen,
			const char *secret, const uint8_t *vector)
{
	lrad_MD5_CTX context, old;
	uint8_t	digest[AUTH_VECTOR_LEN];
	uint8_t passwd[MAX_PASS_LEN];
	int	i, n;
	int	len;

	/*
	 *	If the length is zero, round it up.
	 */
	len = inlen;
	if (len == 0) {
		len = AUTH_PASS_LEN;
	}
	else if (len > MAX_PASS_LEN) len = MAX_PASS_LEN;

	else if ((len & 0x0f) != 0) {
		len += 0x0f;
		len &= ~0x0f;
	}
	*outlen = len;

	memcpy(passwd, input, len);
	memset(passwd + len, 0, sizeof(passwd) - len);

	lrad_MD5Init(&context);
	lrad_MD5Update(&context, secret, strlen(secret));
	old = context;

	/*
	 *	Do first pass.
	 */
	lrad_MD5Update(&context, vector, AUTH_PASS_LEN);

	for (n = 0; n < len; n += AUTH_PASS_LEN) {
		if (n > 0) {
			context = old;
			lrad_MD5Update(&context,
				       passwd + n - AUTH_PASS_LEN,
				       AUTH_PASS_LEN);
		}

		lrad_MD5Final(digest, &context);
		for (i = 0; i < AUTH_PASS_LEN; i++) {
			passwd[i + n] ^= digest[i];
		}
	}

	memcpy(output, passwd, len);
}

static void make_tunnel_passwd(uint8_t *output, int *outlen,
			       const uint8_t *input, int inlen, int room,
			       const char *secret, const uint8_t *vector)
{
	lrad_MD5_CTX context, old;
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
		     (lrad_rand() & 0x07));
	passwd[1] = lrad_rand();
	passwd[2] = inlen;	/* length of the password string */

	lrad_MD5Init(&context);
	lrad_MD5Update(&context, secret, strlen(secret));
	old = context;

	lrad_MD5Update(&context, vector, AUTH_VECTOR_LEN);
	lrad_MD5Update(&context, &passwd[0], 2);

	for (n = 0; n < len; n += AUTH_PASS_LEN) {
		if (n > 0) {
			context = old;
			lrad_MD5Update(&context,
				       passwd + 2 + n - AUTH_PASS_LEN,
				       AUTH_PASS_LEN);
		}

		lrad_MD5Final(digest, &context);
		for (i = 0; i < AUTH_PASS_LEN; i++) {
			passwd[i + 2 + n] ^= digest[i];
		}
	}
	memcpy(output, passwd, len + 2);
}

/*
 *	Hack for IETF RADEXT.  Don't use in a production environment!
 *
 *	FIXME: Pack multiple diameter attributes into one
 *	Extended-Attribute!
 */
static int vp2diameter(const RADIUS_PACKET *packet,
		       const RADIUS_PACKET *original, const char *secret,
		       const VALUE_PAIR *vp, uint8_t *ptr)
{
	uint32_t attr;
	uint32_t length = vp->length;
	uint32_t vendor;
	int total, align;
	uint8_t *length_ptr;

	*(ptr++) = PW_EXTENDED_ATTRIBUTE;
	length_ptr = ptr++;	/* fill this in later. */
	total = 2;

	attr = vp->attribute;
	attr &= ~(1 << 31);	/* implemented limitations, see dict_addattr */
	vendor = VENDOR(attr);
	attr = attr & 0xffff;
	attr = ntohl(attr);
	
	memcpy(ptr, &attr, sizeof(attr));
	ptr += 4;
	total += 4;
	length += 8;	       /* includes 8 bytes of attr & length */
	align = 0;		/* no padding */

	if (vendor != 0) {
		length += 4; /* include 4 bytes of vendor */
		
		length |= (1 << 31);
		length = ntohl(length);
		memcpy(ptr, &length, sizeof(length));
		ptr += 4;
		total += 4;
		
		vendor = ntohl(vendor);
		memcpy(ptr, &vendor, sizeof(vendor));
		ptr += 4;
		total += 4;
	} else {
		length = ntohl(length);
		memcpy(ptr, &length, sizeof(length));
		ptr += 4;
		total += 4;
	}
	*length_ptr = total;

	switch (vp->type) {
	case PW_TYPE_INTEGER:
	case PW_TYPE_DATE:
		attr = ntohl(vp->lvalue); /* stored in host order */
		memcpy(ptr, &attr, sizeof(attr));
		length = 4;
		break;
		
	case PW_TYPE_IPADDR:
		attr = vp->lvalue; /* stored in network order */
		memcpy(ptr, &attr, sizeof(attr));
		length = 4;
		break;
		
	case PW_TYPE_IFID:
	case PW_TYPE_IPV6ADDR:
	case PW_TYPE_IPV6PREFIX:
	case PW_TYPE_ABINARY:
		memcpy(ptr, vp->vp_strvalue, vp->length);
		length = vp->length;
		if ((length & 0x03) != 0) align = 4 - (length & 0x03);
		break;

		/*
		 *	Length MAY be larger than can fit into the
		 *	encapsulating attribute!
		 */
	case PW_TYPE_STRING:
	case PW_TYPE_OCTETS:
	default:
		{
			uint32_t offset = 0;
			
			length = vp->length;
			if ((length & 0x03) != 0) align = 4 - (length & 0x03);
			
			if (total + length > 255) {
				*length_ptr = 255;
				offset = 255 - total;

				memcpy(ptr, vp->vp_octets, offset);
				ptr += offset;
				*(ptr++) = PW_EXTENDED_ATTRIBUTE;
				length_ptr = ptr++;
				*length_ptr = 2;
				length -= offset;

				total += offset + 2;
			}
			
			memcpy(ptr, vp->vp_octets + offset, length);
		}
		break;
	}
	
	/*
	 *	Skip to the end of the data.
	 */
	ptr += length;
	total += length;
	*length_ptr += length;

	/*
	 *	Align the data to a multiple of 4 bytes.
	 */
	if (align != 0) {
		unsigned int i;
		
		*length_ptr += align;
		for (i = 0; i < align; i++) {
			*(ptr++) = '\0';
			total++;
		}
	}

	return total;
}


/*
 *	Parse a data structure into a RADIUS attribute.
 */
int rad_vp2attr(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
		const char *secret, const VALUE_PAIR *vp, uint8_t *ptr)
{
	int		vendorcode;
	int		offset, len, total_length;
	uint32_t	lvalue;
	uint8_t		*length_ptr, *vsa_length_ptr;
	const uint8_t	*data = NULL;
	uint8_t		array[4];

	vendorcode = total_length = 0;
	length_ptr = vsa_length_ptr = NULL;

	/*
	 *	For interoperability, always put vendor attributes
	 *	into their own VSA.
	 */
	if ((vendorcode = VENDOR(vp->attribute)) == 0) {
		*(ptr++) = vp->attribute & 0xFF;
		length_ptr = ptr;
		*(ptr++) = 2;
		total_length += 2;

	} else {
		int vsa_tlen = 1;
		int vsa_llen = 1;
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
		}

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

		total_length += vsa_tlen + vsa_llen;
		if (vsa_length_ptr) *vsa_length_ptr += vsa_tlen + vsa_llen;
		*length_ptr += vsa_tlen + vsa_llen;
	}

	offset = 0;
	if (vp->flags.has_tag) {
		if (TAG_VALID(vp->flags.tag)) {
			ptr[0] = vp->flags.tag & 0xff;
			offset = 1;
	    
		} else if (vp->flags.encrypt == FLAG_ENCRYPT_TUNNEL_PASSWORD) {
			/*
			 *	Tunnel passwords REQUIRE a tag, even
			 *	if don't have a valid tag.
			 */
			ptr[0] = 0;
			offset = 1;
		} /* else don't write a tag */
	} /* else the attribute doesn't have a tag */
	
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
			
	case PW_TYPE_INTEGER:
		len = 4;	/* just in case */
		lvalue = htonl(vp->lvalue);
		memcpy(array, &lvalue, sizeof(lvalue));

		/*
		 *	Perhaps discard the first octet.
		 */
		data = &array[offset];
		len -= offset;
		break;
			
	case PW_TYPE_IPADDR:
		data = (const uint8_t *) &vp->lvalue;
		len = 4;	/* just in case */
		break;

		/*
		 *  There are no tagged date attributes.
		 */
	case PW_TYPE_DATE:
		lvalue = htonl(vp->lvalue);
		data = (const uint8_t *) &lvalue;
		len = 4;	/* just in case */
		break;

	default:		/* unknown type: ignore it */
		librad_log("ERROR: Unknown attribute type %d", vp->type);
		return -1;
	}

	/*
	 *	Bound the data to 255 bytes.
	 */
	if (len + offset + total_length > 255) {
		len = 255 - offset - total_length;
	}	

	/*
	 *	Encrypt the various password styles
	 *
	 *	Attributes with encrypted values MUST be less than
	 *	128 bytes long.
	 */
	switch (vp->flags.encrypt) {
	case FLAG_ENCRYPT_USER_PASSWORD:
		make_passwd(ptr + offset, &len,
			    data, len,
			    secret, packet->vector);
		break;
		
	case FLAG_ENCRYPT_TUNNEL_PASSWORD:
		if (!original) {
			librad_log("ERROR: No request packet, cannot encrypt %s attribute in the vp.", vp->name);
			return -1;
		}

		/*
		 *	Check if 255 - offset - total_length is less
		 *	than 18.  If so, we can't fit the data into
		 *	the available space, and we discard the
		 *	attribute.
		 *
		 *	This is ONLY a problem if we have multiple VSA's
		 *	in one Vendor-Specific, though.
		 */
		if ((255 - offset - total_length) < 18) return 0;

		make_tunnel_passwd(ptr + offset, &len,
				   data, len, 255 - offset - total_length,
				   secret, original->vector);
		break;

		/*
		 *	The code above ensures that this attribute
		 *	always fits.
		 */
	case FLAG_ENCRYPT_ASCEND_SECRET:
		make_secret(ptr + offset, packet->vector,
			    secret, data);
		len = AUTH_VECTOR_LEN;
		break;

		
	default:
		/*
		 *	Just copy the data over
		 */
		memcpy(ptr + offset, data, len);
		break;
	} /* switch over encryption flags */

	/*
	 *	Account for the tag (if any).
	 */
	len += offset;

	/*
	 *	RFC 2865 section 5 says that zero-length attributes
	 *	MUST NOT be sent.
	 */
	if (len == 0) return 0;

	/*
	 *	Update the various lengths.
	 */
	*length_ptr += len;
	if (vsa_length_ptr) *vsa_length_ptr += len;
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
	
	/*
	 *	For simplicity in the following logic, we allow
	 *	the attributes to "overflow" the 4k maximum
	 *	RADIUS packet size, by one attribute.
	 *
	 *	It's uint32_t, for alignment purposes.
	 */
	uint32_t	data[(MAX_PACKET_LEN + 256) / 4];

	/*
	 *	Double-check some things based on packet code.
	 */
	switch (packet->code) {
	case PW_AUTHENTICATION_ACK:
	case PW_AUTHENTICATION_REJECT:
	case PW_ACCESS_CHALLENGE:
		if (!original) {
			librad_log("ERROR: Cannot sign response packet without a request packet.");
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
	packet->verified = 0;
	
	/*
	 *	Load up the configuration values for the user
	 */
	ptr = hdr->data;

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
		if ((VENDOR(reply->attribute) == 0) &&
		    ((reply->attribute & 0xFFFF) > 0xff) &&
		    !reply->flags.diameter) {
			continue;
		}
		
		/*
		 *	Check that the packet is no more than 4k in
		 *	size, AFTER over-flowing the 4k boundary.
		 *	Note that the 'data' buffer, above, is one
		 *	attribute longer than necessary, in order to
		 *	permit this overflow.
		 */
		if (total_length > MAX_PACKET_LEN) {
			librad_log("ERROR: Too many attributes for packet, result is larger than RFC maximum of 4k");
			return -1;
		}
		
		/*
		 *	Set the Message-Authenticator to the correct
		 *	length and initial value.
		 */
		if (reply->attribute == PW_MESSAGE_AUTHENTICATOR) {
			reply->length = AUTH_VECTOR_LEN;
			memset(reply->vp_strvalue, 0, AUTH_VECTOR_LEN);
			packet->verified = total_length; /* HACK! */
		}

		/*
		 *	Check for overflow.
		 */
		if (reply->flags.diameter) {
			len = reply->length;
			
			if (len >= 4096) {
				librad_log("ERROR: Too many attributes for packet, result is larger than RFC maximum of 4k");
				return -1;
			}

			len += 8; /* Code, length */
			if (VENDOR(reply->attribute) != 0) len += 4;
			if ((len & 0x03) != 0) len += 4 - (len & 0x03);

			if (len > 253) len += (len / 253) * 2;

			if ((total_length + len) > MAX_PACKET_LEN) {
				librad_log("ERROR: Too many attributes for packet, result is larger than RFC maximum of 4k");
				return -1;
			}

			debug_pair(reply);

			len = vp2diameter(packet, original, secret, reply, ptr);
		} else {
			/*
			 *	Print out ONLY the attributes which
			 *	we're sending over the wire, and print
			 *	them out BEFORE they're encrypted.
			 */
			debug_pair(reply);
			
			len = rad_vp2attr(packet, original, secret, reply, ptr);
		}

		if (len < 0) return -1;
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
		librad_log("Out of memory");
		return -1;
	}

	memcpy(packet->data, data, packet->data_len);
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
		librad_log("ERROR: RADIUS packets must be assigned an Id.");
		return -1;
	}

	if (!packet->data || (packet->data_len < AUTH_HDR_LEN) ||
	    (packet->verified < 0)) {
		librad_log("ERROR: You must call rad_encode() before rad_sign()");
		return -1;
	}

	/*
	 *	If there's a Message-Authenticator, update it
	 *	now, BEFORE updating the authentication vector.
	 *
	 *	This is a hack...
	 */
	if (packet->verified > 0) {
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
				librad_log("ERROR: Cannot sign response packet without a request packet.");
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
		lrad_hmac_md5(packet->data, packet->data_len,
			      secret, strlen(secret),
			      calc_auth_vector);
		memcpy(packet->data + packet->verified + 2,
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
			
			MD5_CTX	context;
			MD5Init(&context);
			MD5Update(&context, packet->data, packet->data_len);
			MD5Update(&context, secret, strlen(secret));
			MD5Final(digest, &context);
			
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

	if ((packet->code > 0) && (packet->code < MAX_PACKET_CODE)) {
		what = packet_codes[packet->code];
	} else {
		what = "Reply";
	}

	/*
	 *  First time through, allocate room for the packet
	 */
	if (!packet->data) {
		DEBUG("Sending %s of id %d to %s port %d\n",
		      what, packet->id,
		      inet_ntop(packet->dst_ipaddr.af,
				&packet->dst_ipaddr.ipaddr,
				ip_buffer, sizeof(ip_buffer)),
			packet->dst_port);
		
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
	} else if (librad_debug) {
	  	DEBUG("Re-sending %s of id %d to %s port %d\n", what, packet->id,
		      inet_ntop(packet->dst_ipaddr.af,
				&packet->dst_ipaddr.ipaddr,
				ip_buffer, sizeof(ip_buffer)),
		      packet->dst_port);

		for (reply = packet->vps; reply; reply = reply->next) {
			/* FIXME: ignore attributes > 0xff */
			debug_pair(reply);
		}
	}

	/*
	 *	And send it on it's way.
	 */
	return rad_sendto(packet->sockfd, packet->data, packet->data_len, 0,
			  &packet->src_ipaddr, &packet->dst_ipaddr,
			  packet->dst_port);
}


/*
 *	Validates the requesting client NAS.  Calculates the
 *	signature based on the clients private key.
 */
static int calc_acctdigest(RADIUS_PACKET *packet, const char *secret)
{
	uint8_t		digest[AUTH_VECTOR_LEN];
	MD5_CTX		context;

	/*
	 *	Older clients have the authentication vector set to
	 *	all zeros. Return `1' in that case.
	 */
	memset(digest, 0, sizeof(digest));
	if (memcmp(packet->vector, digest, AUTH_VECTOR_LEN) == 0) {
		packet->verified = 1;
		return 1;
	}

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
	MD5Init(&context);
	MD5Update(&context, packet->data, packet->data_len);
	MD5Update(&context, secret, strlen(secret));
	MD5Final(digest, &context);

	/*
	 *	Return 0 if OK, 2 if not OK.
	 */
	packet->verified =
	memcmp(digest, packet->vector, AUTH_VECTOR_LEN) ? 2 : 0;

	return packet->verified;
}

/*
 *	Validates the requesting client NAS.  Calculates the
 *	signature based on the clients private key.
 */
static int calc_replydigest(RADIUS_PACKET *packet, RADIUS_PACKET *original,
			    const char *secret)
{
	uint8_t		calc_digest[AUTH_VECTOR_LEN];
	MD5_CTX		context;

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
	MD5Init(&context);
	MD5Update(&context, packet->data, packet->data_len);
	MD5Update(&context, secret, strlen(secret));
	MD5Final(calc_digest, &context);

	/*
	 *  Copy the packet's vector back to the packet.
	 */
	memcpy(packet->data + 4, packet->vector, AUTH_VECTOR_LEN);

	/*
	 *	Return 0 if OK, 2 if not OK.
	 */
	packet->verified =
		memcmp(packet->vector, calc_digest, AUTH_VECTOR_LEN) ? 2 : 0;
	return packet->verified;
}


/*
 *	See if the data pointed to by PTR is a valid RADIUS packet.
 *
 *	packet is not 'const * const' because we may update data_len,
 *	if there's more data in the UDP packet than in the RADIUS packet.
 */
int rad_packet_ok(RADIUS_PACKET *packet)
{
	uint8_t			*attr;
	int			totallen;
	int			count;
	radius_packet_t		*hdr;
	char			host_ipaddr[128];
	int			seen_eap;
	int			num_attributes;

	/*
	 *	Check for packets smaller than the packet header.
	 *
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"The minimum length is 20 ..."
	 */
	if (packet->data_len < AUTH_HDR_LEN) {
		librad_log("WARNING: Malformed RADIUS packet from host %s: too short (received %d < minimum %d)",
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
		librad_log("WARNING: Malformed RADIUS packet from host %s: too long (received %d > maximum %d)",
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
	    (hdr->code >= MAX_PACKET_CODE)) {
		librad_log("WARNING: Bad RADIUS packet from host %s: unknown packet code %d",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
			   hdr->code);
		return 0;
	}

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
		librad_log("WARNING: Malformed RADIUS packet from host %s: too short (length %d < minimum %d)",
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
		librad_log("WARNING: Malformed RADIUS packet from host %s: too long (length %d > maximum %d)",
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
		librad_log("WARNING: Malformed RADIUS packet from host %s: received %d octets, packet length says %d",
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
	seen_eap = 0;
	num_attributes = 0;

	while (count > 0) {
		/*
		 *	Attribute number zero is NOT defined.
		 */
		if (attr[0] == 0) {
			librad_log("WARNING: Malformed RADIUS packet from host %s: Invalid attribute 0",
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
			librad_log("WARNING: Malformed RADIUS packet from host %s: attribute %d too short",
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

		case PW_EAP_MESSAGE:
			seen_eap |= PW_EAP_MESSAGE;
			break;

		case PW_MESSAGE_AUTHENTICATOR:
			if (attr[1] != 2 + AUTH_VECTOR_LEN) {
				librad_log("WARNING: Malformed RADIUS packet from host %s: Message-Authenticator has invalid length %d",
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     host_ipaddr, sizeof(host_ipaddr)),
					   attr[1] - 2);
				return 0;
			}
			seen_eap |= PW_MESSAGE_AUTHENTICATOR;
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
		librad_log("WARNING: Malformed RADIUS packet from host %s: packet attributes do NOT exactly fill the packet",
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
	if ((librad_max_attributes > 0) &&
	    (num_attributes > librad_max_attributes)) {
		librad_log("WARNING: Possible DoS attack from host %s: Too many attributes in request (received %d, max %d are allowed).",
			   inet_ntop(packet->src_ipaddr.af,
				     &packet->src_ipaddr.ipaddr,
				     host_ipaddr, sizeof(host_ipaddr)),
			   num_attributes, librad_max_attributes);
		return 0;
	}

	/*
	 * 	http://www.freeradius.org/rfc/rfc2869.html#EAP-Message
	 *
	 *	A packet with an EAP-Message attribute MUST also have
	 *	a Message-Authenticator attribute.
	 *
	 *	A Message-Authenticator all by itself is OK, though.
	 */
	if (seen_eap &&
	    (seen_eap != PW_MESSAGE_AUTHENTICATOR) &&
	    (seen_eap != (PW_EAP_MESSAGE | PW_MESSAGE_AUTHENTICATOR))) {
		librad_log("WARNING: Insecure packet from host %s:  Received EAP-Message with no Message-Authenticator.",
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
RADIUS_PACKET *rad_recv(int fd)
{
	RADIUS_PACKET		*packet;

	/*
	 *	Allocate the new request data structure
	 */
	if ((packet = malloc(sizeof(*packet))) == NULL) {
		librad_log("out of memory");
		return NULL;
	}
	memset(packet, 0, sizeof(*packet));

	packet->data_len = rad_recvfrom(fd, &packet->data, 0,
					&packet->src_ipaddr, &packet->src_port,
					&packet->dst_ipaddr, &packet->dst_port);

	/*
	 *	Check for socket errors.
	 */
	if (packet->data_len < 0) {
		librad_log("Error receiving packet: %s", strerror(errno));
		/* packet->data is NULL */
		free(packet);
		return NULL;
	}

	/*
	 *	See if it's a well-formed RADIUS packet.
	 */
	if (!rad_packet_ok(packet)) {
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

	if (librad_debug) {
		char host_ipaddr[128];

		if ((packet->code > 0) && (packet->code < MAX_PACKET_CODE)) {
			printf("rad_recv: %s packet from host %s port %d",
			       packet_codes[packet->code],
			       inet_ntop(packet->src_ipaddr.af,
					 &packet->src_ipaddr.ipaddr,
					 host_ipaddr, sizeof(host_ipaddr)),
			       packet->src_port);
		} else {
			printf("rad_recv: Packet from host %s port %d code=%d",
			       inet_ntop(packet->src_ipaddr.af,
					 &packet->src_ipaddr.ipaddr,
					 host_ipaddr, sizeof(host_ipaddr)),
			       packet->src_port,
			       packet->code);
		}
		printf(", id=%d, length=%d\n", packet->id, packet->data_len);
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
					librad_log("ERROR: Cannot validate Message-Authenticator in response packet without a request packet.");
					return -1;
				}
				memcpy(packet->data + 4, original->vector, AUTH_VECTOR_LEN);
				break;
			}

			lrad_hmac_md5(packet->data, packet->data_len,
				      secret, strlen(secret), calc_auth_vector);
			if (memcmp(calc_auth_vector, msg_auth_vector,
				   sizeof(calc_auth_vector)) != 0) {
				char buffer[32];
				librad_log("Received packet from %s with invalid Message-Authenticator!  (Shared secret is incorrect.)",
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
	if ((packet->code == 0) || packet->code >= MAX_PACKET_CODE) {
		char buffer[32];
		librad_log("Received Unknown packet code %d"
			   "from client %s port %d: Cannot validate signature",
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
		case PW_DISCONNECT_REQUEST:
			/*
			 *	The authentication vector is random
			 *	nonsense, invented by the client.
			 */
			break;

		case PW_ACCOUNTING_REQUEST:
			if (calc_acctdigest(packet, secret) > 1) {
				librad_log("Received Accounting-Request packet "
					   "from %s with invalid signature!  (Shared secret is incorrect.)",
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     buffer, sizeof(buffer)));
				return -1;
			}
			break;

			/* Verify the reply digest */
		case PW_AUTHENTICATION_ACK:
		case PW_AUTHENTICATION_REJECT:
		case PW_ACCOUNTING_RESPONSE:
			rcode = calc_replydigest(packet, original, secret);
			if (rcode > 1) {
				librad_log("Received %s packet "
					   "from client %s port %d with invalid signature (err=%d)!  (Shared secret is incorrect.)",
					   packet_codes[packet->code],
					   inet_ntop(packet->src_ipaddr.af,
						     &packet->src_ipaddr.ipaddr,
						     buffer, sizeof(buffer)),
					   packet->src_port,
					   rcode);
				return -1;
			}
			break;

		default:
			librad_log("Received Unknown packet code %d"
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


/*
 *	Hack for IETF RADEXT.  Don't use in a production environment.
 *
 *	Note that due to architecture limitations, we can't handle
 *	AVP's with more than 253 bytes of data, but that should be
 *	enough for initial inter-operability.
 */
static int diameter2vp(const RADIUS_PACKET *packet,
		       const RADIUS_PACKET *original, const char *secret,
		       const uint8_t *data, int total_length,
		       VALUE_PAIR **pvp)
{
	int lookup, offset, radius_length, attr_length, diameter_length, raw;
	uint32_t attr, length, vendor;
	DICT_ATTR *da;
	VALUE_PAIR *head, **tail, *vp;
	uint8_t *header;	/* diameter header */
	uint8_t	diameter[4096];

	diameter_length = radius_length = 0;
	header = diameter;

	*pvp = NULL;

	/*
	 *	Unpack all contiguous Extended-Attributes into a local
	 *	buffer.  It's slow, but it's safe.
	 */
	while (total_length > 0) {
		if (data[0] != PW_EXTENDED_ATTRIBUTE) break;

		attr_length = data[1];
		radius_length += attr_length;
		total_length -= attr_length;
		attr_length -= 2;

		memcpy(header, data + 2, attr_length);
		header += attr_length;
		diameter_length += attr_length;

		data += attr_length + 2;
	}

	head = NULL;
	tail = NULL;
	header = diameter;

next_diameter:
	raw = 0;

	if ((vp = paircreate(PW_EXTENDED_ATTRIBUTE, PW_TYPE_OCTETS)) == NULL) {
		pairfree(&head);
		return radius_length;
	}

	/*
	 *	Don't add it to the tail until we know it's OK.
	 */

	/*
	 *	Too little data to contain a diameter header.
	 */
	if (diameter_length < 12) {
	done:
		vp->type = PW_TYPE_OCTETS;
		memcpy(vp->vp_octets, header, diameter_length);
		vp->length = diameter_length;
		
		/*
		 *	Ensure there's no encryption or tag stuff,
		 *	we just pass the attribute as-is.
		 */
		memset(&vp->flags, 0, sizeof(vp->flags));


		if (!head) {	/* add vp to the list */
			*pvp = vp;
		} else {
			*pvp = head;
			*tail = vp;
		}

		return radius_length;
	}

	/*
	 *	Sanity check the lengths, next.  If the length is too
	 *	short, then the rest of the diameter buffer can't be
	 *	parsed.
	 */
	length = (header[5] << 16) | (header[6] << 8) | header[7];

	/*
	 *	lies about the length (too short)
	 *	or lies about the length (too long)
	 *	or VSA
	 *		with too little diameter data
	 *		or with too little content
	 */
	if ((length < 9) ||
	    (length > diameter_length) ||
	    (((header[4] & 0x80) != 0) &&
	     ((diameter_length < 16) || (length < 13)))) {
		/*
		 *	The rest of the data is small enough to fit
		 *	into one VP.  Copy it over, and return it.
		 */
		if (diameter_length <= 253) goto done;

		/*
		 *	FIXME: make multiple VP's of the rest of the
		 *	data, so that we don't lose anything!
		 */
		pairfree(&vp);

		*pvp = head;
		return radius_length;
	}

	memcpy(&attr, header, 4);
	attr = ntohl(attr);
	if (attr > 65535) raw = 1; /* implementation limitations */

	/*
	 *	1..255 are RADIUS, and shouldn't be encapsulated this way.
	 *	256.. are Diameter.
	 *
	 *	We've arbitrarily assigned 32768..65535 from the
	 *	Diameter space to "extended RADIUS" attributes.
	 */
	if (attr < 32768) raw = 1;

	/*
	 *	We don't like any non-vendor flag bits being set.
	 */
	if ((header[4] & 0x7f) != 0) raw = 1;

	vendor = 0;
	if ((header[4] & 0x80) != 0) {
		memcpy(&vendor, header + 8 , 4);
		vendor = ntohl(vendor);
		if (vendor > 32767) raw = 1; /* implementation limitations */

		offset = 12;
	} else {
		offset = 8;
	}
	length -= offset;
	header += offset;
	diameter_length -= offset;

	/*
	 *	FIXME: This is an implementation limitation.  We
	 *	should really allow strings longer than 253 bytes...
	 *
	 *	And bailing out completely (i.e. throwing away the rest
	 *	of the data) isn't an intelligent thing to do, either.
	 */
	if (length > 253) {
		*pvp = head;
		pairfree(&vp);
		return radius_length;
	}

	lookup = attr;
	lookup |= (vendor << 16);
	lookup |= (1 << 31);	/* see dict_addattr */

	da = dict_attrbyvalue(lookup);
	if (!da) raw = 1;

	if (!raw) {
		/*
		 *	Copied from paircreate.
		 */
		strcpy(vp->name, da->name);
		vp->type = da->type;
		vp->flags = da->flags;
		vp->attribute = da->attr;
	} else {
		vp->type = PW_TYPE_OCTETS;
	}

	switch (vp->type) {
	case PW_TYPE_STRING:
	case PW_TYPE_OCTETS:
	case PW_TYPE_ABINARY:
		memcpy(vp->vp_octets, header, length);
		vp->length = length;
		break;

	case PW_TYPE_INTEGER:
		if (length != 4) goto force_octets;

		memcpy(&vp->lvalue, header, 4);
		vp->lvalue = ntohl(vp->lvalue);
		vp->length = 4;

		/*
		 *	Try to get named VALUEs
		 */
		{
			DICT_VALUE *dval;
			dval = dict_valbyattr(vp->attribute,
					      vp->lvalue);
			if (dval) {
				strNcpy(vp->vp_strvalue,
					dval->name,
					sizeof(vp->vp_strvalue));
			}
		}
		break;

	case PW_TYPE_DATE:
		if (length != 4) goto force_octets;

		memcpy(&vp->lvalue, header, 4);
		vp->lvalue = ntohl(vp->lvalue);
		vp->length = 4;
		break;


	case PW_TYPE_IPADDR:
		if (length != 4) goto force_octets;

		memcpy(&vp->lvalue, header, 4);
		vp->length = 4;
		break;

		/*
		 *	IPv6 interface ID is 8 octets long.
		 */
	case PW_TYPE_IFID:
		if (length != 8) goto force_octets;
		memcpy(vp->vp_ifid, header, 8);
		vp->length = 8;
		break;
		
		/*
		 *	IPv6 addresses are 16 octets long
		 */
	case PW_TYPE_IPV6ADDR:
		if (length != 16) goto force_octets;
		memcpy(&vp->vp_ipv6addr, header, 16);
		vp->length = 16;
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
		if (length < 2 || length > 18) goto force_octets;
		if (header[1] > 128) goto force_octets;

		memcpy(vp->vp_ipv6prefix, header, length);
		vp->length = length;
		

		/*
		 *	FIXME: double-check that
		 *	(vp->vp_octets[1] >> 3) matches vp->length + 2
		 */
		if (vp->length < 18) {
			memset(vp->vp_octets + vp->length, 0,
			       18 - vp->length);
		}
		break;

	default:
	force_octets:
		vp->type = PW_TYPE_OCTETS;
		
		/*
		 *	Ensure there's no encryption or tag stuff,
		 *	we just pass the attribute as-is.
		 */
		memset(&vp->flags, 0, sizeof(vp->flags));
		break;
	}

	if (!head) {
		head = vp;
	} else {
		*tail = vp;
	}
	tail = &vp->next;

	header += length;
	diameter_length -= length;

	/*
	 *	The checks for length above ensure that we always have
	 *	diameter_length large enough to hold length + padding.
	 */
	if ((length & 0x03) != 0) {
		attr_length = 4 - (length & 0x03); /* padding */
		header += attr_length;
		diameter_length -= attr_length;
	}
	if (diameter_length > 0) goto next_diameter;

	*pvp = head;
	return radius_length;
}



/*
 *	Parse a RADIUS attribute into a data structure.
 */
VALUE_PAIR *rad_attr2vp(const RADIUS_PACKET *packet, const RADIUS_PACKET *original,
			const char *secret, int attribute, int length,
			const uint8_t *data)
{
	int offset = 0;
	VALUE_PAIR *vp;

	if ((vp = paircreate(attribute, PW_TYPE_OCTETS)) == NULL) {
		return NULL;
	}
	
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

	case PW_TYPE_INTEGER:
		if (vp->length != 4) goto raw;

		memcpy(&vp->lvalue, vp->vp_octets, 4);
		vp->lvalue = ntohl(vp->lvalue);

		if (vp->flags.has_tag) vp->lvalue &= 0x00ffffff;

		/*
		 *	Try to get named VALUEs
		 */
		{
			DICT_VALUE *dval;
			dval = dict_valbyattr(vp->attribute,
					      vp->lvalue);
			if (dval) {
				strNcpy(vp->vp_strvalue,
					dval->name,
					sizeof(vp->vp_strvalue));
			}
		}
		break;

	case PW_TYPE_DATE:
		if (vp->length != 4) goto raw;

		memcpy(&vp->lvalue, vp->vp_octets, 4);
		vp->lvalue = ntohl(vp->lvalue);
		break;


	case PW_TYPE_IPADDR:
		if (vp->length != 4) goto raw;

		memcpy(&vp->lvalue, vp->vp_octets, 4);
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
	uint8_t			*ptr;
	int			packet_length;
	int			attribute;
	int			attrlen;
	int			vendorlen;
	radius_packet_t		*hdr;
	int			vsa_tlen, vsa_llen;
	DICT_VENDOR		*dv = NULL;

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

			/*
			 *	192 is "integer" for Ascend.  So if we
			 *	get 12 or more bytes, it must be the
			 *	new extended format.
			 */
			if ((ptr[0] == PW_EXTENDED_ATTRIBUTE) &&
			    (ptr[1] >= 2 + 12)) {
				pair = NULL;
				attrlen = diameter2vp(packet, original, secret,
						      ptr, packet_length, &pair);
				goto check_pair;
			}

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
			dv = dict_vendorbyvalue(myvendor);
			if (dv) {
				vsa_tlen = dv->type;
				vsa_llen = dv->length;
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
				 *	Don't have a type, it's bad.
				 */
				if (sublen < vsa_tlen) goto create_pair;
				
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
				
				/*
				 *	Not enough room for one more
				 *	attribute.  Die!
				 */
				if (sublen < vsa_tlen + vsa_llen) goto create_pair;
				switch (vsa_llen) {
				case 0:
					attribute = (myvendor << 16) | myattr;
					ptr += 4 + vsa_tlen;
					attrlen -= (4 + vsa_tlen);
					packet_length -= 4 + vsa_tlen;
					goto create_pair;

				case 1:
					if (subptr[vsa_tlen] < (vsa_tlen + vsa_llen))
						goto create_pair;

					if (subptr[vsa_tlen] > sublen)
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
		attribute |= (vendorcode << 16);
		ptr += vsa_tlen;

		switch (vsa_llen) {
		case 1:
			attrlen = ptr[0] - (vsa_tlen + vsa_llen);
			break;
			
		case 2:
			attrlen = ptr[1] - (vsa_tlen + vsa_llen);
			break;

		default:	/* can't hit this. */
			return -1;
		}
		ptr += vsa_llen;
		vendorlen -= vsa_tlen + vsa_llen + attrlen;
		if (vendorlen == 0) vendorcode = 0;
		packet_length -= (vsa_tlen + vsa_llen);

		/*
		 *	Create the attribute, setting the default type
		 *	to 'octets'.  If the type in the dictionary
		 *	is different, then the dictionary type will
		 *	over-ride this one.
		 */
	create_pair:
		pair = rad_attr2vp(packet, original, secret,
				   attribute, attrlen, ptr);
	check_pair:
		if (!pair) {
			pairfree(&packet->vps);
			librad_log("out of memory");
			return -1;
		}

		*tail = pair;
		while (pair) {
			debug_pair(pair);
			tail = &pair->next;
			pair = pair->next;
		}

		ptr += attrlen;
		packet_length -= attrlen;
	}

	/*
	 *	Merge information from the outside world into our
	 *	random pool.
	 */
	lrad_rand_seed(packet->data, AUTH_HDR_LEN);
	  
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
int rad_pwencode(char *passwd, int *pwlen, const char *secret,
		 const uint8_t *vector)
{
	lrad_MD5_CTX context, old;
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
	
	lrad_MD5Init(&context);
	lrad_MD5Update(&context, secret, secretlen);
	old = context;		/* save intermediate work */

	/*
	 *	Encrypt it in place.  Don't bother checking
	 *	len, as we've ensured above that it's OK.
	 */
	for (n = 0; n < len; n += AUTH_PASS_LEN) {
		if (n == 0) {
			lrad_MD5Update(&context, vector, AUTH_PASS_LEN);
			lrad_MD5Final(digest, &context);
		} else {
			context = old;
			lrad_MD5Update(&context,
					 passwd + n - AUTH_PASS_LEN,
					 AUTH_PASS_LEN);
			lrad_MD5Final(digest, &context);
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
int rad_pwdecode(char *passwd, int pwlen, const char *secret,
		 const uint8_t *vector)
{
	lrad_MD5_CTX context, old;
	uint8_t	digest[AUTH_VECTOR_LEN];
	int	i, n, secretlen;

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
	
	lrad_MD5Init(&context);
	lrad_MD5Update(&context, secret, secretlen);
	old = context;		/* save intermediate work */

	/*
	 *	The inverse of the code above.
	 */
	for (n = 0; n < pwlen; n += AUTH_PASS_LEN) {
		if (n == 0) {
			lrad_MD5Update(&context, vector, AUTH_VECTOR_LEN);
			lrad_MD5Final(digest, &context);

			context = old;
			lrad_MD5Update(&context, passwd, AUTH_PASS_LEN);
		} else {
			lrad_MD5Final(digest, &context);

			context = old;
			lrad_MD5Update(&context, passwd + n, AUTH_PASS_LEN);
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
int rad_tunnel_pwencode(char *passwd, int *pwlen, const char *secret,
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
		   (lrad_rand() & 0x07));
	salt[1] = lrad_rand();

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
			librad_md5_calc(digest, buffer, secretlen + AUTH_VECTOR_LEN + 2);
		} else {
			memcpy(buffer + secretlen, passwd + n2 - AUTH_PASS_LEN, AUTH_PASS_LEN);
			librad_md5_calc(digest, buffer, secretlen + AUTH_PASS_LEN);
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
int rad_tunnel_pwdecode(uint8_t *passwd, int *pwlen, const char *secret,
			const uint8_t *vector)
{
	lrad_MD5_CTX  context, old;
	uint8_t		digest[AUTH_VECTOR_LEN];
	int		secretlen;
	unsigned	i, n, len, reallen;

	len = *pwlen;

	/*
	 *	We need at least a salt.
	 */
	if (len < 2) {
		librad_log("tunnel password is too short");
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

	lrad_MD5Init(&context);
	lrad_MD5Update(&context, secret, secretlen);
	old = context;		/* save intermediate work */

	/*
	 *	Set up the initial key:
	 *
	 *	 b(1) = MD5(secret + vector + salt)
	 */
	lrad_MD5Update(&context, vector, AUTH_VECTOR_LEN);
	lrad_MD5Update(&context, passwd, 2);

	reallen = 0;
	for (n = 0; n < len; n += AUTH_PASS_LEN) {
		int base = 0;

		if (n == 0) {
			lrad_MD5Final(digest, &context);

			context = old;

			/*
			 *	A quick check: decrypt the first octet
			 *	of the password, which is the
			 *	'data_len' field.  Ensure it's sane.
			 */
			reallen = passwd[2] ^ digest[0];
			if (reallen >= len) {
				librad_log("tunnel password is too long for the attribute");
				return -1;
			}

			lrad_MD5Update(&context, passwd + 2, AUTH_PASS_LEN);

			base = 1;
		} else {
			lrad_MD5Final(digest, &context);

			context = old;
			lrad_MD5Update(&context, passwd + n + 2, AUTH_PASS_LEN);
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
	char		*ptr;
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
	challenge = pairfind(packet->vps, PW_CHAP_CHALLENGE);
	if (challenge) {
		memcpy(ptr, challenge->vp_strvalue, challenge->length);
		i += challenge->length;
	} else {
		memcpy(ptr, packet->vector, AUTH_VECTOR_LEN);
		i += AUTH_VECTOR_LEN;
	}

	*output = id;
	librad_md5_calc((uint8_t *)output + 1, (uint8_t *)string, i);

	return 0;
}


/*
 *	Seed the random number generator.
 *
 *	May be called any number of times.
 */
void lrad_rand_seed(const void *data, size_t size)
{
	uint32_t hash;

	/*
	 *	Ensure that the pool is initialized.
	 */
	if (!lrad_rand_initialized) {
		int fd;
		
		memset(&lrad_rand_pool, 0, sizeof(lrad_rand_pool));

		fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0) {
			size_t total;
			ssize_t this;

			total = this = 0;
			while (total < sizeof(lrad_rand_pool.randrsl)) {
				this = read(fd, lrad_rand_pool.randrsl,
					    sizeof(lrad_rand_pool.randrsl) - total);
				if ((this < 0) && (errno != EINTR)) break;
				if (this > 0) total += this;
 			}
			close(fd);
		} else {
			lrad_rand_pool.randrsl[0] = fd;
			lrad_rand_pool.randrsl[1] = time(NULL);
			lrad_rand_pool.randrsl[2] = errno;
		}

		lrad_randinit(&lrad_rand_pool, 1);
		lrad_rand_pool.randcnt = 0;
		lrad_rand_initialized = 1;
	}

	if (!data) return;

	/*
	 *	Hash the user data
	 */
	hash = lrad_rand();
	if (!hash) hash = lrad_rand();
	hash = lrad_hash_update(data, size, hash);
	
	lrad_rand_pool.randmem[lrad_rand_pool.randcnt] ^= hash;
}


/*
 *	Return a 32-bit random number.
 */
uint32_t lrad_rand(void)
{
	uint32_t num;

	/*
	 *	Ensure that the pool is initialized.
	 */
	if (!lrad_rand_initialized) {
		lrad_rand_seed(NULL, 0);
	}

	num = lrad_rand_pool.randrsl[lrad_rand_pool.randcnt++];
	if (lrad_rand_pool.randcnt == 256) {
		lrad_isaac(&lrad_rand_pool);
		lrad_rand_pool.randcnt = 0;
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
		librad_log("out of memory");
		return NULL;
	}
	memset(rp, 0, sizeof(*rp));
	rp->id = -1;
	rp->verified = -1;

	if (newvector) {
		int i;
		uint32_t hash, base;

		/*
		 *	Don't expose the actual contents of the random
		 *	pool.
		 */
		base = lrad_rand();
		for (i = 0; i < AUTH_VECTOR_LEN; i += sizeof(uint32_t)) {
			hash = lrad_rand() ^ base;
			memcpy(rp->vector + i, &hash, sizeof(hash));
		}
	}
	lrad_rand();		/* stir the pool again */

	return rp;
}

/*
 *	Free a RADIUS_PACKET
 */
void rad_free(RADIUS_PACKET **radius_packet_ptr)
{
	RADIUS_PACKET *radius_packet;

	if (!radius_packet_ptr) return;
	radius_packet = *radius_packet_ptr;

	free(radius_packet->data);
	pairfree(&radius_packet->vps);

	free(radius_packet);

	*radius_packet_ptr = NULL;
}
