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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 * Copyright 2000-2003  The FreeRADIUS server project
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"
#include	"md5.h"

#include	<stdlib.h>

#ifdef HAVE_UNISTD_H
#include	<unistd.h>
#endif

#include	<fcntl.h>
#include	<string.h>
#include	<ctype.h>

#include	"libradius.h"

#ifdef HAVE_NETINET_IN_H
#include	<netinet/in.h>
#endif

#include	<sys/socket.h>

#ifdef HAVE_ARPA_INET_H
#include	<arpa/inet.h>
#endif

#ifdef HAVE_MALLOC_H
#include	<malloc.h>
#endif

#ifdef WIN32
#include	<process.h>
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
int librad_max_attributes = 0;

typedef struct radius_packet_t {
  uint8_t	code;
  uint8_t	id;
  uint8_t	length[2];
  uint8_t	vector[AUTH_VECTOR_LEN];
  uint8_t	data[1];
} radius_packet_t;

static lrad_randctx lrad_rand_pool;	/* across multiple calls */
static int lrad_pool_initialized = 0;

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
  "CoF-Request",
  "CoF-ACK",
  "CoF-NAK",
  "46",
  "47",
  "48",
  "49",
  "IP-Address-Allocate",
  "IP-Address-Release"
};

/*
 *  Internal prototypes
 */
static void make_secret(unsigned char *digest, uint8_t *vector,
			const char *secret, char *value);

/*
 *	Reply to the request.  Also attach
 *	reply attribute value pairs and any user message provided.
 */
int rad_send(RADIUS_PACKET *packet, const RADIUS_PACKET *original,
	     const char *secret)
{
	VALUE_PAIR		*reply;
	struct	sockaddr_in	saremote;
	struct	sockaddr_in	*sa;
	const char		*what;
	uint8_t			ip_buffer[16];

	/*
	 *	Maybe it's a fake packet.  Don't send it.
	 */
	if (!packet || (packet->sockfd < 0)) {
		return 0;
	}

	if ((packet->code > 0) && (packet->code < 52)) {
		what = packet_codes[packet->code];
	} else {
		what = "Reply";
	}

	/*
	 *  First time through, allocate room for the packet
	 */
	if (!packet->data) {
		  radius_packet_t	*hdr;
		  uint32_t		lvalue;
		  uint8_t		*ptr, *length_ptr, *vsa_length_ptr;
		  uint8_t		digest[16];
		  int			secretlen;
		  int			vendorcode, vendorpec;
		  u_short		total_length;
		  int			len, allowed;
		  int			msg_auth_offset = 0;

		  /*
		   *	For simplicity in the following logic, we allow
		   *	the attributes to "overflow" the 4k maximum
		   *	RADIUS packet size, by one attribute.
		   */
		  uint8_t		data[MAX_PACKET_LEN + 256];
		  
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
			  memset(packet->vector, 0, sizeof(packet->vector));
			  break;

		  default:
			  break;
			  
		  }
		  memcpy(hdr->vector, packet->vector, sizeof(hdr->vector));

		  DEBUG("Sending %s of id %d to %s:%d\n",
			what, packet->id,
			ip_ntoa((char *)ip_buffer, packet->dst_ipaddr),
			packet->dst_port);
		  
		  total_length = AUTH_HDR_LEN;
		  
		  /*
		   *	Load up the configuration values for the user
		   */
		  ptr = hdr->data;
		  vendorcode = 0;
		  vendorpec = 0;
		  vsa_length_ptr = NULL;

		  /*
		   *	Loop over the reply attributes for the packet.
		   */
		  for (reply = packet->vps; reply; reply = reply->next) {
			  /*
			   *	Ignore non-wire attributes
			   */
			  if ((VENDOR(reply->attribute) == 0) &&
			      ((reply->attribute & 0xFFFF) > 0xff)) {
				  continue;
			  }

			  /*
			   *	Check that the packet is no more than
			   *	4k in size, AFTER over-flowing the 4k
			   *	boundary.  Note that the 'data'
			   *	buffer, above, is one attribute longer
			   *	than necessary, in order to permit
			   *	this overflow.
			   */
			  if (total_length > MAX_PACKET_LEN) {
				  librad_log("ERROR: Too many attributes for packet, result is larger than RFC maximum of 4k");
				  return -1;
			  }

			  /*
			   *	Set the Message-Authenticator to the
			   *	correct length and initial value.
			   */
			  if (reply->attribute == PW_MESSAGE_AUTHENTICATOR) {
				  reply->length = AUTH_VECTOR_LEN;
				  memset(reply->strvalue, 0, AUTH_VECTOR_LEN);
				  msg_auth_offset = total_length;
			  }

			  /*
			   *	Print out ONLY the attributes which
			   *	we're sending over the wire, and print
			   *	them out BEFORE they're encrypted.
			   */
			  debug_pair(reply);

			  /*
			   *	We have a different vendor.  Re-set
			   *	the vendor codes.
			   */
			  if (vendorcode != VENDOR(reply->attribute)) {
				  vendorcode = 0;
				  vendorpec = 0;
				  vsa_length_ptr = NULL;
			  }

			  /*
			   *	If the Vendor-Specific attribute is getting
			   *	full, then create a new VSA attribute
			   *
			   *	FIXME: Multiple VSA's per Vendor-Specific
			   *	SHOULD be configurable.  When that's done,
			   *	the (1), below, can be changed to point to
			   *	a configuration variable which is set TRUE
			   *	if the NAS cannot understand multiple VSA's
			   *	per Vendor-Specific
			   */
			  if ((1) || /* ALWAYS create a new Vendor-Specific */
			      (vsa_length_ptr &&
			       (reply->length + *vsa_length_ptr) >= MAX_STRING_LEN)) {
				  vendorcode = 0;
				  vendorpec = 0;
				  vsa_length_ptr = NULL;
			  }

			  /*
			   *	Maybe we have the start of a set of
			   *	(possibly many) VSA attributes from
			   *	one vendor.  Set a global VSA wrapper
			   */
			  if ((vendorcode == 0) &&
			      ((vendorcode = VENDOR(reply->attribute)) != 0)) {
				  vendorpec  = dict_vendorpec(vendorcode);
				  
				  /*
				   *	This is a potentially bad error...
				   *	we can't find the vendor ID!
				   */
				  if (vendorpec == 0) {
					  /* FIXME: log an error */
					  continue;
				  }

				  /*
				   *	Build a VSA header.
				   */
				  *ptr++ = PW_VENDOR_SPECIFIC;
				  vsa_length_ptr = ptr;
				  *ptr++ = 6;
				  lvalue = htonl(vendorpec);
				  memcpy(ptr, &lvalue, 4);
				  ptr += 4;
				  total_length += 6;
			  }

			  if (vendorpec == VENDORPEC_USR) {
				  lvalue = htonl(reply->attribute & 0xFFFF);
				  memcpy(ptr, &lvalue, 4);

				  length_ptr = vsa_length_ptr;

				  total_length += 4;
				  *length_ptr  += 4;
				  ptr          += 4;

				  /*
				   *	Each USR-style attribute gets
				   *	it's own VSA wrapper, so we
				   *	re-set the vendor specific
				   *	information.
				   */
				  vendorcode = 0;
				  vendorpec = 0;
				  vsa_length_ptr = NULL;

			  } else {
				  /*
				   *	All other attributes are as
				   *	per the RFC spec.
				   */
				  *ptr++ = (reply->attribute & 0xFF);
				  length_ptr = ptr;
				  if (vsa_length_ptr) *vsa_length_ptr += 2;
				  *ptr++ = 2;
				  total_length += 2;
			  }
			  
			  switch(reply->type) {
				  
				  /*
				   *	Ascend binary attributes are
				   *	stored internally in binary form.
				   */
			  case PW_TYPE_IFID:
			  case PW_TYPE_IPV6ADDR:
			  case PW_TYPE_IPV6PREFIX:
			  case PW_TYPE_ABINARY:
			  case PW_TYPE_STRING:
			  case PW_TYPE_OCTETS:
				  /*
				   *  Encrypt the various password styles
				   */
				  switch (reply->flags.encrypt) {
				  default:
					  break;

				  case FLAG_ENCRYPT_USER_PASSWORD:
				    rad_pwencode((char *)reply->strvalue,
						 &(reply->length),
						 (const char *)secret,
						 (const char *)packet->vector);
				    break;

				  case FLAG_ENCRYPT_TUNNEL_PASSWORD:
					  if (!original) {
						  librad_log("ERROR: No request packet, cannot encrypt Tunnel-Password attribute in the reply.");
						  return -1;
					  }
					  rad_tunnel_pwencode(reply->strvalue,
							      &(reply->length),
							      secret,
							      original->vector);
					  break;


				  case FLAG_ENCRYPT_ASCEND_SECRET:
					  make_secret(digest, packet->vector,
						      secret, reply->strvalue);
					  memcpy(reply->strvalue, digest, AUTH_VECTOR_LEN );
					  reply->length = AUTH_VECTOR_LEN;
					  break;
				  } /* switch over encryption flags */

				  len = reply->length;

				  /*
				   *    Set the TAG at the beginning
				   *    of the string if tagged.  If
				   *    tag value is not valid for
				   *    tagged attribute, make it 0x00
				   *    per RFC 2868.  -cparker
				   */
				  if (reply->flags.has_tag) {
					  if (TAG_VALID(reply->flags.tag)) {
						  len++;
						  *ptr++ = reply->flags.tag;

					  } else if (reply->flags.encrypt == FLAG_ENCRYPT_TUNNEL_PASSWORD) {
						  /*
						   *  Tunnel passwords
						   *  REQUIRE a tag,
						   *  even if we don't
						   *  have a valid
						   *  tag.
						   */
						  len++;
						  *ptr++ = 0x00;
					  } /* else don't write a tag */
				  } /* else the attribute doesn't have a tag */
				 
				  /*
				   *	Ensure we don't go too far.
				   *	The 'length' of the attribute
				   *	may be 0..255, minus whatever
				   *	octets are used in the attribute
				   *	header.
				   */
				  allowed = 255;
				  if (vsa_length_ptr) {
					  allowed -= *vsa_length_ptr;
				  } else {
					  allowed -= *length_ptr;
				  }
				  
				  if (len > allowed) {
					  len = allowed;
				  }
				  
				  *length_ptr += len;
				  if (vsa_length_ptr) *vsa_length_ptr += len;
				  /*
				   *  If we have tagged attributes we can't assume that
				   *  len == reply->length.  Use reply->length for copying
				   *  the string data into the packet.  Use len for the
				   *  true length of the string+tags.
				   */
				  memcpy(ptr, reply->strvalue, reply->length);
				  ptr += reply->length;
				  total_length += len;
				  break;
				  
			  case PW_TYPE_INTEGER:
			  case PW_TYPE_IPADDR:
				  *length_ptr += 4;
				  if (vsa_length_ptr) *vsa_length_ptr += 4;

				  if (reply->type == PW_TYPE_INTEGER ) {
				          /*  If tagged, the tag becomes the MSB of the value */
				          if(reply->flags.has_tag) {
					         /*  Tag must be ( 0x01 -> 0x1F ) OR 0x00  */
					         if(!TAG_VALID(reply->flags.tag)) {
						       reply->flags.tag = 0x00;
						 }
					         lvalue = htonl((reply->lvalue & 0xffffff) |
								((reply->flags.tag & 0xff) << 24));
					  } else {
					         lvalue = htonl(reply->lvalue);
					  }
				  } else {
					  /*
					   *  IP address is already in
					   *  network byte order.
					   */
					  lvalue = reply->lvalue;
				  }
				  memcpy(ptr, &lvalue, 4);
				  ptr += 4;
				  total_length += 4;
				  break;

				  /*
				   *  There are no tagged date attributes.
				   */
			  case PW_TYPE_DATE:
				  *length_ptr += 4;
				  if (vsa_length_ptr) *vsa_length_ptr += 4;

				  lvalue = htonl(reply->lvalue);
				  memcpy(ptr, &lvalue, 4);
				  ptr += 4;
				  total_length += 4;
				  break;
			  default:
				  break;
			  }
		  } /* done looping over all attributes */

		  /*
		   *	Fill in the rest of the fields, and copy
		   *	the data over from the local stack to
		   *	the newly allocated memory.
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
		  memcpy(hdr->length, &total_length, sizeof(u_short));

		  /*
		   *	If this is not an authentication request, we
		   *	need to calculate the md5 hash over the entire packet
		   *	and put it in the vector.
		   */
		  secretlen = strlen(secret);

		  /*
		   *	If there's a Message-Authenticator, update it
		   *	now, BEFORE updating the authentication vector.
		   */
		  if (msg_auth_offset) {
			  uint8_t calc_auth_vector[AUTH_VECTOR_LEN];
			  
			  switch (packet->code) {
			  default:
				  break;
				  
			  case PW_AUTHENTICATION_ACK:
			  case PW_AUTHENTICATION_REJECT:
			  case PW_ACCESS_CHALLENGE:
				  /* this was checked above */
				  memcpy(hdr->vector, original->vector,
					 AUTH_VECTOR_LEN);
				  break;
			  }
			  
			  /*
			   *	Set the authentication vector to zero,
			   *	calculate the signature, and put it
			   *	into the Message-Authenticator
			   *	attribute.
			   */
			  memset(packet->data + msg_auth_offset + 2,
				 0, AUTH_VECTOR_LEN);
			  lrad_hmac_md5(packet->data, packet->data_len,
					secret, secretlen, calc_auth_vector);
			  memcpy(packet->data + msg_auth_offset + 2,
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
				MD5_CTX	context;
				MD5Init(&context);
				MD5Update(&context, packet->data, packet->data_len);
				MD5Update(&context, secret, strlen(secret));
				MD5Final(digest, &context);
				
				memcpy(hdr->vector, digest, AUTH_VECTOR_LEN);
				memcpy(packet->vector, digest, AUTH_VECTOR_LEN);
				break;
			}
		  } /* switch over packet codes */


		  /*
		   *	If packet->data points to data, then we print out
		   *	the VP list again only for debugging.
		   */
	} else if (librad_debug) {
	  	DEBUG("Re-sending %s of id %d to %s:%d\n", what, packet->id,
		      ip_ntoa((char *)ip_buffer, packet->dst_ipaddr),
		      packet->dst_port);
		
		for (reply = packet->vps; reply; reply = reply->next) {
			/* FIXME: ignore attributes > 0xff */
			debug_pair(reply);
		}
	}
	
	/*
	 *	And send it on it's way.
	 */
	sa = (struct sockaddr_in *) &saremote;
        memset ((char *) sa, '\0', sizeof (saremote));
	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = packet->dst_ipaddr;
	sa->sin_port = htons(packet->dst_port);

	return sendto(packet->sockfd, packet->data, (int)packet->data_len, 0,
		      (struct sockaddr *)&saremote, sizeof(struct sockaddr_in));
}


/*
 *	Validates the requesting client NAS.  Calculates the
 *	signature based on the clients private key.
 */
static int calc_acctdigest(RADIUS_PACKET *packet, const char *secret)
{
	u_char		digest[AUTH_VECTOR_LEN];
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
 *	Receive UDP client requests, and fill in
 *	the basics of a RADIUS_PACKET structure.
 */
RADIUS_PACKET *rad_recv(int fd)
{
	RADIUS_PACKET		*packet;
	struct sockaddr_in	saremote;
	int			totallen;
	socklen_t		salen;
	u_short			len;
	uint8_t			*attr;
	int			count;
	radius_packet_t		*hdr;
	char			host_ipaddr[16];
	int			seen_eap;
	uint8_t			data[MAX_PACKET_LEN];
	int			num_attributes;
	
	/*
	 *	Allocate the new request data structure
	 */
	if ((packet = malloc(sizeof(RADIUS_PACKET))) == NULL) {
		librad_log("out of memory");
		return NULL;
	}
	memset(packet, 0, sizeof(RADIUS_PACKET));

	/*
	 *	Receive the packet.
	 */
	salen = sizeof(saremote);
	memset(&saremote, 0, sizeof(saremote));
	packet->data_len = recvfrom(fd, data, sizeof(data),
		0, (struct sockaddr *)&saremote, &salen);

	/*
	 *	Check for socket errors.
	 */
	if (packet->data_len < 0) {
		librad_log("Error receiving packet: %s", strerror(errno));
		free(packet);
		return NULL;
	}

	/*
	 *	Fill IP header fields.  We need these for the error
	 *	messages which may come later.
	 */
	packet->sockfd = fd;
	packet->src_ipaddr = saremote.sin_addr.s_addr;
	packet->src_port = ntohs(saremote.sin_port);

	/*
	 *	FIXME: Do even more filtering by only permitting
	 *	certain IP's.  The problem is that we don't know
	 *	how to do this properly for all possible clients...
	 */

	/*
	 *	Explicitely set the VP list to empty.
	 */
	packet->vps = NULL;

	/*
	 *	Check for packets smaller than the packet header.
	 *
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	"The minimum length is 20 ..."
	 */
	if (packet->data_len < AUTH_HDR_LEN) {
		librad_log("WARNING: Malformed RADIUS packet from host %s: too short (received %d < minimum %d)",
			   ip_ntoa(host_ipaddr, packet->src_ipaddr),
			   packet->data_len, AUTH_HDR_LEN);
		free(packet);
		return NULL;
	}

	/*
	 *	RFC 2865, Section 3., subsection 'length' says:
	 *
	 *	" ... and maximum length is 4096."
	 */
	if (packet->data_len > MAX_PACKET_LEN) {
		librad_log("WARNING: Malformed RADIUS packet from host %s: too long (received %d > maximum %d)",
			   ip_ntoa(host_ipaddr, packet->src_ipaddr),
			   packet->data_len, MAX_PACKET_LEN);
		free(packet);
		return NULL;
	}

	/*
	 *	Check for packets with mismatched size.
	 *	i.e. We've received 128 bytes, and the packet header
	 *	says it's 256 bytes long.
	 */
	hdr = (radius_packet_t *)data;
	memcpy(&len, hdr->length, sizeof(u_short));
	totallen = ntohs(len);

	/*
	 *	Code of 0 is not understood.
	 *	Code of 16 or greate is not understood.
	 */
	if ((hdr->code == 0) ||
	    (hdr->code >= 52)) {
		librad_log("WARNING: Bad RADIUS packet from host %s: unknown packet code %d",
			   ip_ntoa(host_ipaddr, packet->src_ipaddr),
			   hdr->code);
		free(packet);
		return NULL;
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
			   ip_ntoa(host_ipaddr, packet->src_ipaddr),
			   totallen, AUTH_HDR_LEN);
		free(packet);
		return NULL;
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
			   ip_ntoa(host_ipaddr, packet->src_ipaddr),
			   totallen, MAX_PACKET_LEN);
		free(packet);
		return NULL;
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
			   ip_ntoa(host_ipaddr, packet->src_ipaddr),
			   packet->data_len, totallen);
		free(packet);
		return NULL;
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
		memset(data + totallen, 0, packet->data_len - totallen);
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
				   ip_ntoa(host_ipaddr, packet->src_ipaddr));
			free(packet);
			return NULL;
		}
		
		/*
		 *	Attributes are at LEAST as long as the ID & length
		 *	fields.  Anything shorter is an invalid attribute.
		 */
       		if (attr[1] < 2) {
			librad_log("WARNING: Malformed RADIUS packet from host %s: attribute %d too short",
				   ip_ntoa(host_ipaddr, packet->src_ipaddr),
				   attr[0]);
			free(packet);
			return NULL;
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
					   ip_ntoa(host_ipaddr, packet->src_ipaddr),
					   attr[1] - 2);
				free(packet);
				return NULL;
			}
			seen_eap |= PW_MESSAGE_AUTHENTICATOR;
			break;
			
		case PW_VENDOR_SPECIFIC:
			if (attr[1] <= 6) {
				librad_log("WARNING: Malformed RADIUS packet from host %s: Vendor-Specific has invalid length %d",
					   ip_ntoa(host_ipaddr, packet->src_ipaddr),
					   attr[1] - 2);
				free(packet);
				return NULL;
			}

			/*
			 *	Don't allow VSA's with vendor zero.
			 */
			if ((attr[2] == 0) && (attr[3] == 0) &&
			    (attr[4] == 0) && (attr[5] == 0)) {
				librad_log("WARNING: Malformed RADIUS packet from host %s: Vendor-Specific has vendor ID of zero",
					   ip_ntoa(host_ipaddr, packet->src_ipaddr));
				free(packet);
				return NULL;
			}

			/*
			 *	Don't look at the contents of VSA's,
			 *	too many vendors have non-standard
			 *	formats.
			 */
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
			   ip_ntoa(host_ipaddr, packet->src_ipaddr));
		free(packet);
		return NULL;
	}

	/*
	 *	If we're configured to look for a maximum number of
	 *	attributes, and we've seen more than that maximum,
	 *	then throw the packet away, as a possible DoS.
	 */
	if ((librad_max_attributes > 0) &&
	    (num_attributes > librad_max_attributes)) {
		librad_log("WARNING: Possible DoS attack from host %s: Too many attributes in request (received %d, max %d are allowed).",
			   ip_ntoa(host_ipaddr, packet->src_ipaddr),
			   num_attributes, librad_max_attributes);
		free(packet);
		return NULL;
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
			   ip_ntoa(host_ipaddr, packet->src_ipaddr));
		free(packet);
		return NULL;
	}

	if (librad_debug) {
		if ((hdr->code > 0) && (hdr->code < 52)) {
			printf("rad_recv: %s packet from host %s:%d",
			       packet_codes[hdr->code],
			       ip_ntoa(host_ipaddr, packet->src_ipaddr), packet->src_port);
		} else {
			printf("rad_recv: Packet from host %s:%d code=%d",	
			       ip_ntoa(host_ipaddr, packet->src_ipaddr), packet->src_port,
			       hdr->code);
		}
		printf(", id=%d, length=%d\n", hdr->id, totallen);
	}

	/*
	 *	Fill RADIUS header fields
	 */
	packet->code = hdr->code;
	packet->id = hdr->id;
	memcpy(packet->vector, hdr->vector, AUTH_VECTOR_LEN);

	/*
	 *  Now that we've sanity checked the packet, we can allocate
	 *  memory for it, and copy the data from the local area to
	 *  the packet buffer.
	 */
	if ((packet->data = malloc(packet->data_len)) == NULL) {
	  free(packet);
	  librad_log("out of memory");
	  return NULL;
	}
	memcpy(packet->data, data, packet->data_len);

	return packet;
}

/*
 *	Calculate/check digest, and decode radius attributes.
 */
int rad_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original,
	       const char *secret)
{
	uint32_t		lvalue;
	uint32_t		vendorcode;
	VALUE_PAIR		**tail;
	VALUE_PAIR		*pair;
	uint8_t			*ptr;
	int			length;
	int			attribute;
	int			attrlen;
	int			vendorlen;
	radius_packet_t		*hdr;

	hdr = (radius_packet_t *)packet->data;

	/*
	 *	Before we allocate memory for the attributes, do more
	 *	sanity checking.
	 */
	ptr = hdr->data;
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
					   ip_ntoa(buffer, packet->src_ipaddr));
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
	 *	Calculate and/or verify digest.
	 */
	switch(packet->code) {
		int rcode;

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
				char buffer[32];
				librad_log("Received Accounting-Request packet "
				    "from %s with invalid signature!  (Shared secret is incorrect.)",
				    ip_ntoa(buffer, packet->src_ipaddr));
				return -1;
			}
			break;

			/* Verify the reply digest */
		case PW_AUTHENTICATION_ACK:
		case PW_AUTHENTICATION_REJECT:
		case PW_ACCOUNTING_RESPONSE:
			rcode = calc_replydigest(packet, original, secret);
			if (rcode > 1) {
				char buffer[32];
				librad_log("Received %s packet "
					   "from %s with invalid signature (err=%d)!  (Shared secret is incorrect.)",
					   packet_codes[packet->code],
					   ip_ntoa(buffer, packet->src_ipaddr),
					   rcode);
				return -1;
			}
		  break;
	}

	/*
	 *	Extract attribute-value pairs
	 */
	ptr = hdr->data;
	length = packet->data_len - AUTH_HDR_LEN;
	packet->vps = NULL;
	tail = &packet->vps;

	vendorcode = 0;
	vendorlen  = 0;

	while (length > 0) {
		if (vendorlen > 0) {
			attribute = *ptr++ | (vendorcode << 16);
			attrlen   = *ptr++;
		} else {
			attribute = *ptr++;
			attrlen   = *ptr++;
		}

		attrlen -= 2;
		length  -= 2;

		/*
		 *	This could be a Vendor-Specific attribute.
		 */
		if ((vendorlen <= 0) &&
		    (attribute == PW_VENDOR_SPECIFIC)) {
			int	sublen;
			uint8_t	*subptr;

			/*
			 *	attrlen was checked to be >= 6, in rad_recv
			 */

			memcpy(&lvalue, ptr, 4);
			vendorcode = ntohl(lvalue);

			/*
			 *	This is an implementation issue.
			 *	We currently pack vendor into the upper
			 *	16 bits of a 32-bit attribute number,
			 *	so we can't handle vendor numbers larger
			 *	than 16 bits.
			 */
			if (vendorcode > 65535) goto create_pair;

			/*
			 *	vendorcode was checked to be non-zero
			 *	above, in rad_recv.
			 */

			/*
			 *	First, check to see if the
			 *	sub-attributes fill the VSA, as
			 *	defined by the RFC.  If not, then it
			 *	may be a USR-style VSA, or it may be a
			 *	vendor who packs all of the
			 *	information into one nonsense
			 *	attribute
			 */
			subptr = ptr + 4;
			sublen = attrlen - 4;

			while (sublen > 0) {
				if (subptr[1] < 2) { /* too short */
					break;
				}

				if (subptr[1] > sublen) { /* too long */
					break;
				}

				sublen -= subptr[1]; /* just right */
				subptr += subptr[1];
			}

			/*
			 *	If the attribute is RFC compatible,
			 *	then allow it as an RFC style VSA.
			 */
			if (sublen == 0) {
				ptr += 4;
				vendorlen = attrlen - 4;
				attribute = *ptr++ | (vendorcode << 16);
				attrlen   = *ptr++;
				attrlen -= 2;
				length -= 6;

				/*
				 *	USR-style attributes are 4 octets,
				 *	with the upper 2 octets being zero.
				 *
				 *	The upper octets may not be zero,
				 *	but that then means we won't be
				 *	able to pack the vendor & attribute
				 *	into a 32-bit number, so we can't
				 *	handle it.
				 *
				 *
				 *	FIXME: Update the dictionaries so
				 *	that we key off of per-attribute
				 *	flags "4-octet", instead of hard
				 *	coding USR here.  This will also
				 *	let us send packets with other
				 *	vendors having 4-octet attributes.
				 */
			} else if ((vendorcode == VENDORPEC_USR) &&
				   ((ptr[4] == 0) && (ptr[5] == 0))) {
				DICT_ATTR *da;
				
				da = dict_attrbyvalue((vendorcode << 16) |
						      (ptr[6] << 8) |
						      ptr[7]);

				/*
				 *	See if it's in the dictionary.
				 *	If so, it's a valid USR style
				 *	attribute.  If not, it's not...
				 *
				 *	Don't touch 'attribute' until
				 *	we know what to do!
				 */
				if (da != NULL) {
					attribute = ((vendorcode << 16) |
						     (ptr[6] << 8) |
						     ptr[7]);
					ptr += 8;
					attrlen -= 8;
					length -= 8;
				} /* else it's not in the dictionary */
			} /* else it was a stupid vendor format */
		} /* else it wasn't a VSA */

		/*
		 *	Create the attribute, setting the default type
		 *	to 'octects'.  If the type in the dictionary
		 *	is different, then the dictionary type will
		 *	over-ride this one.
		 */
	create_pair:
		if ((pair = paircreate(attribute, PW_TYPE_OCTETS)) == NULL) {
			pairfree(&packet->vps);
			librad_log("out of memory");
			return -1;
		}
		
		pair->length = attrlen;
		pair->operator = T_OP_EQ;
		pair->next = NULL;
		
		switch (pair->type) {
			
			/*
			 *	The attribute may be zero length,
			 *	or it may have a tag, and then no data...
			 */
		case PW_TYPE_STRING:
			if (pair->flags.has_tag) {
				int offset = 0;

				/*
				 *	If there's sufficient room for
				 *	a tag, and the tag looks valid,
				 *	then use it.
				 */
				if ((pair->length > 0) &&
				    TAG_VALID(*ptr)) {
					pair->flags.tag = *ptr;
					pair->length--;
					offset = 1;

					/*
					 *	If the leading tag
					 *	isn't valid, then it's
					 *	ignored for the tunnel
					 *	password attribute.
					 */
				} else if (pair->flags.encrypt == FLAG_ENCRYPT_TUNNEL_PASSWORD) {
					/*
					 * from RFC2868 - 3.5.  Tunnel-Password
					 * If the value of the Tag field is greater than
					 * 0x00 and less than or equal to 0x1F, it SHOULD
					 * be interpreted as indicating which tunnel
					 * (of several alternatives) this attribute pertains;
					 * otherwise, the Tag field SHOULD be ignored.
					 */
					pair->flags.tag = 0x00;
					if (pair->length > 0) pair->length--;
					offset = 1;
				} else {
				       pair->flags.tag = 0x00;
				}

				/*
				 *	pair->length MAY be zero here.
				 */
				memcpy(pair->strvalue, ptr + offset,
				       pair->length);
			} else {
			  /*
			   *	Ascend binary attributes never have a
			   *	tag, and neither do the 'octets' type.
			   */
			case PW_TYPE_ABINARY:
			case PW_TYPE_OCTETS:
				/* attrlen always < MAX_STRING_LEN */
				memcpy(pair->strvalue, ptr, attrlen);
			        pair->flags.tag = 0;
			}

			/*
			 *	Decrypt passwords here.
			 */
			switch (pair->flags.encrypt) {
			default:
				break;

				/*
				 *  User-Password
				 */
			case FLAG_ENCRYPT_USER_PASSWORD:
				if (original) {
					rad_pwdecode((char *)pair->strvalue,
						     pair->length, secret,
						     (char *)original->vector);
				} else {
					rad_pwdecode((char *)pair->strvalue,
						     pair->length, secret,
						     (char *)packet->vector);
				}
				if (pair->attribute == PW_USER_PASSWORD) {
					pair->length = strlen(pair->strvalue);
				}
				break;

				/*
				 *	Tunnel-Password's may go ONLY
				 *	in response packets.
				 */
			case FLAG_ENCRYPT_TUNNEL_PASSWORD:
				if (!original) {
					librad_log("ERROR: Tunnel-Password attribute in request: Cannot decrypt it.");
					return -1;
				}
				if (rad_tunnel_pwdecode(pair->strvalue,
							&pair->length, 
							secret,
							(char *)original->vector) < 0) {
					return -1;
				}
				break;

				/*
				 *  Ascend-Send-Secret
				 *  Ascend-Receive-Secret
				 */
			case FLAG_ENCRYPT_ASCEND_SECRET:
				{
					uint8_t my_digest[AUTH_VECTOR_LEN];
					make_secret(my_digest,
						    original->vector,
						    secret, ptr);
					memcpy(pair->strvalue, my_digest,
					       AUTH_VECTOR_LEN );
					pair->strvalue[AUTH_VECTOR_LEN] = '\0';
					pair->length = strlen(pair->strvalue);
				}
				break;
			} /* switch over encryption flags */
			break;	/* from octets/string/abinary */
			
		case PW_TYPE_INTEGER:
		case PW_TYPE_DATE:
		case PW_TYPE_IPADDR:
			/*
			 *	Check for RFC compliance.  If the
			 *	attribute isn't compliant, turn it
			 *	into a string of raw octets.
			 *
			 *	Also set the lvalue to something
			 *	which should never match anything.
			 */
			if (attrlen != 4) {
				pair->type = PW_TYPE_OCTETS;
				memcpy(pair->strvalue, ptr, attrlen);
				pair->lvalue = 0xbad1bad1;
				break;
			}

      			memcpy(&lvalue, ptr, 4);

			if (pair->type != PW_TYPE_IPADDR) {
				pair->lvalue = ntohl(lvalue);
			} else {
				 /*
				  *  It's an IP address, keep it in network
				  *  byte order, and put the ASCII IP
				  *  address or host name into the string
				  *  value.
				  */
				pair->lvalue = lvalue;
				ip_ntoa(pair->strvalue, pair->lvalue);
			}

			/*
			 *	Tagged attributes of type integer have
			 *	special treatment.
			 */
			if (pair->flags.has_tag &&
			    pair->type == PW_TYPE_INTEGER) {
			        pair->flags.tag = (pair->lvalue >> 24) & 0xff;
				pair->lvalue &= 0x00ffffff;
			}

			/*
			 *	Try to get the name for integer
			 *	attributes.
			 */
			if (pair->type == PW_TYPE_INTEGER) {
				DICT_VALUE *dval;
				dval = dict_valbyattr(pair->attribute,
						      pair->lvalue);
				if (dval) {
					strNcpy(pair->strvalue,
						dval->name,
						sizeof(pair->strvalue));
				}
			}
			break;
			
			/*
			 *	IPv6 interface ID is 8 octets long.
			 */
		case PW_TYPE_IFID:
			if (attrlen != 8)
				pair->type = PW_TYPE_OCTETS;
			memcpy(pair->strvalue, ptr, attrlen);
			break;

			/*
			 *	IPv6 addresses are 16 octets long
			 */
		case PW_TYPE_IPV6ADDR:
			if (attrlen != 16)
				pair->type = PW_TYPE_OCTETS;
			memcpy(pair->strvalue, ptr, attrlen);
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
			if (attrlen < 2 || attrlen > 18)
				pair->type = PW_TYPE_OCTETS;
			if (attrlen >= 2) {
				if (ptr[1] > 128) {
					pair->type = PW_TYPE_OCTETS;
				}
				/*
				 *	FIXME: double-check that
				 *	(ptr[1] >> 3) matches attrlen + 2
				 */
			}
			memcpy(pair->strvalue, ptr, attrlen);
			break;

		default:
			DEBUG("    %s (Unknown Type %d)\n",
			      pair->name, pair->type);
			free(pair);
			pair = NULL;
			break;
		}
		
		if (pair) {
			debug_pair(pair);
			*tail = pair;
			tail = &pair->next;
		}

		ptr += attrlen;
		length -= attrlen;
		if (vendorlen > 0) vendorlen -= (attrlen + 2);
	}

	/*
	 *	Merge information from the outside world into our
	 *	random pool
	 */
	for (length = 0; length < AUTH_VECTOR_LEN; length++) {
		lrad_rand_pool.randmem[length] += packet->vector[length];
	}
	lrad_rand_pool.randmem[lrad_rand_pool.randmem[0] & 0xff] += packet->id;
	lrad_rand_pool.randmem[lrad_rand_pool.randmem[1] & 0xff] += packet->data_len;

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
#define AUTH_PASS_LEN (16)
int rad_pwencode(char *passwd, int *pwlen, const char *secret,
		 const char *vector)
{
	uint8_t	buffer[AUTH_VECTOR_LEN + MAX_STRING_LEN + 1];
	char	digest[AUTH_VECTOR_LEN];
	int	i, n, secretlen;
	int	len;

	/*
	 *	Pad password to multiple of AUTH_PASS_LEN bytes.
	 */
	len = *pwlen;
	if (len > 128) len = 128;
	*pwlen = len;
	if (len % AUTH_PASS_LEN != 0) {
		n = AUTH_PASS_LEN - (len % AUTH_PASS_LEN);
		for (i = len; n > 0; n--, i++)
			passwd[i] = 0;
		len = *pwlen = i;
	}

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = strlen(secret);
	memcpy(buffer, secret, secretlen);
	memcpy(buffer + secretlen, vector, AUTH_VECTOR_LEN);
	librad_md5_calc((u_char *)digest, buffer, secretlen + AUTH_VECTOR_LEN);

	/*
	 *	Now we can encode the password *in place*
	 */
	for (i = 0; i < AUTH_PASS_LEN; i++)
		passwd[i] ^= digest[i];

	if (len <= AUTH_PASS_LEN) return 0;

	/*
	 *	Length > AUTH_PASS_LEN, so we need to use the extended
	 *	algorithm.
	 */
	for (n = 0; n < 128 && n <= (len - AUTH_PASS_LEN); n += AUTH_PASS_LEN) { 
		memcpy(buffer + secretlen, passwd + n, AUTH_PASS_LEN);
		librad_md5_calc((u_char *)digest, buffer, secretlen + AUTH_PASS_LEN);
		for (i = 0; i < AUTH_PASS_LEN; i++)
			passwd[i + n + AUTH_PASS_LEN] ^= digest[i];
	}

	return 0;
}

/*
 *	Decode password.
 */
int rad_pwdecode(char *passwd, int pwlen, const char *secret,
		 const char *vector)
{
	uint8_t	buffer[AUTH_VECTOR_LEN + MAX_STRING_LEN + 1];
	char	digest[AUTH_VECTOR_LEN];
	char	r[AUTH_VECTOR_LEN];
	char	*s;
	int	i, n, secretlen;
	int	rlen;

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = strlen(secret);
	memcpy(buffer, secret, secretlen);
	memcpy(buffer + secretlen, vector, AUTH_VECTOR_LEN);
	librad_md5_calc((u_char *)digest, buffer, secretlen + AUTH_VECTOR_LEN);

	/*
	 *	Now we can decode the password *in place*
	 */
	memcpy(r, passwd, AUTH_PASS_LEN);
	for (i = 0; i < AUTH_PASS_LEN && i < pwlen; i++)
		passwd[i] ^= digest[i];

	if (pwlen <= AUTH_PASS_LEN) {
		passwd[pwlen+1] = 0;
		return pwlen;
	}

	/*
	 *	Length > AUTH_PASS_LEN, so we need to use the extended
	 *	algorithm.
	 */
	rlen = ((pwlen - 1) / AUTH_PASS_LEN) * AUTH_PASS_LEN;

	for (n = rlen; n > 0; n -= AUTH_PASS_LEN ) { 
		s = (n == AUTH_PASS_LEN) ? r : (passwd + n - AUTH_PASS_LEN);
		memcpy(buffer + secretlen, s, AUTH_PASS_LEN);
		librad_md5_calc((u_char *)digest, buffer, secretlen + AUTH_PASS_LEN);
		for (i = 0; i < AUTH_PASS_LEN && (i + n) < pwlen; i++)
			passwd[i + n] ^= digest[i];
	}
	passwd[pwlen] = 0;

	return pwlen;
}

static unsigned int salt_offset = 0;

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
			const char *vector)
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
			const char *vector)
{
	uint8_t		buffer[AUTH_VECTOR_LEN + MAX_STRING_LEN + 3];
	uint8_t		digest[AUTH_VECTOR_LEN];
	uint8_t		decrypted[MAX_STRING_LEN + 1];
	int		secretlen;
	unsigned	i, n, len;
	
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

	/*
	 *	Set up the initial key:
	 *
	 *	 b(1) = MD5(secret + vector + salt)
	 */
	memcpy(buffer, secret, secretlen);
	memcpy(buffer + secretlen, vector, AUTH_VECTOR_LEN);
	memcpy(buffer + secretlen + AUTH_VECTOR_LEN, passwd, 2);
	librad_md5_calc(digest, buffer, secretlen + AUTH_VECTOR_LEN + 2);

	/*
	 *	A quick check: decrypt the first octet of the password,
	 *	which is the 'data_len' field.  Ensure it's sane.
	 *
	 *	'n' doesn't include the 'data_len' octet
	 *	'len' does.
	 */
	n = passwd[2] ^ digest[0];
	if (n >= len) {
		librad_log("tunnel password is too long for the attribute");
		return -1;
	}

	/*
	 *	Loop over the data, decrypting it, and generating
	 *	the key for the next round of decryption.
	 */
	for (n = 0; n < len; n += AUTH_PASS_LEN) {
		for (i = 0; i < AUTH_PASS_LEN; i++) {
			decrypted[n + i] = passwd[n + i + 2] ^ digest[i];

			/*
			 *	Encrypted password may not be aligned
			 *	on 16 octets, so we catch that here...
			 */
			if ((n + i) == len) break;
		}

		/*
		 *	Update the digest, based on
		 *
		 *	b(n) = MD5(secret + cleartext(n-1)
		 *
		 *	but only if there's more data...
		 */
		memcpy(buffer + secretlen, passwd + n + 2, AUTH_PASS_LEN);
		librad_md5_calc(digest, buffer, secretlen + AUTH_PASS_LEN);
	}

	/*
	 *	We've already validated the length of the decrypted
	 *	password.  Copy it back to the caller.
	 */
	memcpy(passwd, decrypted + 1, decrypted[0]);
	passwd[decrypted[0]] = 0;
	*pwlen = decrypted[0];

	return decrypted[0];
}

/*
 *	Encode a CHAP password
 *
 *	FIXME: might not work with Ascend because
 *	we use vp->length, and Ascend gear likes
 *	to send an extra '\0' in the string!
 */
int rad_chap_encode(RADIUS_PACKET *packet, char *output, int id,
		    VALUE_PAIR *password)
{
	int		i;
	char		*ptr;
	char		string[MAX_STRING_LEN * 2 + 1];
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
	memcpy(ptr, password->strvalue, password->length);
	ptr += password->length;
	i += password->length;

	/*
	 *	Use Chap-Challenge pair if present,
	 *	Request-Authenticator otherwise.
	 */
	challenge = pairfind(packet->vps, PW_CHAP_CHALLENGE);
	if (challenge) {
		memcpy(ptr, challenge->strvalue, challenge->length);
		i += challenge->length;
	} else {
		memcpy(ptr, packet->vector, AUTH_VECTOR_LEN);
		i += AUTH_VECTOR_LEN; 
	}

	*output = id;
	librad_md5_calc((u_char *)output + 1, (u_char *)string, i);

	return 0;
}

/*
 *	Create a random vector of AUTH_VECTOR_LEN bytes.
 */
static void random_vector(uint8_t *vector)
{
	int i;

	if (!lrad_pool_initialized) {
		memset(&lrad_rand_pool, 0, sizeof(lrad_rand_pool));

		/*
		 *	Initialize the state to something, using
		 *	numbers which aren't random, but which also
		 *	aren't static.
		 */
		lrad_rand_pool.randrsl[0] = (uint32_t) &lrad_pool_initialized;
		lrad_rand_pool.randrsl[1] = (uint32_t) &i;
		lrad_rand_pool.randrsl[2] = (uint32_t) vector;

		lrad_randinit(&lrad_rand_pool, 1);
	}

	lrad_isaac(&lrad_rand_pool);

	/*
	 *	Copy the random data over.
	 */
	for (i = 0; i < AUTH_VECTOR_LEN; i++) {
		*(vector++) = lrad_rand_pool.randrsl[i] & 0xff;
	}
}

/*
 *	Return a 32-bit random number.
 */
uint32_t lrad_rand(void)
{
	uint32_t answer;
	static int rand_index = 0;

	/*
	 *	Ensure that the pool is initialized.
	 */
	if (!lrad_pool_initialized) {
		uint8_t vector[AUTH_VECTOR_LEN];

		random_vector(vector);
	}

	/*
	 *	Grab an entry from the pool.
	 */
	answer = lrad_rand_pool.randrsl[rand_index];

	/*
	 *	Go to the next entry (wrapping around to zero).
	 */
	rand_index++;
	rand_index &= 0xff;

	/*
	 *	Every 256 numbers, churn the pool again.
	 */
	if (rand_index == 0) {
		lrad_isaac(&lrad_rand_pool);
	}

	return answer;
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
	memset(rp, 0, sizeof(RADIUS_PACKET));
	if (newvector)
		random_vector(rp->vector);

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

	if (radius_packet->data) free(radius_packet->data);
	if (radius_packet->vps) pairfree(&radius_packet->vps);

	free(radius_packet);

	*radius_packet_ptr = NULL;
}

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
static void make_secret(unsigned char *digest, uint8_t *vector,
			const char *secret, char *value)
{
        u_char  buffer[256 + AUTH_VECTOR_LEN];
        int             secretLen = strlen(secret);
        int             i;

        memcpy(buffer, vector, AUTH_VECTOR_LEN );
        memcpy(buffer + AUTH_VECTOR_LEN, secret, secretLen );

        librad_md5_calc(digest, buffer, AUTH_VECTOR_LEN + secretLen );
        memset(buffer, 0, sizeof(buffer));

        for ( i = 0; i < AUTH_VECTOR_LEN; i++ ) {
		digest[i] ^= value[i];
        }
}
