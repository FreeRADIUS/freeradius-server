/*
 * radius.c	Functions to send/receive radius packets.
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<stdlib.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<string.h>
#include	<ctype.h>

#include	"libradius.h"

#if HAVE_NETINET_IN_H
#include	<netinet/in.h>
#endif

#include	<sys/socket.h>

#if HAVE_ARPA_INET_H
#include	<arpa/inet.h>
#endif

#if HAVE_MALLOC_H
#include	<malloc.h>
#endif

#ifdef WIN32
#include	<process.h>
#endif

/*
 *  The RFC says 4096 octets max, and most packets are less than 256.
 *  However, this number is just larger than the maximum MTU of just
 *  most types of networks, except maybe for gigabit ethernet.
 */
#define PACKET_DATA_LEN 1600

typedef struct radius_packet_t {
  uint8_t	code;
  uint8_t	id;
  uint8_t	length[2];
  uint8_t	vector[16];
  uint8_t	data[1];
} radius_packet_t;

static uint8_t random_vector_pool[AUTH_VECTOR_LEN*2];

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
  "Status-Client"
};

/*
 *	Reply to the request.  Also attach
 *	reply attribute value pairs and any user message provided.
 */
int rad_send(RADIUS_PACKET *packet, const char *secret)
{
	VALUE_PAIR		*reply;
	struct	sockaddr	saremote;
	struct	sockaddr_in	*sa;
	const char		*what;
	uint8_t			ip_buffer[16];

	reply = packet->vps;
	
	if ((packet->code > 0) && (packet->code < 14)) {
		what = packet_codes[packet->code];
	} else {
		what = "Reply";
	}

	/*
	 *  First time through, allocate room for the packet
	 */
	if (!packet->data) {
		  radius_packet_t	*hdr;
		  int32_t		lvalue;
		  uint8_t		*ptr, *length_ptr;
		  uint8_t		digest[16];
		  int			secretlen;
		  int			vendorcode, vendorpec;
		  u_short		total_length, tmp;
		  int			len;
		  
		  hdr = (radius_packet_t *) malloc(PACKET_DATA_LEN);
		  if (!hdr) {
		    librad_log("Out of memory");
		    return -1;
		  }
		  packet->data = (uint8_t *) hdr;
		  
		  /*
		   *	Build standard header
		   */
		  hdr->code = packet->code;
		  hdr->id = packet->id;
		  if (packet->code == PW_ACCOUNTING_REQUEST) {
			  memset(hdr->vector, 0, AUTH_VECTOR_LEN);
		  } else {
			  memcpy(hdr->vector, packet->vector, AUTH_VECTOR_LEN);
		  }

		  DEBUG("Sending %s of id %d to %s:%d\n",
			what, packet->id,
			ip_ntoa((char *)ip_buffer, packet->dst_ipaddr),
			packet->dst_port);
		  
		  total_length = AUTH_HDR_LEN;
		  
		  /*
		   *	Load up the configuration values for the user
		   */
		  ptr = hdr->data;
		  while (reply != NULL) {
		    /*
		     *	This could be a vendor-specific attribute.
		     */
		    length_ptr = NULL;
		    if ((vendorcode = VENDOR(reply->attribute)) > 0 &&
			(vendorpec  = dict_vendorpec(vendorcode)) > 0) {
		      *ptr++ = PW_VENDOR_SPECIFIC;
		      length_ptr = ptr;
		      *ptr++ = 6;
		      lvalue = htonl(vendorpec);
		      memcpy(ptr, &lvalue, 4);
		      ptr += 4;
		      total_length += 6;
		    } else if (reply->attribute > 0xff) {
		      /*
		       *	Ignore attributes > 0xff
		       */

		      if (librad_debug) {
			printf("\t  ");
			vp_print(stdout, reply);
			printf("\n");
		      }
		      reply = reply->next;
		      continue;
		    } else
		      vendorpec = 0;
		    
#ifdef ATTRIB_NMC
		    if (vendorpec == VENDORPEC_USR) {
		      lvalue = htonl(reply->attribute & 0xFFFF);
		      memcpy(ptr, &lvalue, 4);
		      total_length += 2;
		      *length_ptr  += 2;
		      ptr          += 4;
		    } else
#endif
		      *ptr++ = (reply->attribute & 0xFF);
		    
		    switch(reply->type) {
		      
		    case PW_TYPE_STRING:
		      /*
		       *	If it's a password, encode it.
		       */
		      if (!vendorpec) {
			if (reply->attribute == PW_PASSWORD) {
			  rad_pwencode((char *)reply->strvalue,
				       &(reply->length),
				       secret, (char *)packet->vector);

			  /*
			   *	If there's a CHAP password, assume it's
			   *    currently in clear text, and encode it
			   *    in place.
			   *
			   *	The ID is taken from pseudo-random
			   *	numbers somehow...
			   */
			} else if (reply->attribute == PW_CHAP_PASSWORD) {
			  rad_chap_encode(packet, (char *)reply->strvalue,
					  packet->id, reply);
			  reply->length = 1 + CHAP_VALUE_LENGTH;
			} 
		      }
		      
#ifndef ASCEND_BINARY
		    case PW_TYPE_ABINARY:
#endif
		    case PW_TYPE_OCTETS:
		      len = reply->length;
		      
		      if (len >= MAX_STRING_LEN) {
			len = MAX_STRING_LEN - 1;
		      }
#ifdef ATTRIB_NMC
		      if (vendorpec != VENDORPEC_USR)
#endif
			*ptr++ = len + 2;
		      if (length_ptr) *length_ptr += len + 2;
		      memcpy(ptr, reply->strvalue,len);
		      ptr += len;
		      total_length += len + 2;
		      break;
		      
		    case PW_TYPE_INTEGER:
		    case PW_TYPE_IPADDR:
#ifdef ATTRIB_NMC
		      if (vendorpec != VENDORPEC_USR)
#endif
			*ptr++ = sizeof(uint32_t) + 2;
		      if (length_ptr) *length_ptr += sizeof(uint32_t)+ 2;
		      if (reply->type != PW_TYPE_IPADDR)
			lvalue = htonl(reply->lvalue);
		      else
			lvalue = reply->lvalue;
		      memcpy(ptr, &lvalue, sizeof(uint32_t));
		      ptr += sizeof(uint32_t);
		      total_length += sizeof(uint32_t) + 2;
		      break;
#ifdef ASCEND_BINARY
		    case PW_TYPE_ABINARY:
		      len = reply->length;
		      if (len >= MAX_STRING_LEN) {
			len = MAX_STRING_LEN - 1;
		      }
#ifdef ATTRIB_NMC
		      if (vendorpec != VENDORPEC_USR)
#endif
			*ptr++ = len + 2;
		      if (length_ptr) *length_ptr += len + 2;
		      memcpy(ptr, reply->strvalue,len);
		      ptr += len;
		      total_length += len + 2;
		      break;
#endif

		    default:
		      break;
		    }
		    
		    /*
		     *	Print out ONLY the attributes which we're
		     *	sending over the wire.  Also, pick up any hacked
		     *  password attributes.
		     */
		    debug_pair(reply);
		    reply = reply->next;
		  }
		  
		  tmp = htons(total_length);
		  memcpy(hdr->length, &tmp, sizeof(u_short));
		  packet->data_len = total_length;

		  /*
		   *	If this is not an authentication request, we
		   *	need to calculate the md5 hash over the entire packet
		   *	and put it in the vector.
		   */
		  if (packet->code != PW_AUTHENTICATION_REQUEST) {
		  	secretlen = strlen(secret);
			memcpy((char *)hdr + total_length, secret, secretlen);
			librad_md5_calc(digest, (unsigned char *)hdr,
					total_length + secretlen);
			memcpy(hdr->vector, digest, AUTH_VECTOR_LEN);
			memset((char *)hdr + total_length, 0, secretlen);
		  }

		  /*
		   *	If packet->data points to data, then we print out
		   *	the VP list again only for debugging.
		   */
	} else if (librad_debug) {
	  	DEBUG("Sending %s of id %d to %s\n", what, packet->id,
		      ip_ntoa((char *)ip_buffer, packet->dst_ipaddr));
		while (reply) {
		  /* FIXME: ignore attributes > 0xff */
		  debug_pair(reply);
		  reply = reply->next;
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
		      &saremote, sizeof(struct sockaddr_in));
}


/*
 *	Validates the requesting client NAS.  Calculates the
 *	signature based on the clients private key.
 */
int calc_acctdigest(RADIUS_PACKET *packet, const char *secret, char *recvbuf, int len)
{
	int		secretlen;
	u_char		digest[AUTH_VECTOR_LEN];

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
	secretlen = strlen(secret);
	memset(recvbuf + 4, 0, AUTH_VECTOR_LEN);
	memcpy(recvbuf + len, secret, secretlen);
	librad_md5_calc(digest, (u_char *)recvbuf, len + secretlen);

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
static int calc_replydigest(RADIUS_PACKET *packet, RADIUS_PACKET *original, const char *secret, char *recvbuf, int len)
{
	int		secretlen;
	uint8_t		calc_digest[AUTH_VECTOR_LEN];

	memcpy(recvbuf + 4, original->vector, sizeof(original->vector));
	secretlen = strlen(secret);
	memcpy(recvbuf + len, secret, secretlen);
	librad_md5_calc(calc_digest, (u_char *)recvbuf, len + secretlen);

	/*
	 *	Return 0 if OK, 2 if not OK.
	 */
	packet->verified =
		memcmp(packet->vector, calc_digest, sizeof(packet->vector)) ? 2 : 0;
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

	/*
	 *	Allocate the new request data structure
	 */
	if ((packet = malloc(sizeof(RADIUS_PACKET))) == NULL) {
		librad_log("out of memory");
		errno = ENOMEM;
		return NULL;
	}
	memset(packet, 0, sizeof(RADIUS_PACKET));
	if ((packet->data = malloc(PACKET_DATA_LEN)) == NULL) {
		free(packet);
		librad_log("out of memory");
		errno = ENOMEM;
		return NULL;
	}

	/*
	 *	Receive the packet.
	 */
	salen = sizeof(saremote);
	memset(&saremote, 0, sizeof(saremote));
	packet->data_len = recvfrom(fd, packet->data, PACKET_DATA_LEN,
		0, (struct sockaddr *)&saremote, &salen);

	/*
	 *	Fill IP header fields.  We need these for the error
	 *	messages which may come later.
	 */
	packet->sockfd = fd;
	packet->src_ipaddr = saremote.sin_addr.s_addr;
	packet->src_port = ntohs(saremote.sin_port);

	/*
	 *	Explicitely set the VP list to empty.
	 */
	packet->vps = NULL;

	/*
	 *	Check for socket errors.
	 */
	if (packet->data_len < 0) {
		librad_log("Error receiving packet from host %s: %s",
			   ip_ntoa(host_ipaddr, packet->src_ipaddr),
			   strerror(errno));
		free(packet->data);
		free(packet);
		return NULL;
	}

	/*
	 *	Check for packets smaller than the packet header.
	 */
	if (packet->data_len < AUTH_HDR_LEN) {
		librad_log("Malformed RADIUS packet from host %s: too short",
			   ip_ntoa(host_ipaddr, packet->src_ipaddr));
		free(packet->data);
		free(packet);
		return NULL;
	}

	/*
	 *	Check for packets with mismatched size.
	 *	i.e. We've received 128 bytes, and the packet header
	 *	says it's 256 bytes long.
	 */
	hdr = (radius_packet_t *)packet->data;
	memcpy(&len, hdr->length, sizeof(u_short));
	totallen = ntohs(len);
	if (packet->data_len != totallen) {
		librad_log("Malformed RADIUS packet from host %s: received %d octets, packet size says %d",
			   ip_ntoa(host_ipaddr, packet->src_ipaddr),
			   packet->data_len, totallen);
		free(packet->data);
		free(packet);
		return NULL;
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
	while (count > 0) {
		/*
		 *	Attribute number zero is NOT defined.
		 */
		if (attr[0] == 0) {
			librad_log("Malformed RADIUS packet from host %s: Invalid attribute 0",
				   ip_ntoa(host_ipaddr, packet->src_ipaddr));
			free(packet->data);
			free(packet);
			return NULL;
		}
		
		/*
		 *	Attributes are at LEAST as long as the ID & length
		 *	fields.  Anything shorter is an invalid attribute.
		 */
       		if (attr[1] < 2) {
			librad_log("Malformed RADIUS packet from host %s: attribute %d too short",
				   ip_ntoa(host_ipaddr, packet->src_ipaddr),
				   attr[0]);
			free(packet->data);
			free(packet);
			return NULL;
		}
		count -= attr[1];	/* grab the attribute length */
		attr += attr[1];
	}

	/*
	 *	If the attributes add up to a packet, it's allowed.
	 *
	 *	If not, we complain, and throw the packet away.
	 */
	if (count != 0) {
		librad_log("Malformed RADIUS packet from host %s: packet attributes do NOT exactly fill the packet",
			   ip_ntoa(host_ipaddr, packet->src_ipaddr));
		free(packet->data);
		free(packet);
		return NULL;
	}

	if (librad_debug) {
		if ((hdr->code > 0) && (hdr->code < 14)) {
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

	return packet;
}

/*
 *	Calculate/check digest, and decode radius attributes.
 */
int rad_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original, const char *secret)
{
	DICT_ATTR		*attr;
	uint32_t		lvalue;
	uint32_t		vendorcode;
	uint32_t		vendorpec;
	VALUE_PAIR		*first_pair;
	VALUE_PAIR		*prev;
	VALUE_PAIR		*pair;
	uint8_t			*ptr;
	int			length;
	int			attribute;
	int			attrlen;
	int			vendorlen;
	radius_packet_t		*hdr;

	hdr = (radius_packet_t *)packet->data;
	length = packet->data_len;

	/*
	 *	Calculate and/or verify digest.
	 */
	switch(packet->code) {
		case PW_AUTHENTICATION_REQUEST:
			/*
			 *	The authentication vector is random
			 *	nonsense, invented by the client.
			 */
			break;
		case PW_ACCOUNTING_REQUEST:
			if (calc_acctdigest(packet, secret,
			    (char *)packet->data, length) > 1) {
				char buffer[32];
				librad_log("Received accounting packet "
				    "from %s with invalid signature!",
				    ip_ntoa(buffer, packet->src_ipaddr));
				return 1;
			}
			break;

			/* Verify the reply digest */
		case PW_AUTHENTICATION_ACK:
		case PW_AUTHENTICATION_REJECT:
			if (calc_replydigest(packet, original, secret,
					     (char *)packet->data,
					     length) > 1) {
				char buffer[32];
				librad_log("Received authentication reply packet "
					   "from %s with invalid signature!",
					   ip_ntoa(buffer, packet->src_ipaddr));
				return 1;
			}
		  break;

		case PW_ACCOUNTING_RESPONSE:
			/*
			 *	FIXME!  Calculate the response digest!
			 */
			break;
	}

	/*
	 *	Extract attribute-value pairs
	 */
	ptr = hdr->data;
	length -= AUTH_HDR_LEN;
	first_pair = NULL;
	prev = NULL;

	vendorcode = 0;
	vendorlen  = 0;

	while(length > 0) {

		if (vendorlen > 0) {
			attribute = *ptr++ | (vendorcode << 16);
			attrlen   = *ptr++;
		} else {
			attribute = *ptr++;
			attrlen   = *ptr++;
		}
		if (attrlen < 2) { /* rad_recv() now handles this check */
			length = 0;
			continue;
		}
		attrlen -= 2;
		length  -= 2;

		/*
		 *	This could be a Vendor-Specific attribute.
		 *
		 */
		if ((vendorlen <= 0) &&
		    (attribute == PW_VENDOR_SPECIFIC) && 
		    (attrlen > 6)) {
			memcpy(&lvalue, ptr, 4);
			vendorpec = ntohl(lvalue);
			if ((vendorcode = dict_vendorcode(vendorpec)) != 0) {
#ifdef ATTRIB_NMC
				if (vendorpec == VENDORPEC_USR) {
					ptr += 4;
					memcpy(&lvalue, ptr, 4);
					/*printf("received USR %04x\n", ntohl(lvalue));*/
					attribute = (ntohl(lvalue) & 0xFFFF) |
							(vendorcode << 16);
					ptr += 4;
					attrlen -= 8;
					length -= 8;
				} else
#endif
				{
					ptr += 4;
					vendorlen = attrlen - 4;
					attribute = *ptr++ | (vendorcode << 16);
					attrlen   = *ptr++;
					attrlen -= 2;
					length -= 6;
				}
			}
			/*
			 *  Else the vendor wasn't found...
			 */
		}

		if ( attrlen >= MAX_STRING_LEN ) {
			DEBUG("attribute %d too long, %d >= %d\n", attribute,
				attrlen, MAX_STRING_LEN);
		}
		/* rad_recv() now handles this check */
		else if ( attrlen > length ) {
			DEBUG("attribute %d longer than buffer left, %d > %d\n",
				attribute, attrlen, length);
		}
		else {
			/*
			 *	FIXME: should we us paircreate() ?
			 */
			if ((pair = malloc(sizeof(VALUE_PAIR))) == NULL) {
				pairfree(first_pair);
				librad_log("out of memory");
				errno = ENOMEM;
				return -1;
			}

			memset(pair, 0, sizeof(VALUE_PAIR));
			if ((attr = dict_attrbyvalue(attribute)) == NULL) {
				sprintf(pair->name, "Attr-%d", attribute);
				pair->type = PW_TYPE_STRING;
			} else {
				strcpy(pair->name, attr->name);
				pair->type = attr->type;
			}
			pair->attribute = attribute;
			pair->length = attrlen;
			pair->next = NULL;

			switch (pair->type) {

			case PW_TYPE_OCTETS:
			case PW_TYPE_ABINARY:
			case PW_TYPE_STRING:
				/* attrlen always < MAX_STRING_LEN */
				memcpy(pair->strvalue, ptr, attrlen);
				break;
			
			case PW_TYPE_INTEGER:
			case PW_TYPE_DATE:
			case PW_TYPE_IPADDR:
				/*
				 *	Check for RFC compliance.
				 *	If the attribute isn't compliant,
				 *	turn it into a string of raw octets.
				 *
				 *	Also set the lvalue to something
				 *	which should never match anything.
				 */
				if (attrlen != 4) {
					pair->type = PW_TYPE_OCTETS;
					memcpy(pair->strvalue, ptr, attrlen);
					pair->lvalue = 0xbaddbadd;
					break;
				}
				memcpy(&lvalue, ptr, 4);
				if (attr->type != PW_TYPE_IPADDR)
					pair->lvalue = ntohl(lvalue);
				else
					pair->lvalue = lvalue;
				break;
			
			default:
				DEBUG("    %s (Unknown Type %d)\n",
					attr->name,attr->type);
				free(pair);
				pair = NULL;
				break;
			}

			if (pair) {
				debug_pair(pair);
				if (first_pair == NULL)
					first_pair = pair;
				else
				  	prev->next = pair;
				prev = pair;
			}
		}
		ptr += attrlen;
		length -= attrlen;
		if (vendorlen > 0) vendorlen -= (attrlen + 2);
	}

	packet->vps = first_pair;

	/*
	 *	Merge information from the outside world into our
	 *	random vector pool.
	 */
	for (length = 0; length < AUTH_VECTOR_LEN; length++) {
		random_vector_pool[length] ^= packet->vector[length];
	}

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
int rad_pwencode(char *passwd, int *pwlen, const char *secret, const char *vector)
{
	uint8_t	buffer[AUTH_VECTOR_LEN + MAX_STRING_LEN + 1];
	char	digest[AUTH_VECTOR_LEN];
	int	i, n, secretlen;
	int	len;

	/*
	 *	Padd password to multiple of AUTH_PASS_LEN bytes.
	 */
	len = strlen(passwd);
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
int rad_pwdecode(char *passwd, int pwlen, const char *secret, const char *vector)
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

/*
 *	Encode a CHAP password
 *
 *	FIXME: might not work with Ascend because
 *	we use vp->length, and Ascend gear likes
 *	to send an extra '\0' in the string!
 */
int rad_chap_encode(RADIUS_PACKET *packet, char *output, int id, VALUE_PAIR *password)
{
	int		i;
	char		*ptr;
	char		string[MAX_STRING_LEN];
	VALUE_PAIR	*challenge;

	/*
	 *	Sanity check the input parameters
	 */
	if ((packet == NULL) || (password == NULL)) {
		return -1;
	}

	/*
	 *	Note that the password VP can be EITHER
	 *	a Password attribute (from a check-item list),
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
	int		i;
	static int	did_srand = 0;
	static int	counter = 0;
#ifdef __linux__
	static int	urandom_fd = -1;

	/*
	 *	Use /dev/urandom if available.
	 */
	if (urandom_fd > -2) {
		/*
		 *	Open urandom fd if not yet opened.
		 */
		if (urandom_fd < 0)
			urandom_fd = open("/dev/urandom", O_RDONLY);
		if (urandom_fd < 0) {
			/*
			 *	It's not there, don't try
			 *	it again.
			 */
			DEBUG("Cannot open /dev/urandom, using rand()\n");
			urandom_fd = -2;
		} else {

			fcntl(urandom_fd, F_SETFD, 1);

			/*
			 *	Read 16 bytes.
			 */
			if (read(urandom_fd, (char *) vector, AUTH_VECTOR_LEN)
			    == AUTH_VECTOR_LEN)
				return;
			/*
			 *	We didn't get 16 bytes - fall
			 *	back on rand) and don't try again.
			 */
		DEBUG("Read short packet from /dev/urandom, using rand()\n");
			urandom_fd = -2;
		}
	}
#endif

	if (!did_srand) {
		srand(time(NULL) + getpid());

		/*
		 *	Now that we have a bad random seed, let's
		 *	make it a little better by MD5'ing it.
		 */
		for (i = 0; i < (int)sizeof(random_vector_pool); i++) {
			random_vector_pool[i] += rand() & 0xff;
		}

		librad_md5_calc((u_char *) random_vector_pool,
				(u_char *) random_vector_pool,
				sizeof(random_vector_pool));

		did_srand = 1;
	}

	/*
	 *	Modify our random pool, based on the counter,
	 *	and put the resulting information through MD5,
	 *	so it's all mashed together.
	 */
	counter++;
	random_vector_pool[AUTH_VECTOR_LEN] += (counter & 0xff);
	librad_md5_calc((u_char *) random_vector_pool,
			(u_char *) random_vector_pool,
			sizeof(random_vector_pool));

	/*
	 *	And do another MD5 hash of the result, to give
	 *	the user a random vector.  This ensures that the
	 *	user has a random vector, without giving them
	 *	an exact image of what's in the random pool.
	 */
	librad_md5_calc((u_char *) vector,
			(u_char *) random_vector_pool,
			sizeof(random_vector_pool));
}


/*
 *	Allocate a new RADIUS_PACKET
 */
RADIUS_PACKET *rad_alloc(int newvector)
{
	RADIUS_PACKET	*rp;

	if ((rp = malloc(sizeof(RADIUS_PACKET))) == NULL)
		return NULL;
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
	RADIUS_PACKET *radius_packet = *radius_packet_ptr;

	if (radius_packet->data) free(radius_packet->data);
	if (radius_packet->vps) pairfree(radius_packet->vps);

	free(radius_packet);

	*radius_packet_ptr = NULL;
}
