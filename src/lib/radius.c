/*
 * radius.c	Functions to send/receive radius packets.
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"
#include	"md5.h"

#include	<stdlib.h>

#if HAVE_UNISTD_H
#include	<unistd.h>
#endif

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
 *  Internal prototypes
 */
static void make_secret(unsigned char *digest, uint8_t *vector,
			const char *secret, char *value);

/*
 *	Reply to the request.  Also attach
 *	reply attribute value pairs and any user message provided.
 */
int rad_send(RADIUS_PACKET *packet, const RADIUS_PACKET *original, const char *secret)
{
	VALUE_PAIR		*reply;
	struct	sockaddr_in	saremote;
	struct	sockaddr_in	*sa;
	const char		*what;
	uint8_t			ip_buffer[16];

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
		  uint8_t		*ptr, *length_ptr, *vsa_length_ptr;
		  uint8_t		digest[16];
		  int			secretlen;
		  int			vendorcode, vendorpec;
		  u_short		total_length;
		  int			len, allowed;
		  int			msg_auth_offset = 0;
		  uint8_t		data[4096];
		  
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
		  vendorcode = 0;
		  vendorpec = 0;
		  vsa_length_ptr = NULL;

		  for (reply = packet->vps; reply; reply = reply->next) {
			  /*
			   *	Ignore non-wire attributes
			   */
			  if ((VENDOR(reply->attribute) == 0) &&
			      ((reply->attribute & 0xFFFF) > 0xff)) {
				  continue;
			  }

			  /*
			   *	Do stuff for Message-Authenticator
			   */
			  if (reply->attribute == PW_MESSAGE_AUTHENTICATOR) {
				  /*
				   *  Set it to zero!
				   */
				  reply->length = AUTH_VECTOR_LEN;
				  memset(reply->strvalue, 0, AUTH_VECTOR_LEN);
				  msg_auth_offset = total_length;
			  }

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
				   *	Each USR attribute gets it's own
				   *	VSA wrapper, so we re-set the
				   *	vendor specific information.
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
			  case PW_TYPE_ABINARY:
			  case PW_TYPE_STRING:
			  case PW_TYPE_OCTETS:
				  /*
				   *  Hmm... this is based on names
				   *  right now.  We really shouldn't do
				   *  this.  It should be based on the value
				   *  of the attribute (VSA or not).
				   */
				  if ((strcmp(reply->name, "Ascend-Send-Secret") == 0) ||
				      (strcmp(reply->name, "Ascend-Receive-Secret") == 0)) {
					  make_secret(digest, packet->vector,
						      secret, reply->strvalue);
					  memcpy(reply->strvalue, digest, AUTH_VECTOR_LEN );
					  reply->length = AUTH_VECTOR_LEN;
				  }

				  /* 
				   *    Encrypt Tunnel-Password
				   *    here -- cparker@starnetusa.net
				   */

				  /*
				   *	Encrypt with Tunnel-Password style if needed.
				   */
				  if (reply->flags.encrypt == 2) {

				    rad_tunnel_pwencode(reply->strvalue,
							&(reply->length),
							secret,
							packet->vector);
				    
				  }
			  

				  len = reply->length;

				  /*
				   *    Set the TAG at the beginning of the string if tagged.
				   *    If tag value is not valid for tagged attribute, make 
				   *    it 0x00 per RFC 2868.  -cparker
				   */
				  if(reply->flags.has_tag) {
				          len++;
					  if(TAG_VALID(reply->flags.tag)) {
					          *ptr++ = reply->flags.tag;
					  } else {
					          *ptr++ = 0x00;
					  }
				  }
				 
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
					  lvalue = reply->lvalue;
				  }
				  memcpy(ptr, &lvalue, 4);
				  ptr += 4;
				  total_length += 4;
				  break;

			  default:
				  break;
			  }
			  
			  /*
			   *	Print out ONLY the attributes which
			   *	we're sending over the wire.  Also,
			   *	pick up any hacked password
			   *	attributes.
			   */
			  debug_pair(reply);
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
		  if (packet->code != PW_AUTHENTICATION_REQUEST &&
		      packet->code != PW_STATUS_SERVER) {
		    MD5_CTX	context;
		      /*
		       *	Set the Message-Authenticator attribute,
		       *	BEFORE setting the reply authentication vector
		       *	for CHALLENGE, ACCEPT and REJECT.
		       */
		      if (msg_auth_offset) {
			      uint8_t calc_auth_vector[AUTH_VECTOR_LEN];

			      switch (packet->code) {
			      default:
				break;
				
			      case PW_AUTHENTICATION_ACK:
			      case PW_AUTHENTICATION_REJECT:
			      case PW_ACCESS_CHALLENGE:
				if (original) {
				  memcpy(hdr->vector, original->vector, AUTH_VECTOR_LEN);
				}
				break;
			      }

			      memset(packet->data + msg_auth_offset + 2, 0,
				     AUTH_VECTOR_LEN);
			      lrad_hmac_md5(packet->data, packet->data_len,
					    secret, secretlen, calc_auth_vector);
			      memcpy(packet->data + msg_auth_offset + 2,
				     calc_auth_vector, AUTH_VECTOR_LEN);
			      memcpy(hdr->vector, packet->vector, AUTH_VECTOR_LEN);
		      }

		      MD5Init(&context);
		      MD5Update(&context, packet->data, packet->data_len);
		      MD5Update(&context, secret, strlen(secret));
		      MD5Final(digest, &context);

		      memcpy(hdr->vector, digest, AUTH_VECTOR_LEN);
		      memcpy(packet->vector, digest, AUTH_VECTOR_LEN);
		  }

		  /*
		   *	Set the Message-Authenticator attribute,
		   *	AFTER setting the authentication vector
		   *	only for ACCESS-REQUESTS
		   */
		  else if (msg_auth_offset) {
			  uint8_t calc_auth_vector[AUTH_VECTOR_LEN];

			  switch (packet->code) {
			  default:
			    break;
			    
			  case PW_AUTHENTICATION_ACK:
			  case PW_AUTHENTICATION_REJECT:
			  case PW_ACCESS_CHALLENGE:
			    if (original) {
			      memcpy(hdr->vector, original->vector, AUTH_VECTOR_LEN);
			    }
			    break;
			  }

			  memset(packet->data + msg_auth_offset + 2,
				 0, AUTH_VECTOR_LEN);
			  lrad_hmac_md5(packet->data, packet->data_len,
					secret, secretlen, calc_auth_vector);
			  memcpy(packet->data + msg_auth_offset + 2,
				  calc_auth_vector, AUTH_VECTOR_LEN);
			  memcpy(hdr->vector, packet->vector, AUTH_VECTOR_LEN);
		  }

		  /*
		   *	If packet->data points to data, then we print out
		   *	the VP list again only for debugging.
		   */
	} else if (librad_debug) {
	  	DEBUG("Sending %s of id %d to %s\n", what, packet->id,
		      ip_ntoa((char *)ip_buffer, packet->dst_ipaddr));
		
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
		      &saremote, sizeof(struct sockaddr_in));
}


/*
 *	Validates the requesting client NAS.  Calculates the
 *	signature based on the clients private key.
 */
static int calc_acctdigest(RADIUS_PACKET *packet, const char *secret)
{
	u_char		digest[AUTH_VECTOR_LEN];
	MD5_CTX	context;

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
static int calc_replydigest(RADIUS_PACKET *packet, RADIUS_PACKET *original, const char *secret)
{
	uint8_t		calc_digest[AUTH_VECTOR_LEN];
	MD5_CTX		context;

	/*
	 *  Copy the original vector in place.
	 */
	memcpy(packet->data + 4, original->vector, sizeof(original->vector));

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
	memcpy(packet->data + 4, packet->vector, sizeof(packet->vector));

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
	uint8_t			*vendorattr;
	int			count;
	radius_packet_t		*hdr;
	char			host_ipaddr[16];
	int			seen_eap;
	uint8_t			data[4096];
	int			num_attributes;
	uint32_t                vendorcode;
	int			vendorlen;
	
	/*
	 *	Allocate the new request data structure
	 */
	if ((packet = malloc(sizeof(RADIUS_PACKET))) == NULL) {
		librad_log("out of memory");
		errno = ENOMEM;
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
		free(packet);
		return NULL;
	}

	/*
	 *	Check for packets smaller than the packet header.
	 */
	if (packet->data_len < AUTH_HDR_LEN) {
		librad_log("WARNING: Malformed RADIUS packet from host %s: too short",
			   ip_ntoa(host_ipaddr, packet->src_ipaddr));
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
	if (packet->data_len != totallen) {
		librad_log("WARNING: Malformed RADIUS packet from host %s: received %d octets, packet size says %d",
			   ip_ntoa(host_ipaddr, packet->src_ipaddr),
			   packet->data_len, totallen);
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
			if (attr[1] < 6) {
				librad_log("WARNING: Malformed RADIUS packet from host %s: Vendor-Specific has invalid length %d",
					   ip_ntoa(host_ipaddr, packet->src_ipaddr),
					   attr[1] - 2);
				free(packet);
				return NULL;
			}
			memcpy(&vendorcode, attr + 2, 4);
			vendorcode = ntohl(vendorcode);
			if (vendorcode == VENDORPEC_USR) {
				if (attr[1] < 8){
					librad_log("WARNING: Malformed RADIUS packet from host %s: USR attribute has invalid length %d",
					   ip_ntoa(host_ipaddr, packet->src_ipaddr),
					   attr[1] - 2);
					free(packet);
					return NULL;
				}
				break;
			}
			vendorlen = attr[1] - 6;
			vendorattr = attr + 6;
			while (vendorlen >= 2) {
				if (vendorattr[1] < 2){
					librad_log("WARNING: Malformed RADIUS packet from host %s: Vendor specific attribute has invalid length %d",
					   ip_ntoa(host_ipaddr, packet->src_ipaddr),
					   vendorattr[1] - 2);
					free(packet);
					return NULL;
				}
				vendorlen -= vendorattr[1];
				vendorattr += vendorattr[1];
			}
			if (vendorlen != 0){
				librad_log("WARNING: Malformed RADIUS packet from host %s: Vendor specific attributes do not exactly fill Vendor-Specific",
				   ip_ntoa(host_ipaddr, packet->src_ipaddr),
				   vendorattr[1] - 2);
				free(packet);
				return NULL;
			}
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
	 *	If we've seen an EAP-Message attribute without a
	 *	Message-Authenticator attribute, it's invalid.
	 */
	if (((seen_eap & PW_EAP_MESSAGE) == PW_EAP_MESSAGE) &&
	    ((seen_eap & PW_MESSAGE_AUTHENTICATOR) != PW_MESSAGE_AUTHENTICATOR)) {
		librad_log("WARNING: Malformed RADIUS packet from host %s: Contains EAP-Message, but no Message-Authenticator",
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
int rad_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original, const char *secret)
{
	DICT_ATTR		*attr;
	uint32_t		lvalue;
	uint32_t		vendorcode;
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
			  if (original) {
				  memcpy(packet->data + 4, original->vector, AUTH_VECTOR_LEN);
			  }
			  break;
			}

			lrad_hmac_md5(packet->data, packet->data_len,
				      secret, strlen(secret), calc_auth_vector);
			if (memcmp(calc_auth_vector, msg_auth_vector,
				    sizeof(calc_auth_vector)) != 0) {
				char buffer[32];
				librad_log("Received packet from %s with invalid Message-Authenticator!",
					   ip_ntoa(buffer, packet->src_ipaddr));
				return 1;
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
		case PW_AUTHENTICATION_REQUEST:
		case PW_STATUS_SERVER:
			/*
			 *	The authentication vector is random
			 *	nonsense, invented by the client.
			 */
			break;

		case PW_ACCOUNTING_REQUEST:
			if (calc_acctdigest(packet, secret) > 1) {
				char buffer[32];
				librad_log("Received Accounting-Request packet "
				    "from %s with invalid signature!",
				    ip_ntoa(buffer, packet->src_ipaddr));
				return 1;
			}
			break;

			/* Verify the reply digest */
		case PW_AUTHENTICATION_ACK:
		case PW_AUTHENTICATION_REJECT:
		case PW_ACCOUNTING_RESPONSE:
			if (calc_replydigest(packet, original, secret) > 1) {
				char buffer[32];
				librad_log("Received %s packet "
					   "from %s with invalid signature!",
					   packet_codes[packet->code],
					   ip_ntoa(buffer, packet->src_ipaddr));
				return 1;
			}
		  break;
	}

	/*
	 *	Extract attribute-value pairs
	 */
	ptr = hdr->data;
	length = packet->data_len - AUTH_HDR_LEN;
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
			vendorcode = ntohl(lvalue);
			if (vendorcode != 0) {

				if (vendorcode == VENDORPEC_USR) {
					ptr += 4;
					memcpy(&lvalue, ptr, 4);
					/*printf("received USR %04x\n", ntohl(lvalue));*/
					attribute = (ntohl(lvalue) & 0xFFFF) |
							(vendorcode << 16);
					ptr += 4;
					attrlen -= 8;
					length -= 8;

				} else {
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

		/*
		 *	FIXME: should we us paircreate() ?
		 */
		if ((pair = malloc(sizeof(VALUE_PAIR))) == NULL) {
			pairfree(&first_pair);
			librad_log("out of memory");
			errno = ENOMEM;
			return -1;
		}
		
		memset(pair, 0, sizeof(VALUE_PAIR));
		if ((attr = dict_attrbyvalue(attribute)) == NULL) {
			snprintf(pair->name, sizeof(pair->name), "Attr-%d", attribute);
			pair->type = PW_TYPE_STRING;
		} else {
			strcpy(pair->name, attr->name);
			pair->type = attr->type;
			pair->flags = attr->flags;
		}
		pair->attribute = attribute;
		pair->length = attrlen;
		pair->next = NULL;
		
		switch (pair->type) {
			
		case PW_TYPE_OCTETS:
		case PW_TYPE_ABINARY:
		case PW_TYPE_STRING:
			/*
			 *	Hmm... this is based on names right
			 *	now.  We really shouldn't do this.
			 *	It should be based on the value of
			 *	the attribute (VSA or not).
			 */
			if ((strcmp(pair->name, "Ascend-Send-Secret") == 0) ||
			    (strcmp(pair->name, "Ascend-Receive-Secret") == 0)) {
				uint8_t my_digest[AUTH_VECTOR_LEN];
				make_secret( my_digest, original->vector,
					     secret, ptr);
				memcpy(pair->strvalue, my_digest, AUTH_VECTOR_LEN );
				pair->strvalue[AUTH_VECTOR_LEN] = '\0';
				pair->length = strlen(pair->strvalue);
			} else if (pair->flags.has_tag &&
				   pair->type == PW_TYPE_STRING) {
			        if(TAG_VALID(*ptr)) 
				       pair->flags.tag = *ptr;
				else
				       pair->flags.tag = 0x00;
				pair->length--;
				memcpy(pair->strvalue, ptr + 1, 
				       pair->length);
			} else {
				/* attrlen always < MAX_STRING_LEN */
				memcpy(pair->strvalue, ptr, attrlen);
			        pair->flags.tag = 0;
			}

			/* FIXME: Decrypt attributes like Tunnel-Password here -cparker */
			if(pair->flags.encrypt == 2) {

			        rad_tunnel_pwdecode((char *)pair->strvalue,
						     pair->length, 
						     secret,
						     (char *)original->vector);
				pair->length = strlen(pair->strvalue);

			}

			break;
			
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
				pair->lvalue = 0xbaddbadd;
				break;
			}

      			memcpy(&lvalue, ptr, 4);

			if (attr->type != PW_TYPE_IPADDR)
				pair->lvalue = ntohl(lvalue);
			else
				pair->lvalue = lvalue;

			/*
			 *  Only PW_TYPE_INTEGER should have tags.
			 */
			if (pair->flags.has_tag &&
			    pair->type == PW_TYPE_INTEGER) {
			        pair->flags.tag = (pair->lvalue >> 24) & 0xff;
				pair->lvalue &= 0xffffff;
			}
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
 *	Encode Tunnel-Password attributes when sending them out on the wire.
 *
 *	int *pwlen is updated to the new length of the encrypted
 *	password - a multiple of 16 bytes.
 *
 *      This is per RFC-2868 which adds a two char SALT to the initial intermediate
 *      value MD5 hash.
 */

int rad_tunnel_pwencode(char *passwd, int *pwlen, const char *secret, const char *vector)
{
	uint8_t	buffer[AUTH_VECTOR_LEN + MAX_STRING_LEN + 3];
	char	digest[AUTH_VECTOR_LEN];
	char    salt[2];
	int	i, n, secretlen;
	int	len;

	if(pwlen < 2) {
	  return 0;
	}
	salt[0] = passwd[0];
	salt[1] = passwd[1];

	/* Advance pointer past the salt, which is first two chars of passwd */
	passwd = passwd + 2;
	
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
	memcpy(buffer + secretlen + AUTH_VECTOR_LEN, salt, 2);
	librad_md5_calc((u_char *)digest, buffer, secretlen + AUTH_VECTOR_LEN + 2);

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
 *	Decode Tunnel-Password encrypted attributes.
 *
 *      Defined in RFC-2868, this adds a two char SALT to the initial intermediate
 *      value, to differentiate it from the above.
 */

int rad_tunnel_pwdecode(char *passwd, int pwlen, const char *secret, const char *vector)
{
	uint8_t	buffer[AUTH_VECTOR_LEN + MAX_STRING_LEN + 3];
	char	digest[AUTH_VECTOR_LEN];
	char	r[AUTH_VECTOR_LEN];
	char    salt[2];
	char	*s;
	int	i, n, secretlen;
	int	rlen;

	if(pwlen < 2) {
	  return 0;
	}
	salt[0] = passwd[0];
	salt[1] = passwd[1];

	passwd = passwd + 2;
        pwlen = pwlen - 2;

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = strlen(secret);
	memcpy(buffer, secret, secretlen);
	memcpy(buffer + secretlen, vector, AUTH_VECTOR_LEN);
	memcpy(buffer + secretlen + AUTH_VECTOR_LEN, salt, 2);
	librad_md5_calc((u_char *)digest, buffer, secretlen + AUTH_VECTOR_LEN + 2);

	/*
	 *	Now we can decode the password *in place*
	 */
	memcpy(r, passwd, AUTH_PASS_LEN);
	for (i = 0; i < AUTH_PASS_LEN && i < pwlen; i++)
		passwd[i] ^= digest[i];

	if (pwlen <= AUTH_PASS_LEN) {
		passwd[pwlen+1] = '\0';
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
	passwd[pwlen] = '\0';

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
