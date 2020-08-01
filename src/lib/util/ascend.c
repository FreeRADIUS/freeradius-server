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

/** Routines to parse Ascend's filter attributes
 *
 * @file src/lib/util/ascend.c
 *
 * @copyright 2003,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#ifdef WITH_ASCEND_BINARY
#include "ascend.h"

#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/talloc.h>

#include <ctype.h>

/*
 * Two types of filters are supported, GENERIC and IP.  The identifiers
 * are:
 */

typedef enum {
	ASCEND_FILTER_GENERIC = 0,
	ASCEND_FILTER_IP = 1,
	ASCEND_FILTER_IPX = 2
} ascend_filter_type_t;

/*
 * Generic filters mask and match up to RAD_MAX_FILTER_LEN bytes
 * starting at some offset.  The length is:
 */
#define RAD_MAX_FILTER_LEN	6

/*
 * ASCEND extensions for ABINARY filters
 */

#define IPX_NODE_ADDR_LEN		6

#if ! defined( false )
# define false		0
# define true		(! false)
#endif


/*
 *	ascend_ip_filter_t
 *
 *	The binary format of an IP filter.  ALL fields are stored in
 *	network byte order.
 *
 *	srcip:		The source IP address.
 *
 *	dstip:		The destination IP address.
 *
 *	srcmask:	The number of leading one bits in the source address
 *			mask.  Specifies the bits of interest.
 *
 *	dstmask:	The number of leading one bits in the destination
 *			address mask. Specifies the bits of interest.
 *
 *	proto:		The IP protocol number
 *
 *	established:	A boolean value.  true when we care about the
 *			established state of a TCP connection.  false when
 *			we dont care.
 *
 *	srcport:	TCP or UDP source port number.
 *
 *	dstport:	TCP or UDP destination port number.
 *
 *	srcPortCmp:	One of the values of the RadFilterComparison
 *			enumeration, specifying how to compare the
 *			srcport value.
 *
 *	dstPortCmp:	One of the values of the RadFilterComparison
 *			enumeration, specifying how to compare the
 *			dstport value.
 *
 *	fill:		Round things out to a int16_t boundary.
 */
typedef struct {
	uint32_t	srcip;
	uint32_t	dstip;
	uint8_t 	srcmask;
	uint8_t 	dstmask;
	uint8_t		proto;
	uint8_t		established;
	uint16_t	srcport;
	uint16_t	dstport;
	uint8_t		srcPortComp;
	uint8_t		dstPortComp;
	unsigned char   fill[4];	/* used to be fill[2] */
} ascend_ip_filter_t;


/*
 *	ascend_ipx_net_t
 *
 *	net:      IPX Net address
 *
 *	node:     IPX Node address
 *
 *	socket:      IPX socket address
 */
typedef struct {
	uint32_t	net;
	uint8_t		node[IPX_NODE_ADDR_LEN];
	uint16_t	socket;
} ascend_ipx_net_t;

/*
 *	ascend_ipx_filter_t
 *
 *	The binary format of an IPX filter.  ALL fields are stored in
 *	network byte order.
 *
 *	src:		Source net, node, and socket.
 *
 *	dst:		Destination net, node, and socket.
 *
 *	srcSocComp:     Source socket compare value
 *
 *	dstSocComp:     Destination socket compare value
 */
typedef struct {
	ascend_ipx_net_t src;
	ascend_ipx_net_t dst;
	uint8_t		srcSocComp;
	uint8_t		dstSocComp;
} ascend_ipx_filter_t;


/*
 *	ascend_generic_filter_t
 *
 *	The binary format of a GENERIC filter.  ALL fields are stored in
 *	network byte order.
 *
 *	offset:		Number of bytes into packet to start comparison.
 *
 *	len:		Number of bytes to mask and compare.  May not
 *			exceed RAD_MAX_FILTER_LEN.
 *
 *	more:		Boolean.  If non-zero the next filter entry is
 *			also to be applied to a packet.
 *
 *	mask:		A bit mask specifying the bits to compare.
 *
 *	value:		A value to compare against the masked bits at
 *			offset in a users packet.
 *
 *	compNeq:	Defines type of comarison (Equal or Notequal)
 *			default is Equal.
 *
 *	fill:		Round things out to a dword boundary
 */
typedef struct {
	uint16_t	offset;
	uint16_t	len;
	uint16_t	more;
	uint8_t		mask[ RAD_MAX_FILTER_LEN ];
	uint8_t		value[ RAD_MAX_FILTER_LEN ];
	uint8_t		compNeq;
	uint8_t		fill[3];	/* used to be fill[1] */
} ascend_generic_filter_t;

/*
 *	ascend_filter_t
 *
 *	A binary filter element.  Contains one of ascend_ip_filter_t,
 *	ascend_ipx_filter_t, or ascend_generic_filter_t.
 *
 *	All fields are stored in network byte order.
 *
 *	type:		Either ASCEND_FILTER_GENERIC or ASCEND_FILTER_IP.
 *
 *	forward:	true if we should forward packets that match this
 *			filter, false if we should drop packets that match
 *			this filter.
 *
 *	direction:	true if this is an input filter, false if this is
 *			an output filter.
 *
 *	fill:		Round things out to a dword boundary.
 *
 *	u:		A union of
 *			ip:		An ip filter entry
 *			generic:	A generic filter entry
 */
typedef struct {
	uint8_t 	type;
	uint8_t		forward;
	uint8_t		direction;
	uint8_t		fill;
	union {
		ascend_ip_filter_t   	 ip;
		ascend_ipx_filter_t   	 ipx;
		ascend_generic_filter_t	generic;
		uint8_t			data[28]; /* ensure it's 32 bytes */
	} u;
} ascend_filter_t;

/*
 *	This is a wild C hack...
 */
typedef struct {
	char data[(sizeof(ascend_filter_t) == 32) ? 1 : -1 ];
} _cpp_hack;

/*
 * FilterPortType:
 *
 * Ascii names of some well known tcp/udp services.
 * Used for filtering on a port type.
 *
 * ??? What the heck is wrong with getservbyname?
 */
static fr_table_num_sorted_t const filterPortType[] = {
	{ L("cmd"),	514 },
	{ L("domain"),	53 },
	{ L("exec"),	512 },
	{ L("finger"),	79 },
	{ L("ftp"),	21 },
	{ L("ftp-data"),   20 },
	{ L("gopher"),	70 },
	{ L("hostname"),	101 },
	{ L("kerberos"),	88 },
	{ L("login"),	513 },
	{ L("nameserver"), 42 },
	{ L("nntp"),	119 },
	{ L("ntp"),	123 },
	{ L("smtp"),	25 },
	{ L("talk"),	517 },
	{ L("telnet"),	23 },
	{ L("tftp"),	69 },
	{ L("www"),	80 }
};
static size_t filterPortType_len = NUM_ELEMENTS(filterPortType);

static fr_table_num_sorted_t const filterType[] = {
	{ L("generic"),	ASCEND_FILTER_GENERIC},
	{ L("ip"), 	ASCEND_FILTER_IP},
	{ L("ipx"), 	ASCEND_FILTER_IPX}
};
static size_t filterType_len = NUM_ELEMENTS(filterType);

typedef enum {
	FILTER_GENERIC_TYPE,
	FILTER_IP_TYPE,
	FILTER_IN,
	FILTER_OUT,
	FILTER_FORWARD,
	FILTER_DROP,
	FILTER_GENERIC_OFFSET,
	FILTER_GENERIC_MASK,
	FILTER_GENERIC_VALUE,
	FILTER_GENERIC_COMPNEQ,
	FILTER_GENERIC_COMPEQ,
	FILTER_MORE,
	FILTER_IP_DST,
	FILTER_IP_SRC,
	FILTER_IP_PROTO,
	FILTER_IP_DST_PORT,
	FILTER_IP_SRC_PORT,
	FILTER_EST,
	FILTER_IPX_TYPE,
	FILTER_IPX_DST_IPXNET,
	FILTER_IPX_DST_IPXNODE,
	FILTER_IPX_DST_IPXSOCK,
	FILTER_IPX_SRC_IPXNET,
	FILTER_IPX_SRC_IPXNODE,
	FILTER_IPX_SRC_IPXSOCK
} FilterTokens;


static fr_table_num_sorted_t const filterKeywords[] = {
	{ L("!="),		FILTER_GENERIC_COMPNEQ },
	{ L("=="),		FILTER_GENERIC_COMPEQ  },
	{ L("drop"),	FILTER_DROP },
	{ L("dstip"),  	FILTER_IP_DST },
	{ L("dstipxnet"),	FILTER_IPX_DST_IPXNET  },
	{ L("dstipxnode"),	FILTER_IPX_DST_IPXNODE  },
	{ L("dstipxsock"),	FILTER_IPX_DST_IPXSOCK  },
	{ L("dstport"),	FILTER_IP_DST_PORT },
	{ L("est"),	FILTER_EST },
	{ L("forward"),	FILTER_FORWARD },
	{ L("generic"),	FILTER_GENERIC_TYPE },
	{ L("in"), 	FILTER_IN },
	{ L("ip"), 	FILTER_IP_TYPE },
	{ L("ipx"),	FILTER_IPX_TYPE  },
	{ L("more"),	FILTER_MORE },
	{ L("out"),	FILTER_OUT },
	{ L("srcip"),  	FILTER_IP_SRC },
	{ L("srcipxnet"),	FILTER_IPX_SRC_IPXNET  },
	{ L("srcipxnode"),	FILTER_IPX_SRC_IPXNODE  },
	{ L("srcipxsock"),	FILTER_IPX_SRC_IPXSOCK  },
	{ L("srcport"),	FILTER_IP_SRC_PORT }
};
static size_t filterKeywords_len = NUM_ELEMENTS(filterKeywords);

/*
 * FilterProtoName:
 *
 * Ascii name of protocols used for filtering.
 *
 *  ??? What the heck is wrong with getprotobyname?
 */
static fr_table_num_sorted_t const filterProtoName[] = {
	{ L("0"),	  0 },
	{ L("icmp"), 1 },
	{ L("ospf"), 89 },
	{ L("tcp"),  6 },
	{ L("udp"),  17 }
};
static size_t filterProtoName_len = NUM_ELEMENTS(filterProtoName);


/*
 * RadFilterComparison:
 *
 * An enumerated values for the IP filter port comparisons.
 */
typedef enum {
	RAD_NO_COMPARE = 0,
	RAD_COMPARE_LESS,
	RAD_COMPARE_EQUAL,
	RAD_COMPARE_GREATER,
	RAD_COMPARE_NOT_EQUAL
} RadFilterComparison;

static fr_table_num_sorted_t const filterCompare[] = {
	{ L("!="), RAD_COMPARE_NOT_EQUAL	},
	{ L("<"),	RAD_COMPARE_LESS	},
	{ L("="),	RAD_COMPARE_EQUAL	},
	{ L(">"),	RAD_COMPARE_GREATER	}
};
static size_t filterCompare_len = NUM_ELEMENTS(filterCompare);


/*
 *	ascend_parse_ipx_net
 *
 *	srcipxnet nnnn srcipxnode mmmmm [srcipxsoc cmd value ]
 */
static int ascend_parse_ipx_net(int argc, char **argv,
				ascend_ipx_net_t *net, uint8_t *comp)
{
	int		token;
	char const	*p;

	if (argc < 3) return -1;

	/*
	 *	Parse the net, which is a hex number.
	 */
	net->net = htonl(strtol(argv[0], NULL, 16));

	/*
	 *	Parse the node.
	 */
	token = fr_table_value_by_str(filterKeywords, argv[1], -1);
	switch (token) {
	case FILTER_IPX_SRC_IPXNODE:
	case FILTER_IPX_DST_IPXNODE:
		break;

	default:
		return -1;
	}

	/*
	 *	Can have a leading "0x" or "0X"
	 */
	p = argv[2];
	if ((memcmp(p, "0X", 2) == 0) ||
	    (memcmp(p, "0x", 2) == 0)) p += 2;

	/*
	 *	Node must be 6 octets long.
	 */
	token = fr_hex2bin(NULL,
			   &FR_DBUFF_TMP(net->node, IPX_NODE_ADDR_LEN),
			   &FR_SBUFF_IN(p, strlen(p)), false);
	if (token != IPX_NODE_ADDR_LEN) return -1;

	/*
	 *	Nothing more, die.
	 */
	if (argc == 3) return 3;

	/*
	 *	Can't be too little or too much.
	 */
	if (argc != 6) return -1;

	/*
	 *	Parse the socket.
	 */
	token = fr_table_value_by_str(filterKeywords, argv[3], -1);
	switch (token) {
	case FILTER_IPX_SRC_IPXSOCK:
	case FILTER_IPX_DST_IPXSOCK:
		break;

	default:
		return -1;
	}

	/*
	 *	Parse the command "<", ">", "=" or "!="
	 */
	token = fr_table_value_by_str(filterCompare, argv[4], -1);
	switch (token) {
	case RAD_COMPARE_LESS:
	case RAD_COMPARE_EQUAL:
	case RAD_COMPARE_GREATER:
	case RAD_COMPARE_NOT_EQUAL:
		*comp = token;
		break;

	default:
		return -1;
	}

	/*
	 *	Parse the value.
	 */
	token = strtoul(argv[5], NULL, 16);
	if (token > 65535) return -1;

	net->socket = token;
	net->socket = htons(net->socket);


	/*
	 *	Everything's OK, we parsed 6 entries.
	 */
	return 6;
}

/*
 *	ascend_parse_ipx_filter
 *
 *	This routine parses an IPX filter string from a string.
 *	The format of the string is:
 *
 *	[ srcipxnet nnnn srcipxnode mmmmm [srcipxsoc cmd value ]]
 * 	[ dstipxnet nnnn dstipxnode mmmmm [dstipxsoc cmd value ]]
 *
 * Fields in [...] are optional.
 *	where:
 *
 *  srcipxnet:      Keyword for source IPX address.
 *		  nnnn = IPX Node address.
 *
 *  srcipxnode:     Keyword for source IPX Node address.
 *		  mmmmm = IPX Node Address, could be FFFFFF.
 *		  A vlid ipx node number should accompany ipx net number.
 *
 *	srcipxsoc:      Keyword for source IPX socket address.
 *
 *	cmd:	    One of ">" or "<" or "=" or "!=".
 *
 *	value:	  Socket value to be compared against, in hex.
 *
 *	dstipxnet:	Keyword for destination IPX address.
 *			nnnn = IPX Node address.
 *
 *	dstipxnode:	Keyword for destination IPX Node address.
 *  		mmmmm = IPX Node Address, could be FFFFFF.
 *		       A valid ipx node number should accompany ipx net number.
 *
 *	dstipxsoc:	Keyword for destination IPX socket address.
 *
 *	cmd:		One of ">" or "<" or "=" or "!=".
 *
 *	value:		Socket value to be compared against, in hex.
 */
static int ascend_parse_ipx(int argc, char **argv, ascend_ipx_filter_t *filter)
{
	int rcode;
	int token;
	int flags = 0;

	/*
	 *	We may have nothing, in which case we simply return.
	 */
	if (argc == 0) return 0;

	/*
	 *	Must have "net N node M"
	 */
	if (argc < 4) return -1;

	while ((argc > 0) && (flags != 0x03)) {
		token = fr_table_value_by_str(filterKeywords, argv[0], -1);
		switch (token) {
		case FILTER_IPX_SRC_IPXNET:
			if (flags & 0x01) return -1;
			rcode = ascend_parse_ipx_net(argc - 1, argv + 1,
						     &(filter->src),
						     &(filter->srcSocComp));
			if (rcode < 0) return -1;
			argc -= (rcode + 1);
			argv += rcode + 1;
			flags |= 0x01;
			break;

		case FILTER_IPX_DST_IPXNET:
			if (flags & 0x02) return -1;
			rcode = ascend_parse_ipx_net(argc - 1, argv + 1,
						     &(filter->dst),
						     &(filter->dstSocComp));
			if (rcode < 0) return -1;
			argc -= (rcode + 1);
			argv += rcode + 1;
			flags |= 0x02;
			break;

		default:
			fr_strerror_printf("Unknown string \"%s\" in IPX data filter",
				   argv[0]);
			return -1;
		}
	}

	/*
	 *	Arguments left over: die.
	 */
	if (argc != 0) return -1;

	/*
	 *	Everything's OK.
	 */
	return 0;
}


/*
 *	Parse an IP address and optionally a netmask, to a uint32_t.
 *
 *	ipaddr should already be initialized to zero.
 *	ipaddr is in network byte order.
 *
 *	Returns -1 on failure, or the number of bits in the netmask, otherwise.
 */
static int ascend_parse_ipaddr(uint32_t *ipaddr, char *str)
{
	int		count = 0;
	int		ip[4];
	int	     masklen;
	uint32_t	netmask = 0;

	/*
	 *	Look for IP's.
	 */
	count = 0;
	while (*str && (count < 4) && (netmask == 0)) {
	next:
		ip[count] = 0;

		while (*str) {
			switch (*str) {
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
			case '8': case '9':
				ip[count] *= 10;
				ip[count] += (*str) - '0';
				str++;
				break;


			case '.': /* dot between IP numbers. */
				str++;
				if (ip[count] > 255) return -1;

				/*
				 *	24, 16, 8, 0, done.
				 */
				*ipaddr |= (ip[count] << (8 * (3 - count)));
				count++;
				goto next;

			case '/': /* netmask  */
				str++;
				masklen = atoi(str);
				if ((masklen < 0) || (masklen > 32)) return -1;
				str += strspn(str, "0123456789");
				netmask = masklen;
				goto finalize;

			default:
				fr_strerror_printf("Invalid character in IP address");
				return -1;
			}
		} /* loop over one character */
	} /* loop until the count hits 4 */

	if (count == 3) {
	finalize:
		/*
		 *	Do the last one, too.
		 */
		if (ip[count] > 255) return -1;

		/*
		 *	24, 16, 8, 0, done.
		 */
		*ipaddr |= (ip[count] << (8 * (3 - count)));
	}

	/*
	 *	We've hit the end of the IP address, and there's something
	 *	else left over: die.
	 */
	if (*str) return -1;

	/*
	 *	Set the default netmask.
	 */
	if (!netmask) {
		if (!*ipaddr) {
			netmask = 0;
		} else if ((*ipaddr & 0x80000000) == 0) {
			netmask = 8;
		} else if ((*ipaddr & 0xc0000000) == 0x80000000) {
			netmask = 16;
		} else if ((*ipaddr & 0xe0000000) == 0xc0000000) {
			netmask = 24;
		} else {
			netmask = 32;
		}
	}

	*ipaddr = htonl(*ipaddr);
	return netmask;
}

/*
 *	ascend_parse_port:  Parse a comparator and port.
 *
 *	Returns -1 on failure, or the comparator.
 */
static int ascend_parse_port(uint16_t *port, char *compare, char *str)
{
	int rcode, token;

	/*
	 *	There MUST be a comparison string.
	 */
	rcode = fr_table_value_by_str(filterCompare, compare, -1);
	if (rcode < 0) return rcode;

	if (strspn(str, "0123456789") == strlen(str)) {
		token = atoi(str);
	} else {
		token = fr_table_value_by_str(filterPortType, str, -1);
	}

	if ((token < 0) || (token > 65535)) return -1;

	*port = token;
	*port = htons(*port);

	return rcode;
}


#define IP_SRC_ADDR_FLAG    (1 << 0)
#define IP_DEST_ADDR_FLAG   (1 << 1)
#define IP_SRC_PORT_FLAG    (1 << 2)
#define IP_DEST_PORT_FLAG   (1 << 3)
#define IP_PROTO_FLAG       (1 << 4)
#define IP_EST_FLAG	 (1 << 5)

#define DONE_FLAGS	(IP_SRC_ADDR_FLAG | IP_DEST_ADDR_FLAG | \
			IP_SRC_PORT_FLAG | IP_DEST_PORT_FLAG | \
			IP_PROTO_FLAG | IP_EST_FLAG)

/*
 *	ascend_parse_ip:
 *
 *	This routine parses an IP filter string from a RADIUS
 *	reply. The format of the string is:
 *
 *	ip dir action [ dstip n.n.n.n/nn ] [ srcip n.n.n.n/nn ]
 *	    [ proto [ dstport cmp value ] [ srcport cmd value ] [ est ] ]
 *
 *	Fields in [...] are optional.
 *
 *	dstip:		Keyword for destination IP address.
 *			n.n.n.n = IP address. /nn - netmask.
 *
 *	srcip:		Keyword for source IP address.
 *			n.n.n.n = IP address. /nn - netmask.
 *
 *	proto:		Optional protocol field. Either a name or
 *			number. Known names are in FilterProtoName[].
 *
 *	dstport:	Keyword for destination port. Only valid with tcp
 *			or udp. 'cmp' are in FilterPortType[]. 'value' can be
 *			a name or number.
 *
 *	srcport:	Keyword for source port. Only valid with tcp
 *			or udp. 'cmp' are in FilterPortType[]. 'value' can be
 *			a name or number.
 *
 *	est:		Keyword for TCP established. Valid only for tcp.
 *
 */
static int ascend_parse_ip(int argc, char **argv, ascend_ip_filter_t *filter)
{
	int rcode;
	int token;
	int flags;

	/*
	 *	We may have nothing, in which case we simply return.
	 */
	if (argc == 0) return 0;

	/*
	 *	There may, or may not, be src & dst IP's in the string.
	 */
	flags = 0;
	while ((argc > 0) && (flags != DONE_FLAGS)) {
		token = fr_table_value_by_str(filterKeywords, argv[0], -1);
		switch (token) {
		case FILTER_IP_SRC:
			if (flags & IP_SRC_ADDR_FLAG) return -1;
			if (argc < 2) return -1;

			rcode = ascend_parse_ipaddr(&filter->srcip, argv[1]);
			if (rcode < 0) return rcode;

			filter->srcmask = rcode;
			flags |= IP_SRC_ADDR_FLAG;
			argv += 2;
			argc -= 2;
			break;

		case FILTER_IP_DST:
			if (flags & IP_DEST_ADDR_FLAG) return -1;
			if (argc < 2) return -1;

			rcode = ascend_parse_ipaddr(&filter->dstip, argv[1]);
			if (rcode < 0) return rcode;

			filter->dstmask = rcode;
			flags |= IP_DEST_ADDR_FLAG;
			argv += 2;
			argc -= 2;
			break;

		case FILTER_IP_SRC_PORT:
			if (flags & IP_SRC_PORT_FLAG) return -1;
			if (argc < 3) return -1;

			rcode = ascend_parse_port(&filter->srcport,
						  argv[1], argv[2]);
			if (rcode < 0) return rcode;
			filter->srcPortComp = rcode;

			flags |= IP_SRC_PORT_FLAG;
			argv += 3;
			argc -= 3;
			break;

		case FILTER_IP_DST_PORT:
			if (flags & IP_DEST_PORT_FLAG) return -1;
			if (argc < 3) return -1;

			rcode = ascend_parse_port(&filter->dstport,
						  argv[1], argv[2]);
			if (rcode < 0) return rcode;
			filter->dstPortComp = rcode;

			flags |= IP_DEST_PORT_FLAG;
			argv += 3;
			argc -= 3;
			break;

		case FILTER_EST:
			if (flags & IP_EST_FLAG) return -1;
			filter->established = 1;
			argv++;
			argc--;
			flags |= IP_EST_FLAG;
			break;

		default:
			if (flags & IP_PROTO_FLAG) return -1;
			if (strspn(argv[0], "0123456789") == strlen(argv[0])) {
				token = atoi(argv[0]);
			} else {
				token = fr_table_value_by_str(filterProtoName, argv[0], -1);
				if (token == -1) {
					fr_strerror_printf("Unknown IP protocol \"%s\" in IP data filter",
						   argv[0]);
					return -1;
				}
			}
			filter->proto = token;
			flags |= IP_PROTO_FLAG;

			argv++;
			argc--;
			break;
		}
	}

	/*
	 *	We should have parsed everything by now.
	 */
	if (argc != 0) {
		fr_strerror_printf("Unknown extra string \"%s\" in IP data filter",
			   argv[0]);
		return -1;
	}

	return 0;
}


/*
 *	ascend_parse_generic
 *
 *	This routine parses a Generic filter string from a RADIUS
 *	reply. The format of the string is:
 *
 *	generic dir action offset mask value [== or != ] [more]
 *
 *	Fields in [...] are optional.
 *
 *	offset:		A Number. Specifies an offset into a frame
 *			to start comparing.
 *
 *	mask:		A hexadecimal mask of bits to compare.
 *
 *	value:		A value to compare with the masked data.
 *
 *	compNeq:	Defines type of comparison. ( "==" or "!=")
 *			Default is "==".
 *
 *	more:		Optional keyword MORE, to represent the attachment
 *			to the next entry.
 */
static int ascend_parse_generic(int argc, char **argv,
				ascend_generic_filter_t *filter)
{
	int rcode;
	int token;
	int flags;

	/*
	 *	We may have nothing, in which case we simply return.
	 */
	if (argc == 0) return 0;

	/*
	 *	We need at least "offset mask value"
	 */
	if (argc < 3) return -1;

	/*
	 *	No more than optional comparison and "more"
	 */
	if (argc > 5) return -1;

	/*
	 *	Offset is a uint16_t number.
	 */
	if (strspn(argv[0], "0123456789") != strlen(argv[0])) return -1;

	rcode = atoi(argv[0]);
	if (rcode > 65535) return -1;

	filter->offset = rcode;
	filter->offset = htons(filter->offset);

	rcode = fr_hex2bin(NULL,
			   &FR_DBUFF_TMP(filter->mask, sizeof(filter->mask)),
			   &FR_SBUFF_IN(argv[1], strlen(argv[1])), false);
	if (rcode != sizeof(filter->mask)) return -1;

	token = fr_hex2bin(NULL,
			   &FR_DBUFF_TMP(filter->value, sizeof(filter->value)),
			   &FR_SBUFF_IN(argv[2], strlen(argv[2])), false);
	if (token != sizeof(filter->value)) return -1;

	filter->len = rcode;
	filter->len = htons(filter->len);

	/*
	 *	Nothing more.  Exit.
	 */
	if (argc == 3) return 0;

	argc -= 3;
	argv += 3;
	flags = 0;

	while (argc >= 1) {
		token = fr_table_value_by_str(filterKeywords, argv[0], -1);
		switch (token) {
		case FILTER_GENERIC_COMPNEQ:
			if (flags & 0x01) return -1;
			filter->compNeq = true;
			flags |= 0x01;
			break;
		case FILTER_GENERIC_COMPEQ:
			if (flags & 0x01) return -1;
			filter->compNeq = false;
			flags |= 0x01;
			break;

		case FILTER_MORE:
			if (flags & 0x02) return -1;
			filter->more = htons( 1 );
			flags |= 0x02;
			break;

		default:
			fr_strerror_printf("Invalid string \"%s\" in generic data filter",
				   argv[0]);
			return -1;
		}

		argc--;
		argv++;
	}

	return 0;
}


/** Filter binary
 *
 * This routine will call routines to parse entries from an ASCII format
 * to a binary format recognized by the Ascend boxes.
 *
 * @param out Where to write parsed filter.
 * @param value ascend filter text.
 * @param len of value.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int ascend_parse_filter(fr_value_box_t *out, char const *value, size_t len)
{
	int		token, type;
	int		rcode;
	int		argc;
	char		*argv[32];
	ascend_filter_t filter;
	char		*p;

	rcode = -1;

	/*
	 *	Tokenize the input string in the VP.
	 *
	 *	Once the filter is *completely* parsed, then we will
	 *	over-write it with the final binary filter.
	 */
	p = talloc_bstrndup(NULL, value, len);

	/*
	 *	Rather than printing specific error messages, we create
	 *	a general one here, which won't be used if the function
	 *	returns OK.
	 */
	fr_strerror_printf("Failed parsing \"%s\" as ascend filer", p);

	argc = fr_dict_str_to_argv(p, argv, 32);
	if (argc < 3) {
		talloc_free(p);
		return -1;
	}

	/*
	 *	Decide which filter type it is: ip, ipx, or generic
	 */
	type = fr_table_value_by_str(filterType, argv[0], -1);
	memset(&filter, 0, sizeof(filter));

	/*
	 *	Validate the filter type.
	 */
	switch (type) {
	case ASCEND_FILTER_GENERIC:
	case ASCEND_FILTER_IP:
	case ASCEND_FILTER_IPX:
		filter.type = type;
		break;

	default:
		fr_strerror_printf("Unknown Ascend filter type \"%s\"", argv[0]);
		talloc_free(p);
		return -1;
	}

	/*
	 *	Parse direction
	 */
	token = fr_table_value_by_str(filterKeywords, argv[1], -1);
	switch (token) {
	case FILTER_IN:
		filter.direction = 1;
		break;

	case FILTER_OUT:
		filter.direction = 0;
		break;

	default:
		fr_strerror_printf("Unknown Ascend filter direction \"%s\"", argv[1]);
		talloc_free(p);
		return -1;
	}

	/*
	 *	Parse action
	 */
	token = fr_table_value_by_str(filterKeywords, argv[2], -1);
	switch (token) {
	case FILTER_FORWARD:
		filter.forward = 1;
		break;

	case FILTER_DROP:
		filter.forward = 0;
		break;

	default:
		fr_strerror_printf("Unknown Ascend filter action \"%s\"", argv[2]);
		talloc_free(p);
		return -1;
	}


	switch (type) {
	case ASCEND_FILTER_GENERIC:
		rcode = ascend_parse_generic(argc - 3, &argv[3], &filter.u.generic);
		break;

	case ASCEND_FILTER_IP:
		rcode = ascend_parse_ip(argc - 3, &argv[3], &filter.u.ip);
		break;

	case ASCEND_FILTER_IPX:
		rcode = ascend_parse_ipx(argc - 3, &argv[3], &filter.u.ipx);
		break;
	}

	/*
	 *	Touch the VP only if everything was OK.
	 */
	if (rcode == 0) memcpy(out->datum.filter, &filter, sizeof(filter));
	talloc_free(p);

	return rcode;
}

/** Print an Ascend binary filter attribute to a string,
 *
 * Grrr... Ascend makes the server do this work, instead of doing it on the NAS.
 *
 * @param[out] need	The number of bytes required to print the next part
 *      		of the string.
 * @param[out] out	Buffer to write the string to.
 * @param[in] outlen	Length of the output buffer, should be at least 1k.
 * @param[in] in	Data to print as filter string.
 * @param[in] inlen	The length of the data we're printing.
 * @param[in] quote	A quote character to append and prepend to the output string.
 * @return
 *	- The amount of data written to out.  If truncation occurs *need will be > 0.
 */
size_t print_abinary(size_t *need, char *out, size_t outlen, uint8_t const *in, size_t inlen, int8_t quote)
{
	size_t 			len, i;
	char			*p = out;
	char			*end = p + outlen;
	ascend_filter_t	const	*filter;

	static char const *action[] = {"drop", "forward"};
	static char const *direction[] = {"out", "in"};

	RETURN_IF_NO_SPACE_INIT(need, 1, p, out, end);

	/*
	 *  Just for paranoia: wrong size filters get printed as octets
	 */
	if (inlen != sizeof(*filter)) {
		p += strlcpy(p, "0x", end - p);

		for (i = 0; i < inlen; i++) {
			len = snprintf(p, end - p, "%02x", in[i]);
			RETURN_IF_TRUNCATED(need, len, p, out, end);
		}
		return p - out;
	}

	if (quote > 0) {
		RETURN_IF_NO_SPACE(need, 1, p, out, end);
		*(p++) = (char) quote;
	}

	filter = (ascend_filter_t const *) in;
	len = snprintf(p, end - p, "%s %s %s", fr_table_str_by_value(filterType, filter->type, "??"),
		       direction[filter->direction & 0x01], action[filter->forward & 0x01]);
	RETURN_IF_TRUNCATED(need, len, p, out, end);

	switch ((ascend_filter_type_t)filter->type) {
	/*
	 *	Handle IP filters
	 */
	case ASCEND_FILTER_IP:
		if (filter->u.ip.srcip) {
			len = snprintf(p, end - p, " srcip %d.%d.%d.%d/%d",
				       ((uint8_t const *) &filter->u.ip.srcip)[0],
				       ((uint8_t const *) &filter->u.ip.srcip)[1],
				       ((uint8_t const *) &filter->u.ip.srcip)[2],
				       ((uint8_t const *) &filter->u.ip.srcip)[3],
				       filter->u.ip.srcmask);
			RETURN_IF_TRUNCATED(need, len, p, out, end);
		}

		if (filter->u.ip.dstip) {
			len = snprintf(p, end - p, " dstip %d.%d.%d.%d/%d",
				       ((uint8_t const *) &filter->u.ip.dstip)[0],
				       ((uint8_t const *) &filter->u.ip.dstip)[1],
				       ((uint8_t const *) &filter->u.ip.dstip)[2],
				       ((uint8_t const *) &filter->u.ip.dstip)[3],
				       filter->u.ip.dstmask);
			RETURN_IF_TRUNCATED(need, len, p, out, end);
		}

		len = snprintf(p, end - p, " %s", fr_table_str_by_value(filterProtoName, filter->u.ip.proto, "??"));
		RETURN_IF_TRUNCATED(need, len, p, out, end);

		if (filter->u.ip.srcPortComp > RAD_NO_COMPARE) {
			len = snprintf(p, end - p, " srcport %s %d",
				       fr_table_str_by_value(filterCompare, filter->u.ip.srcPortComp, "??"),
				       ntohs(filter->u.ip.srcport));
			RETURN_IF_TRUNCATED(need, len, p, out, end);
		}

		if (filter->u.ip.dstPortComp > RAD_NO_COMPARE) {
			len = snprintf(p, end - p, " dstport %s %d",
				       fr_table_str_by_value(filterCompare, filter->u.ip.dstPortComp, "??"),
				       ntohs(filter->u.ip.dstport));
			RETURN_IF_TRUNCATED(need, len, p, out, end);
		}

		if (filter->u.ip.established) {
			len = snprintf(p, end - p, " est");
			RETURN_IF_TRUNCATED(need, len, p, out, end);
		}
		break;
	/*
	 *	Handle IPX filters
	 */
	case ASCEND_FILTER_IPX:
		/* print for source */
		if (filter->u.ipx.src.net) {
			len = snprintf(p, end - p, " srcipxnet 0x%04x srcipxnode 0x%02x%02x%02x%02x%02x%02x",
				       (unsigned int)ntohl(filter->u.ipx.src.net),
				       filter->u.ipx.src.node[0], filter->u.ipx.src.node[1],
				       filter->u.ipx.src.node[2], filter->u.ipx.src.node[3],
				       filter->u.ipx.src.node[4], filter->u.ipx.src.node[5]);
			RETURN_IF_TRUNCATED(need, len, p, out, end);

			if (filter->u.ipx.srcSocComp > RAD_NO_COMPARE) {
				len = snprintf(p, end - p, " srcipxsock %s 0x%04x",
					       fr_table_str_by_value(filterCompare, filter->u.ipx.srcSocComp, "??"),
					       ntohs(filter->u.ipx.src.socket));
				RETURN_IF_TRUNCATED(need, len, p, out, end);
			}
		}

		/* same for destination */
		if (filter->u.ipx.dst.net) {
			len = snprintf(p, end - p, " dstipxnet 0x%04x dstipxnode 0x%02x%02x%02x%02x%02x%02x",
				       (unsigned int)ntohl(filter->u.ipx.dst.net),
				       filter->u.ipx.dst.node[0], filter->u.ipx.dst.node[1],
				       filter->u.ipx.dst.node[2], filter->u.ipx.dst.node[3],
				       filter->u.ipx.dst.node[4], filter->u.ipx.dst.node[5]);
			RETURN_IF_TRUNCATED(need, len, p, out, end);

			if (filter->u.ipx.dstSocComp > RAD_NO_COMPARE) {
				len = snprintf(p, end - p, " dstipxsock %s 0x%04x",
					       fr_table_str_by_value(filterCompare, filter->u.ipx.dstSocComp, "??"),
					       ntohs(filter->u.ipx.dst.socket));
				RETURN_IF_TRUNCATED(need, len, p, out, end);
			}
		}
		break;

	case ASCEND_FILTER_GENERIC:
	{
		int count;

		len = snprintf(p, end - p, " %u ", (unsigned int) ntohs(filter->u.generic.offset));
		RETURN_IF_TRUNCATED(need, len, p, out, end);

		/* show the mask */
		for (count = 0; count < ntohs(filter->u.generic.len); count++) {
			len = snprintf(p, end - p, "%02x", filter->u.generic.mask[count]);
			RETURN_IF_TRUNCATED(need, len, p, out, end);
		}

		p += strlcpy(p, " ", end - p);

		/* show the value */
		for (count = 0; count < ntohs(filter->u.generic.len); count++) {
			len = snprintf(p, end - p, "%02x", filter->u.generic.value[count]);
			RETURN_IF_TRUNCATED(need, len, p, out, end);
		}

		len = snprintf(p, end - p, " %s", (filter->u.generic.compNeq) ? "!=" : "==");
		RETURN_IF_TRUNCATED(need, len, p, out, end);

		if (filter->u.generic.more != 0) {
			len = snprintf(p, end - p, " more");
			RETURN_IF_TRUNCATED(need, len, p, out, end);
		}
	}
		break;

	default:
		break;
	}

	if (quote > 0) {
		RETURN_IF_NO_SPACE(need, 1, p, out, end);
		*(p++) = (char) quote;
	}
	*p = '\0';

	return p - out;
}

#endif
