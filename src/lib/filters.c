/*
 * ASCEND: @(#)filters.c	1.3 (95/07/25 00:55:30)
 *
 *      Copyright (c) 1994 Ascend Communications, Inc.
 *      All rights reserved.
 *
 *	Permission to copy all or part of this material for any purpose is
 *	granted provided that the above copyright notice and this paragraph
 *	are duplicated in all copies.  THIS SOFTWARE IS PROVIDED ``AS IS''
 *	AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 *	LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *	FOR A PARTICULAR PURPOSE.
 */

/* $Id$ */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/time.h>	/* gettimeofday() */

#include "libradius.h"

#define PRINTF( x ) if (librad_debug) librad_log x

#define NO_TOKEN -1

/*
 * Two types of filters are supported, GENERIC and IP.  The identifiers
 * are:
 */

#define RAD_FILTER_GENERIC	0
#define RAD_FILTER_IP		1
#define RAD_FILTER_IPX		2

/*
 * Generic filters mask and match up to RAD_MAX_FILTER_LEN bytes
 * starting at some offset.  The length is:
 */
#define RAD_MAX_FILTER_LEN	6

/*
 * ASCEND extensions for ABINARY filters
 */

#define IPX_NODE_ADDR_LEN		6

typedef UINT4			IpxNet;
typedef unsigned char		IpxNode[ IPX_NODE_ADDR_LEN ];
typedef unsigned short		IpxSocket;

#if ! defined( FALSE )
# define FALSE		0
# define TRUE		(! FALSE)
#endif

/*
 * RadFilterComparison:
 *
 * An enumerated values for the IP filter port comparisons.
 */
typedef enum {
	RAD_NO_COMPARE,
	RAD_COMPARE_LESS,
	RAD_COMPARE_EQUAL,
	RAD_COMPARE_GREATER,
	RAD_COMPARE_NOT_EQUAL
} RadFilterComparison;

    /*
     * RadIpFilter:
     *
     * The binary format of an IP filter.  ALL fields are stored in
     * network byte order.
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
     *	establised:	A boolean value.  TRUE when we care about the
     *			established state of a TCP connection.  FALSE when
     *			we dont care.
     *
     *	srcport:	TCP or UDP source port number.
     *
     *	dstport:	TCP or UDP destination port number.
     *
     *	srcPortCmp:	One of the values of the RadFilterComparison enumeration
     *			specifying how to compare the srcport value.
     *
     *	dstPortCmp:	One of the values of the RadFilterComparison enumeration
     *			specifying how to compare the dstport value.
     *
     *	fill:		Round things out to a dword boundary.
     */
typedef struct radip {
    UINT4  		srcip;
    UINT4  		dstip;
    unsigned char 	srcmask;
    unsigned char 	dstmask;
    unsigned char	proto;
    unsigned char	established;
    unsigned short	srcport;
    unsigned short	dstport;
    unsigned char	srcPortComp;
    unsigned char	dstPortComp;
    unsigned char       fill[4];        /* used to be fill[2] */
} RadIpFilter;

    /*
     * RadIpxFilter:
     * The binary format of a GENERIC filter.  ALL fields are stored in
     * network byte order.
     *
     *  srcIpxNet:      Source IPX Net address
     *
     *  srcIpxNode:     Source IPX Node address
     *
     *  srcIpxSoc:      Source IPX socket address
     *
     *  dstIpxNet:      Destination IPX Net address
     *
     *  dstIpxNode:     Destination IPX Node address
     *
     *  dstIpxSoc:      Destination IPX socket address
     *
     *  srcSocComp:     Source socket compare value
     *
     *  dstSocComp:     Destination socket compare value
     *
     */
typedef struct radipx {                         
    IpxNet              srcIpxNet;                      /* LongWord */
    IpxNode             srcIpxNode;                     /* Byte[6] */
    IpxSocket           srcIpxSoc;                      /* Word */
    IpxNet              dstIpxNet;                      /* LongWord */
    IpxNode             dstIpxNode;                     /* Byte[6] */
    IpxSocket           dstIpxSoc;                      /* Word */
    unsigned char       srcSocComp;
    unsigned char       dstSocComp;
} RadIpxFilter;

    /*
     * RadGenericFilter:
     *
     * The binary format of a GENERIC filter.  ALL fields are stored in
     * network byte order.
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
typedef struct radgeneric {
    unsigned short	offset;
    unsigned short	len;
    unsigned short	more;
    unsigned char	mask[ RAD_MAX_FILTER_LEN ];
    unsigned char	value[ RAD_MAX_FILTER_LEN ];
    unsigned char	compNeq;
    unsigned char       fill[3];        /* used to be fill */
} RadGenericFilter;

    /*
     * RadFilter:
     *
     * A binary filter element.  Contains either a RadIpFilter or a
     * RadGenericFilter.  All fields are stored in network byte order.
     *
     *	type:		Either RAD_FILTER_GENERIC or RAD_FILTER_IP.
     *
     *	forward:	TRUE if we should forward packets that match this
     *			filter, FALSE if we should drop packets that match
     *			this filter.
     *
     *	indirection:	TRUE if this is an input filter, FALSE if this is
     *			an output filter.
     *
     *	fill:		Round things out to a dword boundary.
     *
     *	u:		A union of
     *			ip:		An ip filter entry
     *			generic:	A generic filter entry
     */
typedef struct filter {
    unsigned char 	type;
    unsigned char	forward;
    unsigned char	indirection;
    unsigned char	fill;
    union {
	RadIpFilter   	 ip;
	RadIpxFilter   	 ipx;
	RadGenericFilter generic;
    } u;
} RadFilter;
#define SIZEOF_RADFILTER 26

typedef struct {
    const char*	name;
    int 	value;
} KeywordStruct;

    /*
     * FilterPortType:
     *
     * Ascii names of some well known tcp/udp services.
     * Used for filtering on a port type.
     *
     */

static KeywordStruct filterPortType[] = {
    { "ftp-data", 20 },
    { "ftp", 21 },
    { "telnet", 23 },
    { "smtp", 25 },
    { "nameserver", 42 },
    { "domain", 53 },
    { "tftp", 69 },
    { "gopher", 70 },
    { "finger", 79 },
    { "www", 80 },
    { "kerberos", 88 },
    { "hostname", 101 },
    { "nntp", 119 },
    { "ntp", 123 },
    { "exec", 512 },
    { "login", 513 },
    { "cmd", 514 },
    { "talk", 517 },
    {  NULL , NO_TOKEN },
};

typedef enum {
    FILTER_IP_TYPE,
    FILTER_GENERIC_TYPE,
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


static KeywordStruct filterKeywords[] = {
    { "ip", 	FILTER_IP_TYPE },
    { "generic",FILTER_GENERIC_TYPE },
    { "in", 	FILTER_IN },
    { "out",	FILTER_OUT },
    { "forward",FILTER_FORWARD },
    { "drop",	FILTER_DROP },
    { "dstip",  FILTER_IP_DST },
    { "srcip",  FILTER_IP_SRC },
    { "dstport",FILTER_IP_DST_PORT },
    { "srcport",FILTER_IP_SRC_PORT },
    { "est",	FILTER_EST },
    { "more",	FILTER_MORE },
    { "!=",	FILTER_GENERIC_COMPNEQ },
    { "==",	FILTER_GENERIC_COMPEQ  },
    { "ipx",	FILTER_IPX_TYPE  },
    { "dstipxnet",	FILTER_IPX_DST_IPXNET  },
    { "dstipxnode",	FILTER_IPX_DST_IPXNODE  },
    { "dstipxsock",	FILTER_IPX_DST_IPXSOCK  },
    { "srcipxnet",	FILTER_IPX_SRC_IPXNET  },
    { "srcipxnode",	FILTER_IPX_SRC_IPXNODE  },
    { "srcipxsock",	FILTER_IPX_SRC_IPXSOCK  },
    {  NULL , NO_TOKEN },
};

#define FILTER_DIRECTION 	0
#define FILTER_DISPOSITION	1
#define IP_FILTER_COMPLETE  	0x3	/* bits shifted by FILTER_DIRECTION */
					/* FILTER_DISPOSITION */

#define IPX_FILTER_COMPLETE      0x3     /* bits shifted by FILTER_DIRECTION */
                                        /* FILTER_DISPOSITION */

#define GENERIC_FILTER_COMPLETE 0x1c3	/* bits shifted for FILTER_DIRECTION */
					/* FILTER_DISPOSITION, FILTER_GENERIC_OFFSET*/
					/* FILTER_GENERIC_MASK, FILTER_GENERIC_VALUE*/

    /*
     * FilterProtoName:
     *
     * Ascii name of protocols used for filtering.
     *
     */
static KeywordStruct _filterProtoName[] = {
    { "tcp",  6 },
    { "udp",  17 },
    { "ospf", 89 },
    { "icmp", 1 },
    {  NULL , NO_TOKEN },
};

static KeywordStruct filterCompare[] = {
    { ">", RAD_COMPARE_GREATER },
    { "=", RAD_COMPARE_EQUAL },
    { "<", RAD_COMPARE_LESS },
    { "!=", RAD_COMPARE_NOT_EQUAL },
    {  NULL , NO_TOKEN },
};

static char	curString[512];

static int findKey ( char *string, KeywordStruct *list );
static int isAllDigit ( char *token );
static short a2octet ( char *tok, char *retBuf );
static char defaultNetmask ( unsigned long address );
static int ipAddressStringToValue ( char *string, unsigned long *ipAddress,
					 char *netmask);
static int parseIpFilter ( RadFilter *curEntry );
static int parseGenericFilter ( RadFilter *curEntry );
static int parseIpxFilter ( RadFilter *curEntry );
static int stringToNode   ( unsigned char* dest,  unsigned char* src );

    /*
     * findKey:
     *
     * Given a table of keywords, it will try and match string to an
     * entry. If it does it returns that keyword value. if no NO_TOKEN is
     * returned. A sanity check is made for upper case characters.
     *
     *	string:			Pointer to the token to match.
     *
     *	list:			Point to the list of keywords.
     *
     *	returns:		Keyword value on a match or NO_TOKEN.
     */
int findKey(char *string, KeywordStruct *list)
{
    short 	len;
    KeywordStruct*  entry;
    char	buf[80], *ptr;

    len = strlen( (char *) string );
    for( ptr = buf ; len; len--, string++ ) {
	if( isupper( *string ) ) {
	    *ptr++ = tolower( *string );
	} else {
	    *ptr++ = *string;
	}
    }
    *ptr = 0;
    entry = list;
    while( entry->name ) {
   	if( strcmp( entry->name, buf ) == 0 ) {
	    break;
	}
	entry++;
    }
    return( entry->value );
}

    /*
     * isAllDigit:
     *
     * Routine checks a string to make sure all values are digits.
     *
     *	token:			Pointer to sting to check.
     *
     * 	returns:		TRUE if all digits, or FALSE.
     *
     */

static int
isAllDigit(token)
char	*token;
{
    int i;

    i = strlen( (char *) token );
    while( i-- ) {
	if( isdigit( *token ) ) {
	    token++;
	} else {
	    break;
	}
    }
    if( i > 0 ) {
	return( FALSE );
    } 

    return( TRUE );
}

    /*
     * a2octet:
     *
     * Converts the ascii mask and value for generic filters into octets.
     * It also does a sanity check to see if the string is greater than
     * MAX_FILTER_LEN. It assumes the sting is hex with NO leading "0x"
     *
     *	tok:			Pointer to the string.
     *
     *  retBuf:			Pointer to place the octets.
     *
     *	returns:		Number of octects or -1 for error.
     * 
     */
static short
a2octet(tok, retBuf)
char	*tok;
char	*retBuf;
{
    short	rc, len, val, retLen, i;
    char	buf[ RAD_MAX_FILTER_LEN *2 ];
    char	*octet = buf;

    rc = -1;
    retLen = 0;

    if( ( len = strlen( (char*) tok ) ) <= ( RAD_MAX_FILTER_LEN*2 ) ) {
	retLen = len/2;
	if( len % 2 ) {
	    retLen++;
	}
	memset( buf, '\0', RAD_MAX_FILTER_LEN * 2 );
	for( ; len; len-- ) {
	    if( *tok <= '9' && *tok >= '0' ) {
		val = '0';
	        *octet++ = *tok++ - val;
	    } else if( isxdigit( *tok ) ) {
		if( *tok > 'Z' ) {
		    val = 'a';
		} else {
		    val = 'A';
		}
	        *octet++ = ( *tok++ - val ) + 10;
	    } else {
		break;	
	    }
	}
	if( !len ) {
	    /* merge the values */
	    for( i = 0; i < RAD_MAX_FILTER_LEN*2; i+=2 ) {
		*retBuf++ = (buf[i] << 4) | buf[i+1];
	    }
	}
    }

    if( len ) {
	rc = -1;
    } else {
	rc = retLen;
    }
    return( rc );
}



    /*
     * defaultNetmask:
     *
     *	Given an ip address this routine calculate a default netmask.
     *
     *	address:		Ip address.
     *
     *	returns:		Number of bits for the netmask
     *
     */
static char
defaultNetmask(address)
unsigned long	address;
{
    char netmask;

    if ( ! address ) {
	netmask = 0;
    } else if (( address & htonl( 0x80000000 ) ) == 0 ) {
	netmask = 8;
    } else if (( address & htonl( 0xc0000000 ) ) == htonl( 0x80000000 ) ) {
	netmask = 16;
    } else if (( address & htonl( 0xe0000000 ) ) == htonl( 0xc0000000 ) ) {
	netmask = 24;
    } else {
	netmask = 32;
    }
    return netmask;
}

		
static char ipAddressDigits[] = "1234567890./";
    /*
     * This functions attempts to convert an IP address in ASCII dot
     * with an optional netmask part to a pair of IpAddress.  Note:
     * An IpAddress is always stored in network byte order.
     *
     * Parameters:
     *
     *  string:		Pointer to a NULL terminated IP address in dot 
     *			notation followed by an optional /nn to indicate
     *			the number leading of bits in the netmask.
     * 
     *  ipAddress:	Pointer to an IpAddress where the converted
     *			address will be stored.
     *
     *	netmask:	Pointer to an IpAddress where the netmask
     *			will be stored.  If no netmask is passed as
     *			as part of the address the default netmask will
     *			be stored here.
     *
     * Returns:
     *	<>		TRUE if valid conversion, FALSE otherwise.
     *
     *	*ipAddress:	If function returns TRUE, the IP address in NBO.
     *	*netmask:	If function returns TRUE, the netmask in NBO.
     */

static int
ipAddressStringToValue(char *string, unsigned long *ipAddress,
	char *netmask)
{
    u_char*	dst;
    char*	cp;
    int		numDots;
    int		i;
    long	value;

    if ( ! string ) {
    	return(FALSE);
    }

    /* Allow an IP address to be blanked instead of forcing entry of
       0.0.0.0 -- the user will like it. */

    if ( *string == 0 ) {
	*ipAddress = 0;
	*netmask = 0;
	return TRUE;
    }

    /* First just count the number of dots in the address.  If there
       are more or less than three the address is invalid. */

    cp = string;
    numDots = 0;
    while( *cp ) {
	if( !strchr( ipAddressDigits, *cp) ) {
	    return( FALSE );
	}
	if ( *cp == '.') {
	    ++numDots;
	}
	++cp;
    }
    if ( numDots != 3 ) {
	return( FALSE );
    }

    dst = (u_char *) ipAddress;
    cp = string;

    for ( i = 0; i < sizeof( *ipAddress ); i++ ) {
	value = strtol( cp, (char**) &cp, 10 );
	if (( value < 0 ) || ( value > 255 )) {
	    return( FALSE );
	}
	*dst++ = (u_char) value;
	if ( *cp == '.' ) {
	    cp += 1;
	}
    }

    /* If there is a netmask part, parse it, otherwise figure out the
       default netmask for this class of address. */

    if ( *cp == '/' ) {
	value = strtol( cp + 1, (char**) &cp, 10 );
	if (( *cp != 0 ) || ( value < 0 ) || ( value > 32 )) {
	    return FALSE;
	}
	*netmask = (char) value;
    } else {
	*netmask = defaultNetmask( *ipAddress );
    }
    return TRUE;
}

    /*
     * Convert a 12 digit string representation of a hex data field to a
     * value.
     */
static int
stringToNode(dest, src )
unsigned char* 	dest;
unsigned char*  src;
{
    int         srcIx = 0;
    int         ix;
    int         nibble1;
    int         nibble2;
    int		temp;
    unsigned char *src1;

    src1 = (unsigned char *) strchr(src, 'x');

    if (src1 == NULL)
	src1 = (unsigned char *) strchr(src,'X');

    if (src1 == NULL)
	src1 = src;
    else
	src1++;

    /* skip any leading 0x or 0X 's */
    temp = strlen( (char*) src1 );
    if( strlen( (unsigned char*) src1 ) != ( IPX_NODE_ADDR_LEN * 2 ) ) {
        return( FALSE );
    }

    for ( ix = 0; ix < IPX_NODE_ADDR_LEN; ++ix ) {
        if ( src1[ srcIx ] <= '9' ) {
            nibble1 = src1[ srcIx ] & 0x0f;
        } else {
            nibble1 = (src1[ srcIx ] & 0x0f) + 9;
        }
        srcIx += 1;
        if ( src1[ srcIx ] <= '9' ) {
            nibble2 = src1[ srcIx ] & 0x0f;
        } else {
            nibble2 = (src1[ srcIx ] & 0x0f) + 9;
        }
        srcIx += 1;
        ((unsigned char *) dest)[ ix ] = (unsigned char) (nibble1 << 4) + nibble2;
    }

    return( TRUE );
}


    /*
     * parseIpxFilter:
     *
     * This routine parses an IPX filter string from a RADIUS
     * reply. The format of the string is:
     *
     *	ipx dir action [ srcipxnet nnnn srcipxnode mmmmm [srcipxsoc cmd value ]]
     * 	               [ dstipxnet nnnn dstipxnode mmmmm [dstipxsoc cmd value ]]
     *
     * Fields in [...] are optional.
     *	where:
     *
     *  ipx:		Keyword to designate an IPX filter. Actually this
     *			has been determined by parseFilter.
     *
     *	dir:		Filter direction. "IN" or "OUT"
     *
     *	action:		Filter action. "FORWARD" or "DROP"
     *
     *  srcipxnet:      Keyword for source IPX address.
     *                  nnnn = IPX Node address.
     *
     *  srcipxnode:     Keyword for source IPX Node address.
     *                  mmmmm = IPX Node Address, could be FFFFFF.
     *                  A vlid ipx node number should accompany ipx net number.
     *
     *  srcipxsoc:      Keyword for source IPX socket address.
     *
     *  cmd:            One of ">" or "<" or "=" or "!=".
     *
     *  value:          Socket value to be compared against, in hex. 
     *			
     *	dstipxnet:	Keyword for destination IPX address.
     *			nnnn = IPX Node address. 
     *			
     *	dstipxnode:	Keyword for destination IPX Node address.
     *  		mmmmm = IPX Node Address, could be FFFFFF.
     *			A vlid ipx node number should accompany ipx net number.
     *			
     *	dstipxsoc:	Keyword for destination IPX socket address.
     *			
     *	cmd:		One of ">" or "<" or "=" or "!=".
     *			
     *	value:		Socket value to be compared against, in hex.		
     *			
     *			
     * expects:
     *
     *	curEntry:	Pointer to place the filter structure
     *
     *	returns:	-1 for error or 0 for OK
     *	
     */

static int 
parseIpxFilter(curEntry)
RadFilter	*curEntry;
{
    unsigned long	elements = 0l;
    int			tok; 
    char*		token;
    RadIpxFilter*	ipx;

    token = (char *) strtok( NULL, " " ); 

    memset( curEntry, '\0', sizeof( RadFilter ) );
    curEntry->type = RAD_FILTER_IPX; 
    ipx = &curEntry->u.ipx;
 
    while( token ) {
  	tok = findKey( token, filterKeywords );
	switch( tok ) {
	    case FILTER_IN:
	    case FILTER_OUT:
		curEntry->indirection = tok == FILTER_IN ? TRUE: FALSE;
		PRINTF((" got FILTER %s ", tok == FILTER_IN?"IN":"OUT"));
	        elements |= (1 << FILTER_DIRECTION );
		break;

	    case FILTER_FORWARD:
	    case FILTER_DROP:
		PRINTF((" got FILTER %s ",
			tok == FILTER_DROP? "DROP":"FORWARD"));

	        elements |= (1 << FILTER_DISPOSITION );
		if( tok == FILTER_FORWARD ) {
		    curEntry->forward = TRUE;
		} else {
		    curEntry->forward = FALSE;
		}
		break;

	    case FILTER_IPX_DST_IPXNET:
	    case FILTER_IPX_SRC_IPXNET:
                PRINTF((" got FILTER_IPX %s IPXNET ",
                        tok == FILTER_IPX_DST_IPXNET ? "DST":"SRC"));
		token = (char *) strtok( NULL, " " );

		if ( token ) {
		    if( tok == FILTER_IPX_DST_IPXNET ) {
			ipx->dstIpxNet = ntohl( strtol( token, 0, 16 ));
			PRINTF(("D.Net: %08lX  token: %s \n", htonl(ipx->dstIpxNet), token));
		    } else {
			ipx->srcIpxNet = ntohl( strtol( token, 0, 16 ));
			PRINTF(("S Net: %08lX token: %s \n", htonl(ipx->srcIpxNet), token));
		    }
		    break;
		} 
		goto doneErr; 

            case FILTER_IPX_DST_IPXNODE:
            case FILTER_IPX_SRC_IPXNODE:
                PRINTF((" got FILTER_IPX %s IPXNODE ",
			tok == FILTER_IPX_DST_IPXNODE ? "DST":"SRC"));
		token = (char *) strtok( NULL, " " );

		if ( token ) {
		    if ( tok == FILTER_IPX_DST_IPXNODE) {
			stringToNode( (unsigned char *)ipx->dstIpxNode, (unsigned char*)token );
			PRINTF(("D. Node: %08lX%04X \n", 
				htonl((*(int *)(ipx->dstIpxNode))),
				htons((*(short *)(ipx->dstIpxNode+4)))));
		    } else {
			stringToNode( (unsigned char *)ipx->srcIpxNode, (unsigned char*)token );
			PRINTF(("S. Node: %08lX%04X \n", 
				htonl((*(int *)(ipx->srcIpxNode))),
				htons((*(short *)(ipx->srcIpxNode+4)))));
		    }
		    break;
		}
                goto doneErr;

            case FILTER_IPX_DST_IPXSOCK:
            case FILTER_IPX_SRC_IPXSOCK:
	    {
		RadFilterComparison cmp;

                PRINTF((" got FILTER_IPX %s IPXSOCK",
			tok == FILTER_IPX_DST_IPXSOCK ? "DST":"SRC"));
                token = (char *) strtok( NULL, " " );

		if ( token ) {
		    cmp = findKey( token, filterCompare );
		    PRINTF((" cmp value = %d \n", cmp ));
		    if( cmp != NO_TOKEN ) {
		    token = (char *) strtok( NULL, " " );
			if ( token ) {
			    if ( tok == FILTER_IPX_DST_IPXSOCK ) {
				ipx->dstSocComp = cmp;
				ipx->dstIpxSoc = 
			    ntohs( (IpxSocket) strtol( token, NULL, 16 ));
				PRINTF(("%X \n", htons(ipx->dstIpxSoc)));
			    } else {
				ipx->srcSocComp = cmp;
				ipx->srcIpxSoc 
				    = ntohs( (IpxSocket) strtol( token, NULL, 16 ));
				PRINTF(("%X \n", htons(ipx->srcIpxSoc)));
			    }
			    break;
			}
		    }
		}
		goto doneErr;
	     }

	    default:
		/* no keyword match */
		goto doneErr;
	}
        token = (char *) strtok( NULL, " " ); 
    } 

    if( elements == IPX_FILTER_COMPLETE ) {
	return( 0 );
    }

doneErr:
    PRINTF(( "RADIF: IPX Filter syntax error %s \n", token ));
    librad_log("ipx filter error: do not recognize %s in %s \n",
	      token, curString );
    return( -1 );
}

    /*
     * parseIpFilter:
     *
     * This routine parses an IP filter string from a RADIUS
     * reply. The format of the string is:
     *
     *	ip dir action [ dstip n.n.n.n/nn ] [ srcip n.n.n.n/nn ]
     *	    [ proto [ dstport cmp value ] [ srcport cmd value ] [ est ] ] 
     *
     * Fields in [...] are optional.
     *	where:
     *
     *  ip:		Keyword to designate an IP filter. Actually this
     *			has been determined by parseFilter.
     *
     *	dir:		Filter direction. "IN" or "OUT"
     *
     *	action:		Filter action. "FORWARD" or "DROP"
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
     *	dstpost:	Keyword for destination port. Only valid with tcp
     *			or udp. 'cmp' are in FilterPortType[]. 'value' can be
     *			a name or number.
     *
     *	srcpost:	Keyword for source port. Only valid with tcp
     *			or udp. 'cmp' are in FilterPortType[]. 'value' can be
     *			a name or number.
     *			
     *	est:		Keyword for TCP established. Valid only for tcp.
     *			
     * expects:
     *
     *	curEntry:	Pointer to place the filter structure
     *
     *	returns:	-1 for error or 0 for OK
     *	
     */

static int 
parseIpFilter(curEntry)
RadFilter	*curEntry;
{
 
    unsigned long	elements = 0l;
    int			tok; 
    char*		token;
    RadIpFilter*	ip;

    token = (char *) strtok( NULL, " " ); 

    PRINTF((" in ip  filter \n")); 

    memset( curEntry, '\0', sizeof( RadFilter ) );
    curEntry->type = RAD_FILTER_IP; 
    ip = &curEntry->u.ip;
    ip->established = FALSE;
 
    while( token ) {
	PRINTF((" token %s ", token ));
  	tok = findKey( token, filterKeywords );
	switch( tok ) {
	    case FILTER_IN:
	    case FILTER_OUT:
		curEntry->indirection = tok == FILTER_IN ? TRUE: FALSE;
		PRINTF((" got %s ", tok == FILTER_IN?"FILTER_IN":"FILTER_OUT"));
	        elements |= (1 << FILTER_DIRECTION );
		break;
	    case FILTER_FORWARD:
	    case FILTER_DROP:
		PRINTF((" got %s ", tok == FILTER_DROP?
			"FILTER_DROP":"FILTER_FORWARD"));
	        elements |= (1 << FILTER_DISPOSITION );
		if( tok == FILTER_FORWARD ) {
		    curEntry->forward = TRUE;
		} else {
		    curEntry->forward = FALSE;
		}
		break;
	    case FILTER_IP_DST:
	    case FILTER_IP_SRC:
		PRINTF((" got %s ", tok == FILTER_IP_DST?
			"FILTER_IP_DST":"FILTER_IP_SRC"));
		token = (char *) strtok( NULL, " " );
		if ( token ) {
		    if( tok == FILTER_IP_DST ) {
			
		        if( ipAddressStringToValue( (char*)token, 
				 &ip->dstip, (char *)&ip->dstmask ) ) {
			    PRINTF((" ip %lx netmask %lx \n", ip->dstip, 
				     ip->dstmask ));
			    break;
			}
		    } else {
		        if( ipAddressStringToValue( (char *)token, 
				&ip->srcip, (char *)&ip->srcmask ) ) {
			    PRINTF((" ip %lx netmask %lx \n", ip->srcip,
				     ip->srcmask ));
			    break;
			}
		    }
		} 

		PRINTF(( "RADIF: IP Filter syntax error %s \n", token ));
		librad_log("ip filter error: do not recognize %s in %s \n",
			  token, curString );
		goto doneErr ;

	    case FILTER_IP_DST_PORT:
	    case FILTER_IP_SRC_PORT:
	    {
		RadFilterComparison cmp;
		short		 port;

		PRINTF((" got %s ", tok == FILTER_IP_DST_PORT?
			"FILTER_IP_DST_PORT":"FILTER_IP_SRC_PORT"));
		token = (char *) strtok( NULL, " " );
		if ( token ) {
  		    cmp = findKey( token, filterCompare );
		    PRINTF((" cmp value = %d \n", cmp ));
		    if( cmp != NO_TOKEN ) {
			token = (char *) strtok( NULL, " " );
			if ( token ) {
			    if( isAllDigit( token ) ) {
				port = atoi( (char *) token );
			    } else {
  		    	        port = findKey( token, filterPortType );
			    }
			    if( port != (short) NO_TOKEN ) {
		    	    	PRINTF((" port = %d \n", port ));
				if( tok == FILTER_IP_DST_PORT ) {
				    ip->dstPortComp = cmp;
				    ip->dstport = htons( port );
				} else {
				    ip->srcPortComp = cmp;
				    ip->srcport = htons( port );
				}
				break;
			    }
			}
		    }
		}
		librad_log( "ip filter error: do not recognize %s in %s \n",
			  token, curString );
		PRINTF(( "RADIF: IP Filter syntax error %s \n", token ));
		goto doneErr;
		break;
	    }
	    case FILTER_EST:
		PRINTF((" got est %s ", token ));
		ip->established = TRUE;
		break;
	    default:
		/* no keyword match but may match a protocol list */
		if( isAllDigit( token ) ) {
		    tok = atoi( (char *) token );
		} else {
		    tok = findKey( token, _filterProtoName );

		    if( tok == NO_TOKEN ) {
			PRINTF(( "RADIF: IP proto error %s \n", token ));
			librad_log("ip filter error: do not recognize %s in %s \n",
			     token, curString );
			goto doneErr;
		    }
		}
		ip->proto = tok;
		PRINTF(("ip proto cmd = %d ", tok));
	}
        token = (char *) strtok( NULL, " " ); 
    } 

    if( elements == IP_FILTER_COMPLETE ) {
	return( 0 );
    }

doneErr:
    PRINTF((" done err \n"));
    return( -1 );
}

    /*
     * parseGenericFilter:
     *
     * This routine parses a Generic filter string from a RADIUS
     * reply. The format of the string is:
     *
     *	GENERIC dir action offset mask value [== or != ] [more]
     *
     * Fields in [...] are optional.
     *	where:
     *
     * 	generic:	Keyword to indicate a generic filter. This
     *			has been determined by parseFilter.
     *
     *	dir:		Filter direction. "IN" or "OUT"
     *
     *	action:		Filter action. "FORWARD" or "DROP"
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
     *
     * expects:
     *
     *	curEntry:	Pointer to place the filter structure
     *
     *	returns:	-1 for error or 0 for OK
     *	
     */

static int
parseGenericFilter(curEntry)
RadFilter	*curEntry;
{
    unsigned long	elements = 0l; 
    int			tok; 
    int			gstate = FILTER_GENERIC_OFFSET;
    char*		token;
    short		valLen, maskLen;
    RadGenericFilter*	gen;

    token = (char *) strtok( NULL, " " ); 

    PRINTF((" in parse generic filter \n")); 

    maskLen = 0;
    memset( (char *)curEntry, '\0', sizeof( RadFilter ) );
    curEntry->type = RAD_FILTER_GENERIC;
    gen = &curEntry->u.generic;
    gen->more = FALSE; 
    gen->compNeq = FALSE;	

    while( token ) {
	PRINTF((" token %s ", token ));
  	tok = findKey( token, filterKeywords );
   	PRINTF(("tok %d ", tok));
	switch( tok ) {
	    case FILTER_IN:
	    case FILTER_OUT:
		curEntry->indirection = tok == FILTER_IN ? TRUE: FALSE;
	        elements |= (1 << FILTER_DIRECTION );
		PRINTF((" got %s ", tok == FILTER_IN?"FILTER_IN":"FILTER_OUT"));
		break;
	    case FILTER_FORWARD:
	    case FILTER_DROP:
	        elements |= (1 << FILTER_DISPOSITION );
		PRINTF((" got %s ", tok == FILTER_DROP?
			"FILTER_DROP":"FILTER_FORWARD"));
		if( tok == FILTER_FORWARD ) {
		    curEntry->forward = TRUE;
		} else {
		    curEntry->forward = FALSE;
		}
		break;
	    case FILTER_GENERIC_COMPNEQ:
		gen->compNeq = TRUE;
		PRINTF((" got compare %s ", token));
		break;
	    case FILTER_GENERIC_COMPEQ:
		gen->compNeq = FALSE;
		PRINTF((" got compare %s ", token));
		break;
	    case FILTER_MORE:
		gen->more = htons( TRUE );
		PRINTF((" got more %s ", token ));
		break;
	    default:
	        elements |= ( 1 << gstate );
		switch( gstate ) {
		    case FILTER_GENERIC_OFFSET:
			gstate = FILTER_GENERIC_MASK;
			gen->offset = htons( atoi( (char *) token ) );
			break;
		    case FILTER_GENERIC_MASK:
			gstate = FILTER_GENERIC_VALUE;
			maskLen = a2octet( token, (char *)gen->mask );
			if( maskLen == (short) -1 ) {
			    librad_log("filter mask error: %s \n", curString );
			    goto doneErr;
			}
			PRINTF((" octet retlen = %d ", maskLen ));
			for( tok = 0; tok < maskLen; tok++) {
        		    PRINTF(("%2x", gen->mask[tok]));
		        }
			PRINTF(("\n"));
			break;
		    case FILTER_GENERIC_VALUE:
			gstate ++;
			valLen = a2octet( token, (char *)gen->value );
			if( valLen != maskLen ) {
			    librad_log("filter value size is not the same size as the filter mask: %s \n", 
				     curString );
			    goto doneErr;
			}
			gen->len = htons( valLen );
			PRINTF((" octet retlen = %d ", maskLen ));
			for( tok = 0; tok < maskLen; tok++) {
        		    PRINTF(("%2x", gen->value[tok]));
		        }
			PRINTF(("\n"));
			break;
		    default:
			librad_log("filter: do not know %s in %s \n",
				 token, curString );
			PRINTF(( "RADIF: Filter syntax error %s \n", token ));
			goto doneErr;    
		}
	}
        token = (char *) strtok( NULL, " " ); 
    }

    if( elements == GENERIC_FILTER_COMPLETE ) {
	return( 0 );
    }

doneErr:
    PRINTF((" done err \n"));
    return( -1 );
}
		       
    /*
     * filterBinary:
     *
     * This routine will call routines to parse entries from an ASCII format
     * to a binary format recognized by the Ascend boxes.
     *
     *	pair:			Pointer to value_pair to place return.
     *
     *	valstr:			The string to parse	
     *
     *	return:			-1 for error or 0.
     */
int 
filterBinary(VALUE_PAIR *pair, char *valstr)
{

    char*		token;
    unsigned long	tok;
    int			rc;
    RadFilter		radFil, *filt;
    RadGenericFilter*	gen;
    static VALUE_PAIR	*prevRadPair = NULL;


    rc = -1;
    strcpy( curString, valstr );

    token = (char *) strtok( (char *)valstr, " " );
    tok = findKey( token, filterKeywords );
    pair->length = SIZEOF_RADFILTER;
    switch( tok ) {
      case FILTER_IP_TYPE:
	rc = parseIpFilter( &radFil );
	break;
      case FILTER_GENERIC_TYPE:
	rc = parseGenericFilter( &radFil );
	break;
      case  FILTER_IPX_TYPE:
	rc = parseIpxFilter( &radFil );
        break;
    }

    /*
     * if 'more' is set then this new entry must exist, be a 
     * FILTER_GENERIC_TYPE, direction and disposition must match for 
     * the previous 'more' to be valid. If any should fail then TURN OFF 
     * previous 'more'
     */
    if( prevRadPair ) {
	filt = ( RadFilter * )prevRadPair->strvalue;
	if(( tok != FILTER_GENERIC_TYPE ) || (rc == -1 ) ||
	   ( prevRadPair->attribute != pair->attribute ) || 
	   ( filt->indirection != radFil.indirection ) || 
	   ( filt->forward != radFil.forward ) ) {
	    gen = &filt->u.generic;
	    gen->more = FALSE;
	    librad_log("filterBinary:  'more' for previous entry doesn't match: %s.\n",
		     curString );
	}
    }
    prevRadPair = NULL;
    if( rc != -1 && tok == FILTER_GENERIC_TYPE ) {
	if( radFil.u.generic.more ) {
	    prevRadPair = pair;
	} 
    }

    if( rc != -1 ) {
	memcpy( pair->strvalue, (char *) &radFil, pair->length );
    }
    return(rc);
}


/********************************************************************/

/*
 *  The following code was written specifically for the FreeRADIUS
 *  server by Alan DeKok <aland@ox.org>, and as such, falls under
 *  the GPL, and not under the previous Ascend license.
 */

static const char *FindValue(int value, KeywordStruct *list)
{
  KeywordStruct	*entry;

  entry = list;
  while (entry->name) {
    if (entry->value == value) {
      return entry->name;
    }
    entry++;
  }

  return "???";
}

void print_abinary(VALUE_PAIR *vp, u_char *buffer, int len)
{
  int i;
  char *p;
  RadFilter	filter;
  
  static char *filter_type[] = {"generic", "ip", "ipx"};
  static char *action[] = {"drop", "forward"};
  static char *direction[] = {"output", "input"};
  
  p = buffer;

  *(p++) = '"';

  /*
   *  Just for paranoia
   */
  if (vp->length != SIZEOF_RADFILTER) {
    for (i = 0; i < vp->length; i++) {
      sprintf(p, " %02x", vp->strvalue[i]);
      p += 3;
    }
    strcpy(p, "\"");
    return;
  }

  memcpy(&filter, vp->strvalue, SIZEOF_RADFILTER);
  len -= 2;

  i = snprintf(p, len, "%s %s %s",
	       filter_type[filter.type],
	       action[filter.forward & 0x01],
	       direction[filter.indirection & 0x01]);
  p += i;
  len -= i;
    

  if (filter.type == RAD_FILTER_IP) {
    if (filter.u.ip.dstip) {
      i = snprintf(p, len, " dstip %d.%d.%d.%d/%d",
		   ((u_char *) &filter.u.ip.dstip)[0],
		   ((u_char *) &filter.u.ip.dstip)[1],
		   ((u_char *) &filter.u.ip.dstip)[2],
		   ((u_char *) &filter.u.ip.dstip)[3],
		   filter.u.ip.dstmask);
      p += i;
      len -= i;
    }
    
    if (filter.u.ip.srcip) {
      i = snprintf(p, len, " srcip %d.%d.%d.%d/%d",
		   ((u_char *) &filter.u.ip.srcip)[0],
		   ((u_char *) &filter.u.ip.srcip)[1],
		   ((u_char *) &filter.u.ip.srcip)[2],
		   ((u_char *) &filter.u.ip.srcip)[3],
		   filter.u.ip.srcmask);
      p += i;
      len -= i;
    }

    i =  snprintf(p, len, " %d", filter.u.ip.proto);
    p += i;
    len -= i;
    
    if (filter.u.ip.dstPortComp) {
      i = snprintf(p, len, " dstport %s %d",
		   FindValue(filter.u.ip.dstPortComp, filterCompare),
		   ntohs(filter.u.ip.dstport));
      p += i;
      len -= i;
    }
    
    if (filter.u.ip.srcPortComp) {
      i = snprintf(p, len, " srcport %s %d",
		   FindValue(filter.u.ip.srcPortComp, filterCompare),
		   ntohs(filter.u.ip.srcport));
      p += i;
      len -= i;
    }
  } else if (filter.type == RAD_FILTER_IPX) {
    /* print for source */
    if (filter.u.ipx.srcIpxNet) {
      i = snprintf(p, len, " srcipxnet 0x%04x srcipxnode 0x%02x%02x%02x%02x%02x%02x",
		  ntohl(filter.u.ipx.srcIpxNet),
		  filter.u.ipx.srcIpxNode[0], filter.u.ipx.srcIpxNode[1], 
		  filter.u.ipx.srcIpxNode[2], filter.u.ipx.srcIpxNode[3], 
		  filter.u.ipx.srcIpxNode[4], filter.u.ipx.srcIpxNode[5]);
      p += i;
      len -= i;
    }

    /* same for destination */
    if (filter.u.ipx.dstIpxNet) {
      i = snprintf(p, len, " dstipxnet 0x%04x dstipxnode 0x%02x%02x%02x%02x%02x%02x",
		  ntohl(filter.u.ipx.dstIpxNet),
		  filter.u.ipx.dstIpxNode[0], filter.u.ipx.dstIpxNode[1], 
		  filter.u.ipx.dstIpxNode[2], filter.u.ipx.dstIpxNode[3], 
		  filter.u.ipx.dstIpxNode[4], filter.u.ipx.dstIpxNode[5]);
      p += i;
      len -= i;
    }


  }
  
  *(p++) = '"';
  *p = '\0';
}
