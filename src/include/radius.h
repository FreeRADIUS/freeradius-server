/*
 * radius.h  Constants of the radius protocol.
 *
 * Version:  $Id$
 *
 */

typedef enum {
	PW_TYPE_INVALID = 0,			//!< Invalid (uninitialised) attribute type.
	PW_TYPE_STRING,				//!< String of printable characters.
	PW_TYPE_INTEGER,			//!< 32 Bit unsigned integer.
	PW_TYPE_IPV4_ADDR,			//!< 32 Bit IPv4 Address.
	PW_TYPE_DATE,				//!< 32 Bit Unix timestamp.
	PW_TYPE_ABINARY,			//!< Ascend binary format a packed data structure.
	PW_TYPE_OCTETS,				//!< Raw octets.
	PW_TYPE_IFID,				//!< Interface ID.
	PW_TYPE_IPV6_ADDR,			//!< 128 Bit IPv6 Address.
	PW_TYPE_IPV6_PREFIX,			//!< IPv6 Prefix.
	PW_TYPE_BYTE,				//!< 8 Bit unsigned integer.
	PW_TYPE_SHORT,				//!< 16 Bit unsigned integer.
	PW_TYPE_ETHERNET,			//!< 48 Bit Mac-Address.
	PW_TYPE_SIGNED,				//!< 32 Bit signed integer.
	PW_TYPE_IP_ADDR,			//!< WiMAX IPv4 or IPv6 address depending on length.
	PW_TYPE_TLV,				//!< Contains nested attributes.
	PW_TYPE_EXTENDED,			//!< Extended attribute space attribute.
	PW_TYPE_LONG_EXTENDED,			//!< Long extended attribute space attribute.
	PW_TYPE_EVS,				//!< Extended attribute, vendor specific.
	PW_TYPE_INTEGER64,			//!< 64 Bit unsigned integer.
	PW_TYPE_IPV4_PREFIX,			//!< IPv4 Prefix.
	PW_TYPE_VSA,				//!< Vendor-Specific, for RADIUS attribute 26.
	PW_TYPE_TIMEVAL,			//!< Time value (struct timeval), only for config items.
	PW_TYPE_BOOLEAN,			//!< A truth value.
	PW_TYPE_IP_PREFIX,			//!< WiMAX IPv4 or IPv6 address prefix depending on length.
	PW_TYPE_MAX				//!< Number of defined data types.
} PW_TYPE;

typedef enum {
	PW_CODE_UNDEFINED		= 0,	//!< Packet code has not been set
	PW_CODE_ACCESS_REQUEST		= 1,	//!< RFC2865 - Access-Request
	PW_CODE_ACCESS_ACCEPT		= 2,	//!< RFC2865 - Access-Accept
	PW_CODE_ACCESS_REJECT		= 3,	//!< RFC2865 - Access-Reject
	PW_CODE_ACCOUNTING_REQUEST	= 4,	//!< RFC2866 - Accounting-Request
	PW_CODE_ACCOUNTING_RESPONSE	= 5,	//!< RFC2866 - Accounting-Response
	PW_CODE_ACCOUNTING_STATUS	= 6,	//!< RFC3575 - Reserved
	PW_CODE_PASSWORD_REQUEST	= 7,	//!< RFC3575 - Reserved
	PW_CODE_PASSWORD_ACK		= 8,	//!< RFC3575 - Reserved
	PW_CODE_PASSWORD_REJECT		= 9,	//!< RFC3575 - Reserved
	PW_CODE_ACCOUNTING_MESSAGE	= 10,	//!< RFC3575 - Reserved
	PW_CODE_ACCESS_CHALLENGE	= 11,	//!< RFC2865 - Access-Challenge
	PW_CODE_STATUS_SERVER	 	= 12,	//!< RFC2865/RFC5997 - Status Server (request)
	PW_CODE_STATUS_CLIENT		= 13,	//!< RFC2865/RFC5997 - Status Server (response)
	PW_CODE_DISCONNECT_REQUEST	= 40,	//!< RFC3575/RFC5176 - Disconnect-Request
	PW_CODE_DISCONNECT_ACK		= 41,	//!< RFC3575/RFC5176 - Disconnect-Ack (positive)
	PW_CODE_DISCONNECT_NAK		= 42,	//!< RFC3575/RFC5176 - Disconnect-Nak (not willing to perform)
	PW_CODE_COA_REQUEST		= 43,	//!< RFC3575/RFC5176 - CoA-Request
	PW_CODE_COA_ACK			= 44,	//!< RFC3575/RFC5176 - CoA-Ack (positive)
	PW_CODE_COA_NAK			= 45,	//!< RFC3575/RFC5176 - CoA-Nak (not willing to perform)
	PW_CODE_MAX			= 255,	//!< Maximum possible code
} PW_CODE;

#define PW_AUTH_UDP_PORT		1812
#define PW_AUTH_UDP_PORT_ALT		1645
#define PW_ACCT_UDP_PORT		1813
#define PW_ACCT_UDP_PORT_ALT		1646
#define PW_POD_UDP_PORT			1700
#define PW_RADIUS_TLS_PORT	       	2083
#define PW_COA_UDP_PORT			3799

#define	PW_USER_NAME			1
#define	PW_USER_PASSWORD		2
#define	PW_PASSWORD			2
#define	PW_CHAP_PASSWORD		3
#define	PW_NAS_IP_ADDRESS		4
#define	PW_NAS_PORT			5
#define	PW_SERVICE_TYPE			6
#define	PW_FRAMED_PROTOCOL		7
#define	PW_FRAMED_IP_ADDRESS		8
#define	PW_FRAMED_IP_NETMASK		9
#define	PW_FRAMED_ROUTING		10
#define	PW_FILTER_ID			11
#define	PW_FRAMED_MTU			12
#define	PW_FRAMED_COMPRESSION		13
#define	PW_LOGIN_IP_HOST		14
#define	PW_LOGIN_SERVICE		15
#define	PW_LOGIN_TCP_PORT		16
#define PW_OLD_PASSWORD			17
#define PW_REPLY_MESSAGE		18
#define PW_CALLBACK_NUMBER		19
#define PW_CALLBACK_ID			20
#if 0
/*
 *	Deprecated, and no longer used.
 */
#define PW_EXPIRATION			21
#endif
#define PW_FRAMED_ROUTE			22
#define PW_FRAMED_IPXNET		23
#define PW_STATE			24
#define PW_CLASS			25
#define PW_VENDOR_SPECIFIC		26
#define PW_SESSION_TIMEOUT		27
#define PW_IDLE_TIMEOUT			28
#define PW_CALLED_STATION_ID		30
#define PW_CALLING_STATION_ID		31
#define PW_NAS_IDENTIFIER		32
#define PW_PROXY_STATE			33

#define PW_ACCT_STATUS_TYPE		40
#define PW_ACCT_DELAY_TIME		41
#define PW_ACCT_INPUT_OCTETS		42
#define PW_ACCT_OUTPUT_OCTETS		43
#define PW_ACCT_SESSION_ID		44
#define PW_ACCT_AUTHENTIC		45
#define PW_ACCT_SESSION_TIME		46
#define PW_ACCT_INPUT_PACKETS		47
#define PW_ACCT_OUTPUT_PACKETS		48
#define PW_ACCT_TERMINATE_CAUSE		49

#define PW_EVENT_TIMESTAMP		55

#define PW_CHAP_CHALLENGE		60
#define PW_NAS_PORT_TYPE		61
#define PW_PORT_LIMIT			62

#define PW_ARAP_PASSWORD		70
#define PW_ARAP_FEATURES		71
#define PW_ARAP_ZONE_ACCESS		72
#define PW_ARAP_SECURITY		73
#define PW_ARAP_SECURITY_DATA		74
#define PW_PASSWORD_RETRY		75
#define PW_PROMPT			76
#define PW_CONNECT_INFO			77
#define PW_CONFIGURATION_TOKEN		78
#define PW_EAP_MESSAGE			79
#define PW_MESSAGE_AUTHENTICATOR	80

#define PW_ARAP_CHALLENGE_RESPONSE	84
#define PW_NAS_PORT_ID_STRING		87
#define PW_FRAMED_POOL			88
#define PW_CHARGEABLE_USER_IDENTITY	89
#define PW_NAS_IPV6_ADDRESS		95
#define PW_FRAMED_IPV6_PREFIX		97

#define PW_OPERATOR_NAME		126

#define PW_EXTENDED_ATTRIBUTE		192

#define PW_DIGEST_RESPONSE		206
#define PW_DIGEST_ATTRIBUTES		207

/*
 *	All internal attributes are now defined in this file.
 */
#include <freeradius-devel/attributes.h>

/*
 *	Integer Translations
 */

/*	User Types	*/

#define PW_LOGIN_USER			1
#define PW_FRAMED_USER			2
#define PW_CALLBACK_LOGIN_USER		3
#define PW_CALLBACK_FRAMED_USER		4
#define PW_OUTBOUND_USER		5
#define PW_ADMINISTRATIVE_USER		6
#define PW_NAS_PROMPT_USER		7
#define PW_AUTHENTICATE_ONLY		8
#define PW_CALLBACK_NAS_PROMPT		9

/*	Framed Protocols	*/

#define PW_PPP				1
#define PW_SLIP				2

/*	Framed Routing Values	*/

#define PW_NONE				0
#define PW_BROADCAST			1
#define PW_LISTEN			2
#define PW_BROADCAST_LISTEN		3

/*	Framed Compression Types	*/

#define PW_VAN_JACOBSEN_TCP_IP		1

/*	Login Services	*/

#define PW_TELNET			0
#define PW_RLOGIN			1
#define PW_TCP_CLEAR			2
#define PW_PORTMASTER			3

/*	Authentication Level	*/

#define PW_AUTHTYPE_LOCAL		0
#define PW_AUTHTYPE_SYSTEM		1
#define PW_AUTHTYPE_SECURID		2
#define PW_AUTHTYPE_CRYPT		3
#define PW_AUTHTYPE_REJECT		4
#define PW_AUTHTYPE_ACTIVCARD		5
#define PW_AUTHTYPE_EAP			6
#define PW_AUTHTYPE_ACCEPT		254
#define PW_AUTHTYPE_MS_CHAP		1028

/* Post-auth types */
#define PW_POSTAUTHTYPE_LOCAL		0
#define PW_POSTAUTHTYPE_REJECT		1

/*	Port Types		*/

#define PW_NAS_PORT_ASYNC		0
#define PW_NAS_PORT_SYNC		1
#define PW_NAS_PORT_ISDN		2
#define PW_NAS_PORT_ISDN_V120		3
#define PW_NAS_PORT_ISDN_V110		4

/*	Status Types	*/

#define PW_STATUS_START			1
#define PW_STATUS_STOP			2
#define PW_STATUS_ALIVE			3
#define PW_STATUS_ACCOUNTING_ON		7
#define PW_STATUS_ACCOUNTING_OFF	8

/*
 *	Vendor Private Enterprise Codes
 */
#define VENDORPEC_MICROSOFT		311
#define VENDORPEC_FREERADIUS		11344
#define VENDORPEC_WIMAX			24757
#define VENDORPEC_UKERNA		25622

/*
 * Vendor specific attributes
 */
#define PW_FREERADIUS_PROXIED_TO	1

/*
 *	Microsoft has vendor code 311.
 */
#define PW_MSCHAP_RESPONSE		1
#define PW_MSCHAP_ERROR			2
#define PW_MSCHAP_CPW_1			3
#define PW_MSCHAP_CPW_2			4
#define PW_MSCHAP_NT_ENC_PW		6
#define PW_MSCHAP_CHALLENGE		11
#define PW_MSCHAP2_RESPONSE		25
#define PW_MSCHAP2_SUCCESS		26
#define PW_MSCHAP2_CPW			27

/*
 *	Old nonsense.	Will be deleted ASAP
 */
#define PW_AUTHTYPE			1000
#define PW_AUTZTYPE			1011
#define PW_ACCTTYPE			1012
#define PW_SESSTYPE			1013
#define PW_POSTAUTHTYPE			1014

/*
 *	Cisco's VLAN Query Protocol.
 */
#define PW_VQP_PACKET_TYPE		0x2b00
#define PW_VQP_ERROR_CODE		0x2b01
#define PW_VQP_SEQUENCE_NUMBER		0x2b02

#define PW_VQP_CLIENT_IP_ADDRESS	0x2c01
#define PW_VQP_PORT_NAME		0x2c02
#define PW_VQP_VLAN_NAME		0x2c03
#define PW_VQP_DOMAIN_NAME		0x2c04
#define PW_VQP_ETHERNET_FRAME		0x2c05
#define PW_VQP_MAC			0x2c06
#define PW_VQP_UNKNOWN			0x2c07
#define PW_VQP_COOKIE			0x2c08

/*
 * JANET's code for transporting eap channel binding data over ttls
 */

#define PW_UKERNA_CHBIND		135
