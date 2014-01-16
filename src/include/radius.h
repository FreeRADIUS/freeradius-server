/*
 * radius.h  Constants of the radius protocol.
 *
 * Version:  $Id$
 *
 */

typedef enum {
	PW_TYPE_INVALID = 0,	//!< Invalid (uninitialised) attribute type.
	PW_TYPE_STRING,		//!< String of printable characters.
	PW_TYPE_INTEGER,	//!< 32 Bit unsigned integer.
	PW_TYPE_IPADDR,		//!< 32 Bit IPv4 Address.
	PW_TYPE_DATE,		//!< 32 Bit Unix timestamp.
	PW_TYPE_ABINARY,	//!< Ascend binary format a packed data
				//!< structure.
	PW_TYPE_OCTETS,		//!< Raw octets.
	PW_TYPE_IFID,		//!< Interface ID.
	PW_TYPE_IPV6ADDR,	//!< 128 Bit IPv6 Address.
	PW_TYPE_IPV6PREFIX,	//!< IPv6 Prefix.
	PW_TYPE_BYTE,		//!< 8 Bit unsigned integer.
	PW_TYPE_SHORT,		//!< 16 Bit unsigned integer.
	PW_TYPE_ETHERNET,	//!< 48 Bit Mac-Address.
	PW_TYPE_SIGNED,		//!< 32 Bit signed integer.
	PW_TYPE_COMBO_IP,	//!< WiMAX IPv4 or IPv6 address depending
				//!< on length.
	PW_TYPE_TLV,		//!< Contains nested attributes.
	PW_TYPE_EXTENDED,	//!< Extended attribute space attribute.
	PW_TYPE_LONG_EXTENDED,	//!< Long extended attribute space attribute.
	PW_TYPE_EVS,		//!< Extended attribute, vendor specific.
	PW_TYPE_INTEGER64,	//!< 64 Bit unsigned integer.
	PW_TYPE_IPV4PREFIX,	//!< IPv4 Prefix.
	PW_TYPE_VSA,		//!< Vendor-Specific, for attribute 26
	PW_TYPE_MAX		//!< Number of defined data types.
} PW_TYPE;

typedef enum {
	PW_CODE_INVALID			= 0,	//!< Packet code is invalid
	PW_CODE_AUTHENTICATION_REQUEST 	= 1,	//!< RFC2865 - Authentication request
	PW_CODE_AUTHENTICATION_ACK	= 2,	//!< RFC2865 - Access-Accept
	PW_CODE_AUTHENTICATION_REJECT	= 3,	//!< RFC2865 - Access-Reject
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
#define PW_ACCT_UDP_PORT		1813
#define PW_POD_UDP_PORT			1700
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
#define PW_FRAMED_IPV6_PREFIX	97
#define PW_OPERATOR_NAME		126

#define PW_EXTENDED_ATTRIBUTE		192

#define PW_DIGEST_RESPONSE		206
#define PW_DIGEST_ATTRIBUTES		207

#define PW_FALL_THROUGH			500
#define PW_RELAX_FILTER			501
#define PW_EXEC_PROGRAM			502
#define PW_EXEC_PROGRAM_WAIT		503

#define PW_AUTH_TYPE			1000
#define PW_PREFIX			1003
#define PW_SUFFIX			1004
#define PW_GROUP			1005
#define PW_CRYPT_PASSWORD		1006
#define PW_CONNECT_RATE			1007
#define PW_ADD_PREFIX			1008
#define PW_ADD_SUFFIX			1009
#define PW_EXPIRATION			1010
#define PW_AUTZ_TYPE			1011
#define PW_ACCT_TYPE			1012
#define PW_SESSION_TYPE			1013
#define PW_POST_AUTH_TYPE		1014
#define PW_PRE_PROXY_TYPE		1015
#define PW_POST_PROXY_TYPE		1016
#define PW_PRE_ACCT_TYPE		1017
#define PW_EAP_TYPE			1018
#define PW_EAP_TLS_REQUIRE_CLIENT_CERT	1019
#define PW_EAP_MD5_PASSWORD		1022
#define PW_CLIENT_SHORTNAME		1024
#define PW_LOAD_BALANCE_KEY		1025
#define PW_RAW_ATTRIBUTE		1026
#define PW_TNC_VLAN_ACCESS		1027
#define PW_TNC_VLAN_ISOLATE		1028
#define PW_USER_CATEGORY		1029
#define PW_GROUP_NAME			1030
#define PW_HUNTGROUP_NAME		1031
#define PW_SIMULTANEOUS_USE		1034
#define PW_STRIP_USER_NAME		1035
#define PW_HINT				1040
#define PAM_AUTH_ATTR			1041
#define PW_LOGIN_TIME			1042
#define PW_STRIPPED_USER_NAME		1043
#define PW_CURRENT_TIME			1044
#define PW_REALM			1045
#define PW_NO_SUCH_ATTRIBUTE		1046
#define PW_PACKET_TYPE			1047
#define PW_PROXY_TO_REALM		1048
#define PW_REPLICATE_TO_REALM		1049
#define PW_ACCT_SESSION_START_TIME	1050
#define PW_ACCT_UNIQUE_SESSION_ID	1051
#define PW_CLIENT_IP_ADDRESS		1052
#define PW_LDAP_USERDN			1053
#define PW_NS_MTA_MD5_PASSWORD		1054
#define PW_SQL_USER_NAME		1055
#define PW_LM_PASSWORD			1057
#define PW_NT_PASSWORD			1058
#define PW_SMB_ACCOUNT_CTRL		1059
#define PW_SMB_ACCOUNT_CTRL_TEXT	1061
#define PW_USER_PROFILE			1062
#define PW_DIGEST_REALM			1063
#define PW_DIGEST_NONCE			1064
#define PW_DIGEST_METHOD		1065
#define PW_DIGEST_URI			1066
#define PW_DIGEST_QOP			1067
#define PW_DIGEST_ALGORITHM		1068
#define PW_DIGEST_BODY_DIGEST		1069
#define PW_DIGEST_CNONCE		1070
#define PW_DIGEST_NONCE_COUNT		1071
#define PW_DIGEST_USER_NAME		1072
#define PW_POOL_NAME			1073
#define PW_LDAP_GROUP			1074
#define PW_MODULE_SUCCESS_MESSAGE	1075
#define PW_MODULE_FAILURE_MESSAGE	1076
#if 0 /* no longer used */
#define PW_X99_FAST			1077
#endif
#define PW_REWRITE_RULE			1078
#define PW_SQL_GROUP			1079
#define PW_RESPONSE_PACKET_TYPE		1080
#define PW_DIGEST_HA1			1081
#define PW_MS_CHAP_USE_NTLM_AUTH	1082
#define PW_MS_CHAP_USER_NAME		1083
#define PW_PACKET_SRC_IP_ADDRESS	1084
#define PW_PACKET_DST_IP_ADDRESS	1085
#define PW_PACKET_SRC_PORT		1086
#define PW_PACKET_DST_PORT		1087
#define PW_PACKET_AUTHENTICATION_VECTOR	1088
#define PW_TIME_OF_DAY			1089
#define PW_REQUEST_PROCESSING_STAGE	1090

#define PW_SHA_PASSWORD			1093
#define PW_SSHA_PASSWORD		1094
#define PW_MD5_PASSWORD			1095
#define PW_SMD5_PASSWORD		1096

#define PW_PACKET_SRC_IPV6_ADDRESS	1097
#define PW_PACKET_DST_IPV6_ADDRESS	1098
#define PW_VIRTUAL_SERVER		1099
#define PW_CLEARTEXT_PASSWORD		1100
#define PW_PASSWORD_WITH_HEADER		1101
#define PW_SEND_COA_REQUEST		1107
#define PW_MODULE_RETURN_CODE		1108
#define PW_PACKET_ORIGINAL_TIMESTAMP	1109
#define PW_HOME_SERVER_POOL		1111
#define PW_FREERADIUS_CLIENT_IP_ADDRESS		1120
#define PW_FREERADIUS_CLIENT_IPV6_ADDRESS	1121
#define PW_FREERADIUS_CLIENT_IP_PREFIX		1150
#define PW_FREERADIUS_CLIENT_IPV6_PREFIX	1151
#define PW_RECV_COA_TYPE		1131
#define PW_SEND_COA_TYPE		1132
#define PW_MSCHAP_PASSWORD		1133
#define PW_PACKET_TRANSMIT_COUNTER	1134
#define PW_CACHED_SESSION_POLICY     	1135
#define PW_FREERADIUS_CLIENT_SRC_IP_ADDRESS	1143
#define PW_FREERADIUS_CLIENT_SRC_IPV6_ADDRESS	1144

#define PW_OTP_CHALLENGE		1145
#define PW_EAP_SESSION_ID		1146

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
