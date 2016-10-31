#ifndef _IPACCESS_H
#define _IPACCESS_H

#include <osmocom/core/linuxlist.h>

#define IPA_TCP_PORT_OML	3002
#define IPA_TCP_PORT_RSL	3003

struct ipaccess_head {
	uint16_t len;	/* network byte order */
	uint8_t proto;
	uint8_t data[0];
} __attribute__ ((packed));

enum ipaccess_proto {
	IPAC_PROTO_RSL		= 0x00,
	IPAC_PROTO_IPACCESS	= 0xfe,
	IPAC_PROTO_SCCP		= 0xfd,
	IPAC_PROTO_OML		= 0xff,
};

enum ipaccess_msgtype {
	IPAC_MSGT_PING		= 0x00,
	IPAC_MSGT_PONG		= 0x01,
	IPAC_MSGT_ID_GET	= 0x04,
	IPAC_MSGT_ID_RESP	= 0x05,
	IPAC_MSGT_ID_ACK	= 0x06,
};

enum ipaccess_id_tags {
	IPAC_IDTAG_SERNR		= 0x00,
	IPAC_IDTAG_UNITNAME		= 0x01,
	IPAC_IDTAG_LOCATION1		= 0x02,
	IPAC_IDTAG_LOCATION2		= 0x03,
	IPAC_IDTAG_EQUIPVERS		= 0x04,
	IPAC_IDTAG_SWVERSION		= 0x05,
	IPAC_IDTAG_IPADDR		= 0x06,
	IPAC_IDTAG_MACADDR		= 0x07,
	IPAC_IDTAG_UNIT			= 0x08,
};

/*
 * methods for parsing and sending a message
 */
int ipaccess_rcvmsg_base(struct msgb *msg, struct osmo_fd *bfd);
struct msgb *ipaccess_read_msg(struct osmo_fd *bfd, int *error);
void ipaccess_prepend_header(struct msgb *msg, int proto);
int ipaccess_send_id_ack(int fd);
int ipaccess_send_id_req(int fd);


#endif /* _IPACCESS_H */
