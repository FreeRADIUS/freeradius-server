/*
 * Represet M3UA client (and later server) links
 */
#pragma once

#include "mtp_data.h"

#include <osmocom/core/write_queue.h>

#include <netinet/in.h>

struct mtp_m3ua_client_link {
	struct mtp_link *base;

	struct osmo_fd	connect;

	struct osmo_wqueue queue;
	struct osmo_timer_list connect_timer;

	char *source;
	struct sockaddr_storage local;

	char *dest;
	struct sockaddr_storage remote;

	int use_asp_ident;
	int link_index;

	int use_routing_context;		//!< Whether we should include a routing_context in ASPAC
						//!< messages.
	int routing_context;			//!< The routing context to include if use_routing_context is true.

	int use_beat;				//!< Whether to send superfluous heartbeats.
	uint64_t beat_seq;			//!< Heartbeat sequence number.

	uint32_t traffic_mode;

	/* routes to register with SG */
	struct llist_head routes;		//!< Routes to register.
	struct llist_head routes_active;	//!< Routes currently active.
	struct llist_head routes_failed;	//!< Routes that failed.

	/* state of the link */
	int aspsm_active;
	int asptm_active;

	/* reliability handling */
	struct osmo_timer_list t_ack;
	struct osmo_timer_list t_beat;
	int ack_timeout;
};

struct mtp_m3ua_opc {
	struct llist_head list;
	uint32_t opc;
};

struct mtp_m3ua_si {
	struct llist_head list;
	uint32_t si;
};

struct mtp_m3ua_reg_req {
	struct llist_head list;			//!< Anchor for the linked list.

	uint32_t local_rk_identifier;		//!< Local index of the route.

	int use_routing_context;		//!< Whether we should include the routing context
						//!< param.
	uint32_t routing_context;		//!< Routing context value.

	int use_traffic_mode;			//!< Whether we should include traffic mode parameter.
	uint32_t traffic_mode;			//!< 1 - Override, 2 - Loadshare, 3 - Broadcast.

	uint32_t dpc;				//!< Should be an OPC that we use to originate traffic.
						//!< Made up of 8 bits mask, 24 bits point code.

	int use_network_appearance;		//!< Include network appearance param.
	uint16_t network_appearance;		//!< Identifies the network context for the routing key.

	struct llist_head si;			//!< List of service indicators.
	struct llist_head opc;			//!< List origin point codes.

	uint32_t reg_routing_context;		//!< Routing context from ACK.

	int reg_rsp_timeout;			//!< (De)registration request ACK timeout.
	struct osmo_timer_list reg_rsp_timer;

	struct mtp_m3ua_client_link *link;	//!< Pointer back to the part link.
};

int mtp_m3ua_link_is_up(struct mtp_m3ua_client_link *link);
struct mtp_m3ua_reg_req *mtp_m3ua_reg_req_add(struct mtp_m3ua_client_link *link);
struct mtp_m3ua_client_link *mtp_m3ua_client_link_init(struct mtp_link *link);


const char *m3ua_traffic_mode_name(uint32_t mode);
uint32_t m3ua_traffic_mode_num(const char *argv);
