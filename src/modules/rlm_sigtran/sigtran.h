/*
 * @copyright (c) 2016, Network RADIUS SARL (license@networkradius.com)
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Network RADIUS SARL nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * $Id$
 * @file sigtran.h
 * @brief Declarations for various sigtran functions.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2016 Network RADIUS SARL (license@networkradius.com)
 */
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/sccp/sccp.h>
#include <osmocom/core/select.h>

typedef enum {
	SIGTRAN_REQUEST_THREAD_REGISTER,				//!< New worker thread to register.
	SIGTRAN_REQUEST_THREAD_UNREGISTER,				//!< Worker thread to unregister.
	SIGTRAN_REQUEST_LINK_UP,					//!< Bring up a link.
	SIGTRAN_REQUEST_LINK_DOWN,					//!< Take down a link.
	SIGTRAN_REQUEST_MAP_SEND_AUTH_INFO,				//!< Request auth info.
	SIGTRAN_REQUEST_EXIT						//!< Causes the event loop to exit.
#ifndef NDEBUG
	, SIGTRAN_REQUEST_TEST,
#endif
} sigtran_request_type_t;

typedef enum {
	SIGTRAN_RESPONSE_OK,						//!< Request succeeded
	SIGTRAN_RESPONSE_NOOP,						//!< Request did nothing
	SIGTRAN_RESPONSE_NOTFOUND,					//!< User or device Not found.
	SIGTRAN_RESPONSE_FAIL						//!< Request failed.
} sigtran_response_type_t;

/** Vector types
 *
 */
typedef enum {
	SIGTRAN_VECTOR_TYPE_SIM_TRIPLETS,				//!< RAND, SRES, Kc.
	SIGTRAN_VECTOR_TYPE_UMTS_QUINTUPLETS				//!< RAND, XRES, CK, IK, AUTN.
} sigtran_vector_type_t;

/** Request and response from the event loop
 *
 * We allocate the whole thing on the client side, as the client
 * will be blocked waiting on the response from the event loop,
 * and won't mind extra memory being allocated from this ctx.
 */
typedef struct sigtran_transaction {
	struct {
		sigtran_request_type_t		type;			//!< Type of request
		void				*data;			//!< Data for the request.
	} request;
	struct {
		sigtran_response_type_t		type;			//!< Type of response
		void				*data;			//!< Data for the response.
	} response;

	struct {
		REQUEST			*request;
		struct osmo_fd		*ofd;				//!< The FD the txn was received on.
		struct osmo_timer_list	timer;				//!< Timer data.


		uint32_t		otid;				//!< Transaction ID.
		uint8_t			invoke_id;			//!< Sequence number (within transaction).

		bool			defunct;			//!< Response should be deleted and not
									///< processed.
	} ctx;
} sigtran_transaction_t;

typedef struct sigtran_sccp_global_title {
	char const			*address;			//!< Address digits.

	uint8_t				tt;				//!< Translation type.
	bool				tt_is_set;			//!< Translation_type was provided.

	uint8_t				es;				//!< Encoding scheme.
	bool				es_is_set;			//!< Encoding scheme is set.

	uint8_t				np;				//!< Numbering plan
	bool				np_is_set;			//!< Numbering plan is set.

	uint8_t				nai;				//!< Nature of address indicator.
	bool				nai_is_set;			//!< Nature of address indicator is set.
} sigtran_sccp_global_title_t;

/** Structure representing a complete Q.173 SCCP address
 *
 */
typedef struct sigtran_sccp_address {
	uint32_t			pc;				//!< 14bit point code.
	bool				pc_is_set;			//!< Point code is set.

	uint8_t				ssn;				//!< Subsystem number.
	bool				ssn_is_set;			//!< Subsystem number is set.

	sigtran_sccp_global_title_t	gt;
	bool				gt_is_set;			//!< Whether a global title was specified.
} sigtran_sccp_address_t;

typedef struct sigtran_m3ua_route {
	uint32_t			dpc;				//!< Destination point code.
	bool				dpc_is_set;			//!< Whether the DPC was set.

	uint32_t			*opc;				//!< Origin point code.

	uint32_t			*si;				//!< Service indicator.
} sigtran_m3ua_route_t;

/** Configures a M3UA/MTP3/SCCP stack
 *
 */
typedef struct sigtran_conn_conf {
	fr_ipaddr_t			sctp_dst_ipaddr;		//!< IP of the Service Gateway.
	uint16_t			sctp_dst_port;			//!< SCTP port of the service gateway.

	fr_ipaddr_t			sctp_src_ipaddr;		//!< Local IP to originate traffic from.
	uint16_t			sctp_src_port;			//!< Local port to originate traffic from.

	uint32_t			sctp_timeout;

	uint32_t			mtp3_dpc, mtp3_opc;		//!< MTP3 point codes (24bit!).
	uint16_t			m3ua_link_index;
	uint16_t			m3ua_routing_context;
	char const			*m3ua_traffic_mode_str;
	int				m3ua_traffic_mode;
	uint32_t			m3ua_ack_timeout;
	uint32_t			m3ua_beat_interval;

	bool				m3ua_routes_is_set;		//!< Routes section was provided.
	sigtran_m3ua_route_t		m3ua_routes;			//!< Routes to register with SG.


	bool				sccp_route_on_ssn;		//!< Whether we should route on subsystem
									//!< number.
	bool				sccp_ai8;			//!< Address indicator bit 8

	sigtran_sccp_address_t		sccp_calling;			//!< The called SCCP address.
	struct sockaddr_sccp		sccp_calling_sockaddr;		//!< Parsed version of the above.
	sigtran_sccp_address_t		sccp_called;			//!< The calling SCCP address.
	struct sockaddr_sccp		sccp_called_sockaddr;		//!< Parsed version of the above

	tmpl_t			*map_version;			//!< Application context version.
} sigtran_conn_conf_t;

/** Represents a connection to a remote SS7 entity
 *
 * Holds data necessary for M3UA/MTP3/SCCP.
 */
typedef struct sigtran_conn {
	sigtran_conn_conf_t	*conf;

	struct bsc_data		*bsc_data;
	struct mtp_link_set	*mtp3_link_set;
	struct mtp_link		*mtp3_link;
} sigtran_conn_t;

/** MAP send auth info request.
 *
 */
typedef struct sigtran_map_send_auth_info_req {
	sigtran_conn_t const	*conn;					//!< Connection to send request on.
	uint8_t			*imsi;					//!< BCD encoded IMSI.
	uint8_t			version;				//!< Application context version.
	unsigned int		num_vectors;				//!< Number of vectors requested.
} sigtran_map_send_auth_info_req_t;

typedef struct sigtran_vector sigtran_vector_t;

/** Authentication vector returned by HLR
 *
 */
struct sigtran_vector {
	union {
		struct {
			uint8_t	*rand;					//!< Random challenge.
			uint8_t *xres;
			uint8_t *ck;					//!< Encryption key.
			uint8_t *ik;					//!< Integrity key.
			uint8_t *authn;					//!< Authentication response.
		} umts;
		struct {
			uint8_t *rand;					//!< Random challenge.
			uint8_t *sres;					//!< Signing response.
			uint8_t *kc;					//!< Encryption key.
		} sim;
	};
	sigtran_vector_type_t type;					//!< Type of vector returned.

	sigtran_vector_t *next;						//!< Next vector in list.
};

/** MAP send auth info response
 *
 */
typedef struct sigtran_map_send_auth_info_res {
	int			error;
	sigtran_vector_t	*vector;				//!< Linked list of vectors.
} sigtran_map_send_auth_info_res_t;

typedef struct rlm_sigtran {
	char const		*name;					//!< Instance name.

	sigtran_conn_t const	*conn;					//!< Linkset associated with this instance.

	sigtran_conn_conf_t	conn_conf;				//!< Connection configuration

	tmpl_t		*imsi;					//!< Subscriber identifier.
} rlm_sigtran_t;

extern int ctrl_pipe[2];
extern uint8_t const ascii_to_tbcd[];
extern uint8_t const is_char_tbcd[];

/*
 *	client.c
 */
int	sigtran_client_do_transaction(int fd, sigtran_transaction_t *txn);

int	sigtran_client_thread_register(fr_event_list_t *el);

int	sigtran_client_thread_unregister(fr_event_list_t *el, int req_pipe_fd);

int	sigtran_client_link_up(sigtran_conn_t const **out, sigtran_conn_conf_t const *conf);

int	sigtran_client_link_down(sigtran_conn_t const **conn);

rlm_rcode_t sigtran_client_map_send_auth_info(rlm_sigtran_t const *inst, REQUEST *request,
					      sigtran_conn_t const *conn, int fd);

/*
 *	event.c
 */
int 	sigtran_event_start(void);

int	sigtran_event_exit(void);

int	sigtran_event_submit(struct osmo_fd *ofd, sigtran_transaction_t *txn);

/*
 *	sccp.c
 */
int	sigtran_tcap_outgoing(UNUSED struct msgb *msg_in, void *ctx, sigtran_transaction_t *txn, struct osmo_fd *ofd);

void	sigtran_sccp_incoming(struct mtp_link_set *set, struct msgb *msg, int sls);

int	sigtran_sscp_init(sigtran_conn_t *conn);

int	sigtran_sccp_global_init(void);

void	sigtran_sccp_global_free(void);

/*
 *	sigtran.c
 */
int	sigtran_sccp_global_title(TALLOC_CTX *ctx, uint8_t **out, int gt_ind, char const *digits,
				  uint8_t tt, uint8_t np, uint8_t es, uint8_t nai);

int	sigtran_ascii_to_tbcd(TALLOC_CTX *ctx, uint8_t **out, char const *ascii);

/*
 *	log.c
 */
void	sigtran_log_init(TALLOC_CTX *ctx);
