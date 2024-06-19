/*
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** fr_packet_t alloc/free functions
 *
 * @file src/lib/server/packet.c
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/pair_legacy.h>

#include <freeradius-devel/server/packet.h>

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t util_packet_dict[];
fr_dict_autoload_t util_packet_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_net;
static fr_dict_attr_t const *attr_net_src;
static fr_dict_attr_t const *attr_net_src_ip;
static fr_dict_attr_t const *attr_net_src_port;
static fr_dict_attr_t const *attr_net_dst;
static fr_dict_attr_t const *attr_net_dst_ip;
static fr_dict_attr_t const *attr_net_dst_port;
static fr_dict_attr_t const *attr_net_timestamp;

extern fr_dict_attr_autoload_t util_packet_dict_attr[];
fr_dict_attr_autoload_t util_packet_dict_attr[] = {
	{ .out = &attr_net, .name = "Net", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_net_src, .name = "Net.Src", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_net_dst, .name = "Net.Dst", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_net_src_ip, .name = "Net.Src.IP", .type = FR_TYPE_COMBO_IP_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_net_src_port, .name = "Net.Src.Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_net_dst_ip, .name = "Net.Dst.IP", .type = FR_TYPE_COMBO_IP_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_net_dst_port, .name = "Net.Dst.Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_net_timestamp, .name = "Net.Timestamp", .type = FR_TYPE_DATE, .dict = &dict_freeradius },

	{ NULL }
};

static int inet2pairs(TALLOC_CTX *ctx, fr_pair_list_t *list,
		      fr_dict_attr_t const *attr_ip, fr_dict_attr_t const *attr_port,
		      fr_ipaddr_t const *ipaddr, uint16_t port)
{
	fr_pair_t *vp;

	if (fr_pair_find_or_append_by_da(ctx, &vp, list, attr_ip) < 0) return -1;
	fr_value_box_ipaddr(&vp->data, attr_ip, ipaddr, false);
	fr_pair_set_immutable(vp);

	if (fr_pair_find_or_append_by_da(ctx, &vp, list, attr_port) < 0) return -1;
	vp->vp_uint16 = port;
	fr_pair_set_immutable(vp);

	return 0;
}

/** Allocate a "Net." struct with src/dst host and port.
 *
 * @param      ctx    The context in which the packet is allocated.
 * @param[in]  list   #fr_pair_list_t value to resolve to #fr_packet_t.
 * @param[out] packet The request packet.
 *
 * @return
 *	-  0 on success
 *	- <0 on error.
 */
int fr_packet_pairs_from_packet(TALLOC_CTX *ctx, fr_pair_list_t *list, fr_packet_t const *packet)
{
	fr_pair_t *vp, *net, *tlv;

	/*
	 *	Net
	 */
	if (fr_pair_find_or_append_by_da(ctx, &net, list, attr_net) < 0) return -1;

	/*
	 *	Net.Src
	 */
	if (fr_pair_find_or_append_by_da(net, &tlv, &net->vp_group, attr_net_src) < 0) return -1;

	if (inet2pairs(tlv, &tlv->vp_group, attr_net_src_ip, attr_net_src_port, &packet->socket.inet.src_ipaddr, packet->socket.inet.src_port) < 0) return -1;

	/*
	 *	Net.Dst
	 */
	if (fr_pair_find_or_append_by_da(net, &tlv, &net->vp_group, attr_net_dst) < 0) return -1;

	if (inet2pairs(tlv, &tlv->vp_group, attr_net_dst_ip, attr_net_dst_port, &packet->socket.inet.dst_ipaddr, packet->socket.inet.dst_port) < 0) return -1;

	/*
	 *	Timestamp
	 */
	if (fr_pair_find_or_append_by_da(net, &vp, &net->vp_group, attr_net_timestamp) < 0) return -1;
	vp->vp_date = fr_time_to_unix_time(packet->timestamp);
	fr_pair_set_immutable(vp);

	return 0;
}

static void pairs2inet(fr_ipaddr_t *ipaddr, uint16_t *port, fr_pair_list_t const *list,
		       fr_dict_attr_t const *attr_ip, fr_dict_attr_t const *attr_port)
{
	fr_pair_t *vp;

	vp = fr_pair_find_by_da(list, NULL, attr_ip);
	if (vp) *ipaddr = vp->vp_ip;

	vp = fr_pair_find_by_da(list, NULL, attr_port);
	if (vp) *port = vp->vp_uint16;
}

/** Convert pairs to information in a packet.
 *
 * @param packet	the packet to send
 * @param list		the list to check for Net.*
 */
void fr_packet_net_from_pairs(fr_packet_t *packet, fr_pair_list_t const *list)
{
	fr_pair_t *net, *tlv;

	net = fr_pair_find_by_da(list, NULL, attr_net);
	if (!net) return;

	tlv = fr_pair_find_by_da(&net->vp_group, NULL, attr_net_src);
	if (tlv) {
		pairs2inet(&packet->socket.inet.src_ipaddr, &packet->socket.inet.src_port, &tlv->vp_group,
			   attr_net_src_ip, attr_net_src_port);
	}

	tlv = fr_pair_find_by_da(&net->vp_group, NULL, attr_net_dst);
	if (tlv) {
		pairs2inet(&packet->socket.inet.dst_ipaddr, &packet->socket.inet.dst_port, &tlv->vp_group,
			   attr_net_dst_ip, attr_net_dst_port);
	}
}

static int _packet_global_free(UNUSED void *uctx)
{
	fr_dict_autofree(util_packet_dict);

	return 0;
}

static int _packet_global_init(UNUSED void *uctx)
{
	if (fr_dict_autoload(util_packet_dict) < 0) {
	error:
		fr_perror("packet_global_init");
		return -1;
	}

	if (fr_dict_attr_autoload(util_packet_dict_attr) < 0) goto error;

	return 0;
}

/** Initialises the Net. packet attributes.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int packet_global_init(void)
{
	int ret;

	fr_atexit_global_once_ret(&ret, _packet_global_init, _packet_global_free, NULL);

	return ret;
}
