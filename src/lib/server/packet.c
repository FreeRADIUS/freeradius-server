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

/** fr_radius_packet_t alloc/free functions
 *
 * @file src/lib/server/packet.c
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/packet.h>
#include <freeradius-devel/util/pair_legacy.h>

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

	vp = fr_pair_afrom_da(ctx, attr_ip);
	if (!vp) return -1;
	fr_value_box_ipaddr(&vp->data, attr_ip, ipaddr, false);
	fr_pair_set_immutable(vp);
	fr_pair_append(list, vp);

	vp = fr_pair_afrom_da(ctx, attr_port);
	if (!vp) return -1;
	vp->vp_uint16 = port;
	fr_pair_set_immutable(vp);
	fr_pair_append(list, vp);

	return 0;
}

/** Allocate a "Net." struct with src/dst host and port.
 *
 * @param      ctx    The context in which the packet is allocated.
 * @param[in]  list   #fr_pair_list_t value to resolve to #fr_radius_packet_t.
 * @param[out] packet The request packet.
 *
 * @return
 *	-  0 on success
 *	- <0 on error.
 */
int fr_packet_pairs_from_packet(TALLOC_CTX *ctx, fr_pair_list_t *list, fr_radius_packet_t const *packet)
{
	fr_pair_t *vp, *net, *tlv;

	/*
	 *	We overload the pair_legacy_nested flag, as we can't
	 *	call main_config_migrate_option_get(), as this file is
	 *	also included in radclient. :(
	 */
	if (!fr_pair_legacy_nested) {
		if (inet2pairs(ctx, list, attr_net_src_ip, attr_net_src_port, &packet->socket.inet.src_ipaddr, packet->socket.inet.src_port) < 0) return -1;

		if (inet2pairs(ctx, list, attr_net_dst_ip, attr_net_dst_port, &packet->socket.inet.dst_ipaddr, packet->socket.inet.dst_port) < 0) return -1;

		vp = fr_pair_afrom_da(ctx, attr_net_timestamp);
		if (!vp) return -1;
		vp->vp_date = fr_time_to_unix_time(packet->timestamp);
		fr_pair_set_immutable(vp);
		fr_pair_append(list, vp);

		return 0;
	}

	/*
	 *	Net
	 */
	net = fr_pair_afrom_da(ctx, attr_net);
	if (!net) return -1;
	fr_pair_append(list, net);

	/*
	 *	Net.Src
	 */
	tlv = fr_pair_afrom_da(net, attr_net_src);
	if (!tlv) return -1;
	fr_pair_append(&net->vp_group, tlv);

	if (inet2pairs(tlv, &tlv->vp_group, attr_net_src_ip, attr_net_src_port, &packet->socket.inet.src_ipaddr, packet->socket.inet.src_port) < 0) return -1;

	/*
	 *	Net.Dst
	 */
	tlv = fr_pair_afrom_da(net, attr_net_dst);
	if (!tlv) return -1;
	fr_pair_append(&net->vp_group, tlv);
	
	if (inet2pairs(tlv, &tlv->vp_group, attr_net_src_ip, attr_net_src_port, &packet->socket.inet.src_ipaddr, packet->socket.inet.src_port) < 0) return -1;

	/*
	 *	Timestamp
	 */
	vp = fr_pair_afrom_da(net, attr_net_timestamp);
	if (!vp) return -1;
	vp->vp_date = fr_time_to_unix_time(packet->timestamp);
	fr_pair_set_immutable(vp);
	fr_pair_append(&net->vp_group, vp);

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
void fr_packet_pairs_to_packet(fr_radius_packet_t *packet, fr_pair_list_t const *list)
{
	fr_pair_t *vp, *net, *tlv;

	/*
	 *	@todo - create nested ones!
	 */
	if (!fr_pair_legacy_nested) {
		pairs2inet(&packet->socket.inet.src_ipaddr, &packet->socket.inet.src_port, list,
			   attr_net_src_ip, attr_net_src_port);

		pairs2inet(&packet->socket.inet.dst_ipaddr, &packet->socket.inet.dst_port, list,
			   attr_net_dst_ip, attr_net_dst_port);

		vp = fr_pair_find_by_da(list, NULL, attr_net_timestamp);
		if (vp) packet->timestamp = fr_time_add(packet->timestamp, vp->vp_time_delta);
	}

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

/** Initialises the Net. packet attributes.
 *
 * @note Call packet_global_free() when the server is done to avoid leaks.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int packet_global_init(void)
{
	if (fr_dict_autoload(util_packet_dict) < 0) {
	error:
		fr_perror("packet_global_init");
		return -1;
	}

	if (fr_dict_attr_autoload(util_packet_dict_attr) < 0) goto error;

	return 0;
}

void packet_global_free(void)
{
	fr_dict_autofree(util_packet_dict);
}
