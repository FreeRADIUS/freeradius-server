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

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t util_packet_dict[];
fr_dict_autoload_t util_packet_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_net_tlv;
static fr_dict_attr_t const *attr_net_src_ip;
static fr_dict_attr_t const *attr_net_src_port;
static fr_dict_attr_t const *attr_net_dst_ip;
static fr_dict_attr_t const *attr_net_dst_port;
static fr_dict_attr_t const *attr_net_timestamp;

extern fr_dict_attr_autoload_t util_packet_dict_attr[];
fr_dict_attr_autoload_t util_packet_dict_attr[] = {
	{ .out = &attr_net_tlv, .name = "Net", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_net_src_ip, .name = "Net.Src.IP", .type = FR_TYPE_COMBO_IP_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_net_src_port, .name = "Net.Src.Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_net_dst_ip, .name = "Net.Dst.IP", .type = FR_TYPE_COMBO_IP_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_net_dst_port, .name = "Net.Dst.Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_net_timestamp, .name = "Net.Timestamp", .type = FR_TYPE_DATE, .dict = &dict_freeradius },

	{ NULL }
};

/** Allocate a "Net." struct with src/dst host and port.
 *
 * @param      ctx    The context in which the packet is allocated.
 * @param[in]  list   #fr_pair_list_t value to resolve to #fr_radius_packet_t.
 * @param[out] packet The request packet.
 *
 * @return
 *	-  0 on success
 *	- -1 on error.
 */
int fr_packet_pairs_from_packet(TALLOC_CTX *ctx, fr_pair_list_t *list, fr_radius_packet_t const *packet)
{
	fr_pair_t *vp;

	/*
	 *	@todo - create nested ones!
	 *
	 *	We can't call main_config_migrate_option_get(), as this file is also included in radclient. :(
	 */
	vp = fr_pair_afrom_da(ctx, attr_net_src_ip);
	if (!vp) return -1;
	fr_value_box_ipaddr(&vp->data, attr_net_src_ip, &packet->socket.inet.src_ipaddr, true);
	fr_pair_append(list, vp);

	vp = fr_pair_afrom_da(ctx, attr_net_src_port);
	if (!vp) return -1;
	vp->vp_uint32 = packet->socket.inet.src_port;	
	fr_pair_append(list, vp);

	vp = fr_pair_afrom_da(ctx, attr_net_dst_ip);
	if (!vp) return -1;
	fr_value_box_ipaddr(&vp->data, attr_net_dst_ip, &packet->socket.inet.dst_ipaddr, true);
	fr_pair_append(list, vp);

	vp = fr_pair_afrom_da(ctx, attr_net_dst_port);
	if (!vp) return -1;
	vp->vp_uint32 = packet->socket.inet.dst_port;	
	fr_pair_append(list, vp);

	vp = fr_pair_afrom_da(ctx, attr_net_timestamp);
	if (!vp) return -1;
	vp->vp_date = fr_time_to_unix_time(packet->timestamp);
	fr_pair_append(list, vp);

	return 0;
}

int fr_packet_pairs_to_packet(fr_radius_packet_t *packet, fr_pair_list_t const *list)
{
	fr_pair_t *vp;

	/*
	 *	@todo - create nested ones!
	 */
	vp = fr_pair_find_by_da(list, NULL, attr_net_src_ip);
	if (vp) packet->socket.inet.src_ipaddr = vp->vp_ip;

	vp = fr_pair_find_by_da(list, NULL, attr_net_src_port);
	if (vp) packet->socket.inet.src_port = vp->vp_uint16;

	vp = fr_pair_find_by_da(list, NULL, attr_net_dst_ip);
	if (vp) packet->socket.inet.dst_ipaddr = vp->vp_ip;

	vp = fr_pair_find_by_da(list, NULL, attr_net_dst_port);
	if (vp) packet->socket.inet.dst_port = vp->vp_uint16;

	vp = fr_pair_find_by_da(list, NULL, attr_net_timestamp);
	if (vp) packet->timestamp = fr_time_add(packet->timestamp, vp->vp_time_delta);

	return 0;
}

/** Initialises the Net. packet attributes.
 *
 * @note Call log free when the server is done to fix any spurious memory leaks.
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
