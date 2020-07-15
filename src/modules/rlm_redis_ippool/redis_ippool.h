#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

/**
 * $Id$
 * @file redis_ippool.h
 * @brief Common functions for interacting with Redis cluster via Hiredis
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(redis_ippool_h, "$Id$")

typedef enum {
	IPPOOL_RCODE_SUCCESS = 0,
	IPPOOL_RCODE_NOT_FOUND = -1,
	IPPOOL_RCODE_EXPIRED = -2,
	IPPOOL_RCODE_DEVICE_MISMATCH = -3,
	IPPOOL_RCODE_POOL_EMPTY = -4,
	IPPOOL_RCODE_FAIL = -5
} ippool_rcode_t;

typedef enum {
	POOL_ACTION_ALLOCATE = 1,
	POOL_ACTION_UPDATE = 2,
	POOL_ACTION_RELEASE = 3,
	POOL_ACTION_BULK_RELEASE = 4,
} ippool_action_t;

#define IPPOOL_MAX_KEY_PREFIX_SIZE	128
#define IPPOOL_POOL_KEY			"pool"
#define IPPOOL_ADDRESS_KEY		"ip"
#define IPPOOL_DEVICE_KEY		"device"

/** {prefix}:pool
 */
#define IPPOOL_MAX_POOL_KEY_SIZE	IPPOOL_MAX_KEY_PREFIX_SIZE + (sizeof("{}:" IPPOOL_POOL_KEY) - 1) + 2

/** {prefix}:ipaddr/prefix
 */
#define IPPOOL_MAX_IP_KEY_SIZE		IPPOOL_MAX_KEY_PREFIX_SIZE + (sizeof("{}:" IPPOOL_ADDRESS_KEY ":") - 1) + INET6_ADDRSTRLEN + 4


#define IPADDR_LEN(_af) ((_af == AF_UNSPEC) ? 0 : ((_af == AF_INET6) ? 128 : 32))

/** Wrap the prefix in {} and add the pool suffix
 *
 */
#define IPPOOL_BUILD_KEY(_buff, _p, _key, _key_len) \
do { \
	*_p++ = '{'; \
	memcpy(_p, _key, _key_len); \
	_p += _key_len; \
	*_p++ = '}'; \
	*_p++ = ':'; \
	memcpy(_p, IPPOOL_POOL_KEY, sizeof(IPPOOL_POOL_KEY) - 1); \
	_p +=  sizeof(IPPOOL_POOL_KEY) - 1; \
} while (0)

/** Build the IP key {prefix}:ip
 *
 */
#define IPPOOL_BUILD_IP_KEY(_buff, _p, _key, _key_len, _ip) \
do { \
	ssize_t _slen; \
	*_p++ = '{'; \
	memcpy(_p, _key, _key_len); \
	_p += _key_len; \
	_slen = strlcpy((char *)_p, "}:"IPPOOL_ADDRESS_KEY":", sizeof(_buff) - (_p - _buff)); \
	if (is_truncated((size_t)_slen, sizeof(_buff) - (_p - _buff))) { \
		REDEBUG("IP key too long"); \
		ret = IPPOOL_RCODE_FAIL; \
		goto finish; \
	} \
	_p += (size_t)_slen;\
	_slen = fr_pair_value_snprint((char *)_p, sizeof(_buff) - (_p - _buff), _ip, '\0'); \
	if (is_truncated((size_t)_slen, sizeof(_buff) - (_p - _buff))) { \
		REDEBUG("IP key too long"); \
		ret = IPPOOL_RCODE_FAIL; \
		goto finish; \
	} \
	_p += (size_t)_slen;\
} while (0)

/** If the prefix is as wide as the AF data size then print it without CIDR notation.
 *
 */
#define IPPOOL_SPRINT_IP(_buff, _ip, _prefix) \
do { \
	if (_prefix == IPADDR_LEN((_ip)->af)) { \
		inet_ntop((_ip)->af, &((_ip)->addr), _buff, sizeof(_buff)); \
	} else { \
		uint8_t _net = (_ip)->prefix; \
		(_ip)->prefix = _prefix; \
		fr_inet_ntop_prefix(_buff, sizeof(_buff), _ip); \
		(_ip)->prefix = _net; \
	} \
} while (0)
