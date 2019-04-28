-- must match redis_ippool.h
local ippool_rcode_success = 0
local ippool_rcode_not_found = -1
local ippool_rcode_expired = -2
local ippool_rcode_device_mismatch = -3
local ippool_rcode_pool_empty = -4
local ippool_rcode_fail = -5
-- schema namespacing
local ippool_key_pool = "pool"
local ippool_key_address = "ip"
local ippool_key_device = "device"
local ippool_key_netinfo = "netinfo"
