-- must match redis_ippool.h
local ippool_rcode = {
	success = 0,
	not_found = -1,
	expired = -2,
	device_mismatch = -3,
	pool_empty = -4,
	fail = -5
}

-- schema namespacing
local ippool_key = {
	pool = "pool",
	address = "ip",
	device = "device"
}
