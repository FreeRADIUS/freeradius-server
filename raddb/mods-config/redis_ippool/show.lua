-- Lua script for showing lease
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address of lease.
--
-- Returns array { <rcode>[, <counter>] }
-- - IPPOOL_RCODE_SUCCESS lease updated.
-- - IPPOOL_RCODE_NOT_FOUND lease not found in pool.

local pool_key
local address_key

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool
address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. ARGV[1]

return {
	ippool_rcode.success,
	redis.call("ZSCORE", pool_key, ARGV[1]),
	unpack(redis.call("HMGET", address_key, "device", "gateway", "range"))
}
