-- Lua script for modifying range of lease
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address of lease.
-- - ARGV[2] range.
--
-- Returns array { <rcode> }
-- - IPPOOL_RCODE_SUCCESS lease updated.

local address_key

address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. ARGV[1]

return {
	ippool_rcode.success,
	redis.call("HSET", address_key, "range", ARGV[2])
}
