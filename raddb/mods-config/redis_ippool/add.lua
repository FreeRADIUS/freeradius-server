-- Lua script for adding a pool
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address of lease.
-- - ARGV[2] range.
--
-- Returns array { <rcode> }
-- - IPPOOL_RCODE_SUCCESS lease updated.

local pool_key
local address_key

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool

if ARGV[2] ~= nil then
	address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. ARGV[1]
	redis.call("HSET", address_key, "range", ARGV[2])
end

return {
	ippool_rcode.success,
	redis.call("ZADD", pool_key, "NX", 0, ARGV[1])
}
