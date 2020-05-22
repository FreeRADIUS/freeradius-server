-- Lua script for adding a pool
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address of lease.
-- - ARGV[2] range.
--
-- Returns array { <rcode> }
-- - IPPOOL_RCODE_SUCCESS lease updated.

local ret

local pool_key
local address_key

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool
ret = redis.call("ZADD", pool_key, "NX", 0, ARGV[1])

if ARGV[2] then
	address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. ARGV[1]
	ret = redis.call("HSET", address_key, "range", ARGV[2]) or ret
end

return {
	ippool_rcode.success,
	ret
}
