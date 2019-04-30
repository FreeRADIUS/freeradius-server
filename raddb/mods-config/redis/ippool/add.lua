-- Lua script for adding leases
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address to add.
-- - ARGV[2] (optional) Range ID
--
-- Returns @verbatim array { <rcode>[, <counter>] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS lease updated..

local ret

local pool_key
local address_key

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool
ret = redis.call("ZADD", pool_key, "NX", "CH", 0, ARGV[1])

address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. ARGV[1]

redis.call("HSETNX", address_key, "counter", 0)

-- Zero length ranges are allowed, and should be preserved
if ARGV[2] then
  redis.call("HSET", address_key, "range", ARGV[2])
else
  redis.call("HDEL", address_key, "range")
end

return {
  ippool_rcode_success,
  ret
}

