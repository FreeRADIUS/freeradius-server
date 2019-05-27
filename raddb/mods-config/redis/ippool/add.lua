-- Lua script for adding leases
--
-- - KEYS[1] pool name
-- - ARGV[1] IP address/range to add
-- - ARGV[2] prefix to add (0 = auto => 64 for IPv6, 32 for IPv4)
-- - ARGV[3] (optional) range id
--
-- Returns @verbatim array { <rcode>[, <counter>] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS lease added or updated
-- - IPPOOL_RCODE_FAIL

local range = iptool.parse(ARGV[1])
local prefix = toprefix(ARGV[1], ARGV[2])

guard(range, prefix)

local pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool
local address_key

local counter = 0
for addr in iptool.iter(range, prefix) do
	-- we do not try to skip on broadcast/network IPv4 addresses as they are
	-- usable in some configurations, and trivial to prune post-insertion

	address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. addr

	counter = counter + redis.call("ZADD", pool_key, "NX", 0, addr)

	redis.call("HSETNX", address_key, "counter", 0)

	-- Zero length ranges are allowed, and should be preserved
	if ARGV[3] then
		redis.call("HSET", address_key, "range", ARGV[3])
	else
		redis.call("HDEL", address_key, "range")
	end
end

return {
	ippool_rcode_success,
	counter
}
