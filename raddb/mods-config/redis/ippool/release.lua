-- Lua script for releasing leases
--
-- - KEYS[1] pool name
-- - ARGV[1] IP address/range to release
-- - ARGV[2] prefix to add (0 = auto => 64 for IPv6, 32 for IPv4)
--
-- Returns @verbatim array { <rcode>[, <counter>] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS lease updated
-- - IPPOOL_RCODE_FAIL

local range = iptool.parse(ARGV[1])
local prefix = toprefix(ARGV[1], ARGV[2])

guard(range, prefix)

local pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool
local address_key

local time = redis.call("TIME")

local counter = 0
for addr in iptool.iter(range, prefix) do
	-- we do not try to skip on broadcast/network IPv4 addresses as they are
	-- usable in some configurations, and trivial to prune post-insertion

	address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. addr

	-- maximise time between allocations
	redis.call("ZADD", pool_key, "XX", time[1] - 1, addr)
end

return {
	ippool_rcode_success,
	counter
}
