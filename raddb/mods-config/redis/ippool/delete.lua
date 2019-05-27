-- Lua script for deleting a lease
--
-- - KEYS[1] pool name
-- - ARGV[1] IP address to remove
-- - ARGV[2] prefix to add (0 = auto => 64 for IPv6, 32 for IPv4)
--
-- Returns @verbatim array { <rcode>[, <counter>] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS lease updated
-- - IPPOOL_RCODE_NOT_FOUND lease not found in pool
-- - IPPOOL_RCODE_FAIL

local range = iptool.parse(ARGV[1])
local prefix = toprefix(ARGV[1], ARGV[2])

guard(range, prefix)

local pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool
local address_key
local device_key
local device

local counter = 0
for addr in iptool.iter(range, prefix) do
	address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. addr

	device = redis.call("HGET", address_key, "device")
	if device then
		device_key = "{" .. KEYS[1] .. "}:" .. ippool_key_device .. ":" .. device
		redis.call("DEL", device_key)
	end

	redis.call("DEL", address_key)

	counter = counter + redis.call("ZREM", pool_key, addr)
end

return {
	ippool_rcode_success,
	counter
}
