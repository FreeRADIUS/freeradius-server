-- Lua script for deleting a lease
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address/range of lease(s).
-- - ARGV[2] Prefix to add (0 = auto => 64 for IPv6, 32 for IPv4).
--
-- Removes the IP entry in the ZSET, then removes the address hash, and the device key
-- if one exists.
--
-- Will work with partially removed IP addresses (where the ZSET entry is absent but other
-- elements were not cleaned up).
--
-- Returns array { <rcode>[, <counter> ] }
-- - IPPOOL_RCODE_SUCCESS
-- - IPPOOL_RCODE_FAIL

local ok
local range
local prefix

local pool_key

local counter

ok, range = pcall(iptool.parse, ARGV[1])
if not ok then
	return { ippool_rcode_fail }
end
prefix = toprefix(ARGV[1], ARGV[2])
if guard(range, prefix) then
	return { ippool_rcode_fail }
end

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool

counter = 0
for addr in iptool.iter(range, prefix) do
	local ret = redis.call("ZREM", pool_key, addr)
	local address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. addr

	local found = redis.call("HGET", address_key, "device")
	if found then
		local device_key = "{" .. KEYS[1] .. "}:" .. ippool_key.device .. ":" .. found

		ret = redis.call("DEL", address_key) or ret
		-- Remove the association between the device and a lease
		ret = redis.call("DEL", device_key) or ret
	end

	counter = counter + ret
end

return {
	ippool_rcode.success,
	counter
}
