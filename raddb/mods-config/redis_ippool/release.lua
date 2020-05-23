-- Lua script for releasing leases
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address/range of lease(s).
-- - ARGV[2] Prefix to add (0 = auto => 64 for IPv6, 32 for IPv4).
-- - ARGV[3] (optional) Client identifier; use only as a guard when releasing a single IP.
--
-- Removes the IP entry in the ZSET, then removes the address hash, and the device key
-- if one exists. Will do nothing if the lease is not found in the ZSET.
--
-- Sticky IPs work by setting the TTL on the device_key to 10x so do not remove it
--
-- Sets the expiry time to be NOW() - 1 to maximise time between IP address allocations and
-- improve the changes of Sticky IP opportunities.
--
-- Returns array { <rcode>[, <counter> ] }
-- - IPPOOL_RCODE_SUCCESS
-- - IPPOOL_RCODE_FAIL
-- - IPPOOL_RCODE_NOT_FOUND
-- - IPPOOL_RCODE_DEVICE_MISMATCH

local ok
local range
local prefix

local pool_key

local time
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

time = tonumber(redis.call("TIME")[1])

counter = 0
for addr in iptool.iter(range, prefix) do
	local address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. addr

	-- Check that the device releasing was the one the IP address is allocated to.
	if ARGV[3] then
		local found = redis.call("HGET", address_key, "device")
		if found and found ~= ARGV[3] then
			return { ippool_rcode.device_mismatch, found }
		end
	end

	local ret = redis.call("ZADD", pool_key, "XX", time - 1, addr)
	if ret == 1 then
		redis.call("HINCRBY", address_key, "counter", 1)
		counter = counter + 1
	end
end

return {
	ippool_rcode.success,
	counter,
}
