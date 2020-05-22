-- Lua script for releasing leases
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address to release.
-- - ARGV[2] Client identifier.
--
-- Sets the expiry time to be NOW() - 1 to maximise time between
-- IP address allocations.
--
-- Returns array { <rcode>[, <counter>] }
-- - IPPOOL_RCODE_SUCCESS lease updated.
-- - IPPOOL_RCODE_NOT_FOUND lease not found in pool.
-- - IPPOOL_RCODE_DEVICE_MISMATCH lease was allocated to a different client.

local ret
local found

local pool_key
local address_key
local device_key

local time

-- Check that the device releasing was the one
-- the IP address is allocated to.
address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. ARGV[1]
found = redis.call("HGET", address_key, "device")
if not found then
	return { ippool_rcode.not_found }
end
if found and found ~= ARGV[2] then
	return { ippool_rcode.device_mismatch, found[2] }
end

time = tonumber(redis.call("TIME")[1])

-- Set expiry time to now() - 1
pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool
redis.call("ZADD", pool_key, "XX", time - 1, ARGV[1])

-- Remove the association between the device and a lease
device_key = "{" .. KEYS[1] .. "}:" .. ippool_key.device .. ":" .. ARGV[2]
redis.call("DEL", device_key)

return {
	ippool_rcode.success,
	redis.call("HINCRBY", address_key, "counter", 1) - 1
}
