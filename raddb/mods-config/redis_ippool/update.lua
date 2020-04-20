-- Lua script for updating leases
--
-- - KEYS[1] The pool name.
-- - ARGV[1] Wall time (seconds since epoch).
-- - ARGV[2] Expires in (seconds).
-- - ARGV[3] IP address to update.
-- - ARGV[4] Device identifier.
-- - ARGV[5] (optional) Gateway identifier.
--
-- Returns array { <rcode>[, <range>] }
-- - IPPOOL_RCODE_SUCCESS lease updated.
-- - IPPOOL_RCODE_NOT_FOUND lease not found in pool.
-- - IPPOOL_RCODE_EXPIRED lease has already expired.
-- - IPPOOL_RCODE_DEVICE_MISMATCH lease was allocated to a different client.

local ret
local found

local pool_key
local address_key
local device_key

-- We either need to know that the IP was last allocated to the
-- same device, or that the lease on the IP has NOT expired.
address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. ARGV[3]
found = redis.call("HMGET", address_key, "range", "device", "gateway", "counter" )

-- Range may be nil (if not used), so we use the device key
if not found[2] then
	return { ippool_rcode.not_found }
end
if found[2] ~= ARGV[4] then
	return { ippool_rcode.device_mismatch, found[2]}
end

-- Update the expiry time
pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool
redis.call("ZADD", pool_key, "XX", ARGV[1] + ARGV[2], ARGV[3])

-- The device key should usually exist, but
-- theoretically, if we were right on the cusp
-- of a lease being expired, it may have been
-- removed.
device_key = "{" .. KEYS[1] .. "}:" .. ippool_key.device .. ":" .. ARGV[4]
if redis.call("EXPIRE", device_key, ARGV[2]) == 0 then
	redis.call("SET", device_key, ARGV[3])
	redis.call("EXPIRE", device_key, ARGV[2])
end

-- Update the gateway address
if ARGV[5] ~= found[3] then
	redis.call("HSET", address_key, "gateway", ARGV[5])
end

return {
	ippool_rcode.success,
	found[1],
	found[4]
}
