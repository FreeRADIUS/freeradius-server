-- Lua script for releasing leases
--
-- - KEYS[1] The pool name.
-- - ARGV[1] Wall time (seconds since epoch).
-- - ARGV[2] IP address to release.
-- - ARGV[3] (optional) Client identifier.
--
-- Sets the expiry time to be NOW() - 1 to maximise time between
-- IP address allocations.
--
-- Returns @verbatim array { <rcode>[, <counter>] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS lease updated..
-- - IPPOOL_RCODE_NOT_FOUND lease not found in pool.
-- - IPPOOL_RCODE_EXPIRED lease already expired
-- - IPPOOL_RCODE_DEVICE_MISMATCH lease was allocated to a different client..

local ret
local found

local pool_key
local address_key
local device_key

-- Check that the device releasing was the one
-- the IP address is allocated to.
address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. ARGV[2]
if ARGV[3] then
  found = redis.call("HGET", address_key, "device")

  if not found then
    return { ippool_rcode_not_found }
  else if found ~= ARGV[3] then
    return { ippool_rcode_device_mismatch, found }
  end
end

-- Set expiry time to now() - 1
pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool
ret = redis.call("ZADD", pool_key, "XX", "CH", ARGV[1] - 1, ARGV[2])

if ret == 0 then
  return { ippool_rcode_expired }
end

-- Remove the association between the device and a lease
device_key = "{" .. KEYS[1] .. "}:" .. ippool_key_device .. ":" .. ARGV[3]
redis.call("DEL", device_key)

return {
  ippool_rcode_success,
  redis.call("HINCRBY", address_key, "counter", 1) - 1
}
