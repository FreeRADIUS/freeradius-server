-- Lua script for updating leases
--
-- - KEYS[1] pool name
-- - ARGV[1] IP address to update
-- - ARGV[2] expires in (seconds)
-- - ARGV[3] device identifier (administratively configured)
-- - ARGV[4] (optional) gateway identifier
--
-- Returns @verbatim array { <rcode>[, <range>] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS lease updated
-- - IPPOOL_RCODE_NOT_FOUND lease not found in pool
-- - IPPOOL_RCODE_EXPIRED lease has already expired
-- - IPPOOL_RCODE_DEVICE_MISMATCH lease was allocated to a different client

local addr = iptool.norm(ARGV[1])

local pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool
local address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. addr
local device_key = "{" .. KEYS[1] .. "}:" .. ippool_key_device .. ":" .. ARGV[3]

-- We either need to know that the IP was last allocated to the
-- same device, or that the lease on the IP has NOT expired.
local found = redis.call("HMGET", address_key, "range", "device")

if not found[2] then
  return { ippool_rcode_not_found }
elseif found[2] ~= ARGV[3] then
  return { ippool_rcode_device_mismatch, found[2] }
end

local time = redis.call("TIME")

redis.call("ZADD", pool_key, "XX", time[1] + ARGV[2], ARGV[1])

-- we expire device_key significantly later to enable sticky IPs
redis.call("SET", device_key, ARGV[1], "EX", 10 * ARGV[2])

if ARGV[4] then
	redis.call("HSET", address_key, "gateway", ARGV[4])
end

return {
	ippool_rcode_success,
	found[1]
}
