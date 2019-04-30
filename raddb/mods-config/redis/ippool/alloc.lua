-- Lua script for allocating new leases
--
-- - KEYS[1] The pool name.
-- - ARGV[1] Expires in (seconds).
-- - ARGV[2] Device identifier (administratively configured).
-- - ARGV[3] (optional) Gateway identifier.
--
-- Returns @verbatim { <rcode>[, <ip>][, <range>] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS lease updated.
-- - IPPOOL_RCODE_POOL_EMPTY no avaliable leases in pool.

local ip
local expires_in
local time

local pool_key
local address_key
local device_key

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool
device_key = "{" .. KEYS[1] .. "}:" .. ippool_key_device .. ":" .. ARGV[2]

time = redis.call("TIME")

-- Check to see if the client already has a lease,
-- and if it does return that.
--
-- The additional sanity checks are to allow for the record
-- of device/ip binding to persist for longer than the lease.
ip = redis.call("GET", device_key);
if ip then
  expires_in = tonumber(redis.call("ZSCORE", pool_key, ip) - time[1])
  -- when positive, we have to check it is still for the same device
  if expires_in >= 0 then
    address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. ip
    if redis.call("HGET", address_key, "device") ~= ARGV[2] then
      ip = nil
    end
  end
end

-- Else, get the IP address which expired the longest time ago.
if not ip then
  ip = redis.call("ZREVRANGE", pool_key, -1, -1, "WITHSCORES")
  if not ip or not ip[1] or ip[2] >= time[1] then
    return { ippool_rcode_pool_empty }
  end
  ip = ip[1]
end

expires_in = to_number(ARGV[1])

redis.call("ZADD", pool_key, "XX", time[1] + expires_in, ip)

-- Set the device/gateway keys
address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. ip
redis.call("HMSET", address_key, "device", ARGV[2], "gateway", ARGV[3])

-- we expire device_key significantly later to enable sticky IPs
redis.call("SET", device_key, ip, "EX", 10 * expires_in)

redis.call("HINCRBY", address_key, "counter", 1)

return {
  ippool_rcode_success,
  ip,
  redis.call("HGET", address_key, "range")
}
