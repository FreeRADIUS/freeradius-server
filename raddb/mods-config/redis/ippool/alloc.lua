-- Lua script for allocating new leases
--
-- - KEYS[1] The pool name.
-- - ARGV[1] Expires in (seconds).
-- - ARGV[2] Device identifier (administratively configured).
-- - ARGV[3] (optional) Gateway identifier.
--
-- Returns @verbatim { <rcode>[, <ip>][, <range>][, <lease time>][, <counter>] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS lease updated.
-- - IPPOOL_RCODE_POOL_EMPTY no avaliable leases in pool.

local ip
local exists
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
exists = redis.call("GET", device_key);
if exists then
  expires_in = tonumber(redis.call("ZSCORE", pool_key, exists) - time[1])
  if expires_in > 0 then
    ip = redis.call("HMGET", "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. exists, "device", "range", "counter")
    if ip and (ip[1] == ARGV[2]) then
--      if expires_in < ARGV[1] then
--        expires_in = to_number(ARGV[1])
--        redis.call("ZADD", pool_key, "XX", time[1] + expires_in, ip[1])
--      end
      return { ippool_rcode_success, exists, ip[2], expires_in, ip[3] }
    end
  end
end

expires_in = to_number(ARGV[1])

-- Else, get the IP address which expired the longest time ago.
ip = redis.call("ZREVRANGE", pool_key, -1, -1, "WITHSCORES")
if not ip or not ip[1] then
  return { ippool_rcode_pool_empty }
end
if ip[2] >= time[1] then
  return { ippool_rcode_pool_empty }
end
redis.call("ZADD", pool_key, "XX", time[1] + expires_in, ip[1])

-- Set the device/gateway keys
address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. ip[1]
redis.call("HMSET", address_key, "device", ARGV[2], "gateway", ARGV[3])
redis.call("SET", device_key, ip[1])
redis.call("EXPIRE", device_key, expires_in)
return {
  ippool_rcode_success,
  ip[1],
  redis.call("HGET", address_key, "range"),
  expires_in,
  redis.call("HINCRBY", address_key, "counter", 1)
}
