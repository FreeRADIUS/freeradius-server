-- Lua script for allocating new leases
--
-- - KEYS[1] pool name
-- - ARGV[1] expires in (seconds)
-- - ARGV[2] device identifier (administratively configured)
-- - ARGV[3] (optional) gateway identifier
--
-- Returns @verbatim { <rcode>[, <ip>][, <range>] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS lease updated.
-- - IPPOOL_RCODE_POOL_EMPTY no avaliable leases in pool.

local pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool
local address_key
local device_key = "{" .. KEYS[1] .. "}:" .. ippool_key_device .. ":" .. ARGV[2]

local time = redis.call("TIME")

local ip

-- Check to see if the client already has a lease,
-- and if it does return that.
--
-- The additional sanity checks are to allow for the record
-- of device/ip binding to persist for longer than the lease.
ip = redis.call("GET", device_key)
if ip then
	local epoch = redis.call("ZSCORE", pool_key, ip)
	if epoch == nil then
		ip = nil
	-- when positive, we have to check it is still for the same device
	elseif epoch - time[1] >= 0 then
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

redis.call("ZADD", pool_key, "XX", time[1] + ARGV[1], ip)

address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. ip

redis.call("HINCRBY", address_key, "counter", 1)

redis.call("HSET", address_key, "device", ARGV[2])

if ARGV[3] then
	redis.call("HSET", address_key, "gateway", ARGV[3])
else
	redis.call("HDEL", address_key, "gateway")
end

-- we expire device_key significantly later to enable sticky IPs
redis.call("SET", device_key, ip, "EX", 10 * ARGV[1])

return {
  ippool_rcode_success,
  ip,
  redis.call("HGET", address_key, "range")
}
