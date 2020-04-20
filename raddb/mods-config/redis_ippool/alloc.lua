-- Lua script for allocating new leases
--
-- - KEYS[1] The pool name.
-- - ARGV[1] Wall time (seconds since epoch).
-- - ARGV[2] Expires in (seconds).
-- - ARGV[3] Device identifier (administratively configured).
-- - ARGV[4] (optional) Gateway identifier.
--
-- Returns { <rcode>[, <ip>][, <range>][, <lease time>][, <counter>] }
-- - IPPOOL_RCODE_SUCCESS lease updated.
-- - IPPOOL_RCODE_NOT_FOUND lease not found in pool.

local ip
local exists

local pool_key
local address_key
local device_key

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool
device_key = "{" .. KEYS[1] .. "}:" .. ippool_key.device .. ":" .. ARGV[3]

-- Check to see if the client already has a lease,
-- and if it does return that.
--
-- The additional sanity checks are to allow for the record
-- of device/ip binding to persist for longer than the lease.
exists = redis.call("GET", device_key)
if exists then
	local expires_in = tonumber(redis.call("ZSCORE", pool_key, exists) - ARGV[1])
	if expires_in > 0 then
		ip = redis.call("HMGET", "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. exists, "device", "range", "counter")
		if ip and (ip[1] == ARGV[3]) then
--			if expires_in < ARGV[2] then
--				redis.call("ZADD", pool_key, "XX", ARGV[1] + ARGV[2], ip[1])
--				expires_in = ARGV[2]
--			end
			return { ippool_rcode.success, exists, ip[2], expires_in, ip[3] }
		end
	end
end

-- Else, get the IP address which expired the longest time ago.
ip = redis.call("ZREVRANGE", pool_key, -1, -1, "WITHSCORES")
if not ip or not ip[1] then
	return { ippool_rcode.pool_empty }
end
if ip[2] >= ARGV[1] then
	return { ippool_rcode.pool_empty }
end
redis.call("ZADD", pool_key, "XX", ARGV[1] + ARGV[2], ip[1])

-- Set the device/gateway keys
address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. ip[1]
redis.call("HMSET", address_key, "device", ARGV[3], "gateway", ARGV[4])
redis.call("SET", device_key, ip[1])
redis.call("EXPIRE", device_key, ARGV[2])

return {
	ippool_rcode.success,
	ip[1],
	redis.call("HGET", address_key, "range"),
	tonumber(ARGV[2]),
	redis.call("HINCRBY", address_key, "counter", 1)
}
