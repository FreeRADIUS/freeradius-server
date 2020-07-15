-- Lua script for allocating new leases
--
-- - KEYS[1] The pool name.
-- - ARGV[1] Expires in (seconds).
-- - ARGV[2] Device identifier (administratively configured).
-- - ARGV[3] (optional) Gateway identifier.
--
-- Sticky IPs work by setting the TTL on the device_key to 10x ARGV[1]
--
-- Returns { <rcode>[, <ip>, <range>, <lease time> ] }
-- - IPPOOL_RCODE_SUCCESS lease updated.
-- - IPPOOL_RCODE_POOL_EMPTY no available leases in pool.

local pool_key
local address_key
local device_key

local time
local expires_in

local ip

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool
device_key = "{" .. KEYS[1] .. "}:" .. ippool_key.device .. ":" .. ARGV[2]

time = tonumber(redis.call("TIME")[1])
expires_in = tonumber(ARGV[1])

-- Check to see if the client already has a lease,
-- and if it does return that.
--
-- The additional sanity checks are to allow for the record
-- of device/ip binding to persist for longer than the lease.
ip = redis.call("GET", device_key)
if ip then
	local epoch = tonumber(redis.call("ZSCORE", pool_key, ip))
	if epoch == nil then
		ip = nil
	-- when positive, we have to check it is still for the same device
	elseif epoch - time >= 0 then
		address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. ip
		if redis.call("HGET", address_key, "device") ~= ARGV[2] then
			ip = nil
		end
	end
end

-- ...else, get the IP address which expired the longest time ago.
if not ip then
	ip = redis.call("ZREVRANGE", pool_key, -1, -1, "WITHSCORES")
	if not ip or #ip < 2 or tonumber(ip[2]) >= time then
		return { ippool_rcode.pool_empty }
	end
	ip = ip[1]
end

address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. ip

redis.call("ZADD", pool_key, "XX", time + expires_in, ip)

redis.call("HSET", address_key, "device", ARGV[2])

if ARGV[3] then
	redis.call("HSET", address_key, "gateway", ARGV[3])
else
	redis.call("HDEL", address_key, "gateway")
end

redis.call("SET", device_key, ip, "EX", 10 * expires_in)

redis.call("HINCRBY", address_key, "counter", 1)

return {
	ippool_rcode.success,
	ip,
	redis.call("HGET", address_key, "range"),
	expires_in
}
