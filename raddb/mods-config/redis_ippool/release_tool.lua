-- Lua script for releasing a lease
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address to release.
--
-- Removes the IP entry in the ZSET, then removes the address hash, and the device key
-- if one exists.
--
-- Will do nothing if the lease is not found in the ZSET.
--
-- Returns
-- - 0 if no ip addresses were removed.
-- - 1 if an ip address was removed.

local found
local ret

local pool_key
local address_key
local device_key

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool

-- Set expiry time to 0
ret = redis.call("ZADD", pool_key, "XX", "CH", 0, ARGV[1])
if ret == 0 then
	return {
		ippool_rcode.success,
		0
	}
end

address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. ARGV[1]
found = redis.call("HGET", address_key, "device")
if not found then
	return {
		ippool_rcode.success,
		ret
	}
end

-- Remove the association between the device and a lease
device_key = "{" .. KEYS[1] .. "}:" .. ippool_key.device .. ":" .. found
redis.call("DEL", device_key)

return {
	ippool_rcode.success,
	1
}
