-- Lua script for deleting a lease
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address to delete.
--
-- Removes the IP entry in the ZSET, then removes the address hash, and the device key
-- if one exists.
--
-- Will work with partially removed IP addresses (where the ZSET entry is absent but other
-- elements were not cleaned up).
--
-- Returns
-- - 0 if no ip addresses were removed.
-- - 1 if an ip address was removed.

local found
local ret

local address_key
local pool_key
local device_key

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool

ret = redis.call("ZREM", pool_key, ARGV[1])

address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. ARGV[1]

found = redis.call("HGET", address_key, "device")
if not found then
	return ret
end
redis.call("DEL", address_key)

-- Remove the association between the device and a lease
device_key = "{" .. KEYS[1] .. "}:" .. ippool_key.device .. ":" .. found
redis.call("DEL", device_key)

return 1
