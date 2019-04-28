-- Lua script for deleting a lease
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address to remove.
--
-- Removes the IP entry in the ZSET, then removes the address hash, and the device key
-- if one exists.
--
-- Will work with partially removed IP addresses (where the ZSET entry is absent but other
-- elements weren"t cleaned up).
--
-- Returns @verbatim array { <rcode>[, <counter>] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS lease updated..
-- - IPPOOL_RCODE_NOT_FOUND lease not found in pool.

local device
local ret

local address_key
local pool_key
local device_key

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool
ret = redis.call("ZREM", pool_key, ARGV[1])

if ret == 0 then
  return { ippool_rcode_not_found }
end

-- Remove the association between the device and a lease
address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. ARGV[1]
device = redis.call("HGET", address_key, "device")
if device then
  device_key = "{" .. KEYS[1] .. "}:" .. ippool_key_device .. ":" .. device
  redis.call("DEL", device_key)
end

redis.call("DEL", address_key)

return {
  ippool_rcode_success,
  ret
}
