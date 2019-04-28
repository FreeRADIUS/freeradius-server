-- Show leases
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address to show.
--
-- Returns @verbatim array { <rcode>[, json{ ip, expires, ... }] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS.
-- - IPPOOL_RCODE_NOT_FOUND lease not found in pool.

local result
local value

local address_key
local pool_key

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool

result = {}
result.ip = ARGV[1]
result.expires = tonumber(redis.call("ZSCORE", pool_key, ARGV[1]))

if not result.expires then
  return { ippool_rcode_not_found }
end

address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. ARGV[1]
value = redis.call("HGETALL", address_key)
if not value then
  value = {}
end
for i=1,#value,2 do
  if result[value[i]] == nil then
    result[value[i]] = value[i+1]
  end
end

return {
  ippool_rcode_success,
  cjson.encode(result)
}
