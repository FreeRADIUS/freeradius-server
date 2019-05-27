-- Lua script for showing leases
--
-- - KEYS[1] pool name
-- - ARGV[1] IP address to show
-- - ARGV[2] prefix to add (0 = auto => 64 for IPv6, 32 for IPv4)
--
-- Returns @verbatim array { <rcode>[, json{ { ip, expires, ... }, ... }] } @endverbatim
-- - IPPOOL_RCODE_SUCCESS
-- - IPPOOL_RCODE_FAIL

local range = iptool.parse(ARGV[1])
local prefix = toprefix(ARGV[1], ARGV[2])

guard(range, prefix)

local pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool
local address_key

local results = {}
local result, v
for addr in iptool.iter(range, prefix) do
	local e = redis.call("ZSCORE", pool_key, addr)
	if e then
		result = {
			ip	= addr,
			expires	= tonumber(e)
		}

		address_key = "{" .. KEYS[1] .. "}:" .. ippool_key_address .. ":" .. addr

		v = redis.call("HGETALL", address_key)
		if not v then
			v = {}
		end
		for i=1,#v,2 do
			if result[v[i]] == nil then
				result[v[i]] = v[i+1]
			end
		end

		table.insert(results, result)
	end
end

if #results > 0 then
	results = cjson.encode(results)
else
	results = "[]"
end

return {
	ippool_rcode_success,
	results
}
