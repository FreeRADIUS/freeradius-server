-- Lua script for showing lease
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address/range of lease(s).
-- - ARGV[2] Prefix to add (0 = auto => 64 for IPv6, 32 for IPv4).
--
-- Returns array { <rcode>[, { <addr>, <expiry>, <device>, <gateway>, <range> }, ... ] }
-- - IPPOOL_RCODE_SUCCESS lease updated.
-- - IPPOOL_RCODE_FAIL

local ok
local range
local prefix

local pool_key

local results

ok, range = pcall(iptool.parse, ARGV[1])
if not ok then
	return { ippool_rcode_fail }
end
prefix = toprefix(ARGV[1], ARGV[2])
if guard(range, prefix) then
	return { ippool_rcode_fail }
end

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool

results = {}
for addr in iptool.iter(range, prefix) do
	local address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. addr

	table.insert(results, {
		addr,
		tonumber(redis.call("ZSCORE", pool_key, addr)),
		unpack(redis.call("HMGET", address_key, "device", "gateway", "range"))
	})
end

return {
	ippool_rcode.success,
	results
}
