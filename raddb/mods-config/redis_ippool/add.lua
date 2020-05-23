-- Lua script for adding a pool
--
-- - KEYS[1] The pool name.
-- - ARGV[1] IP address/range of lease(s).
-- - ARGV[2] Prefix to add (0 = auto => 64 for IPv6, 32 for IPv4).
-- - ARGV[3] (optional) Range ID.
--
-- Returns array { <rcode>[, <counter> ] }
-- - IPPOOL_RCODE_SUCCESS
-- - IPPOOL_RCODE_FAIL

local ok
local range
local prefix

local pool_key

local counter

ok, range = pcall(iptool.parse, ARGV[1])
if not ok then
	return { ippool_rcode_fail }
end
prefix = toprefix(ARGV[1], ARGV[2])
if guard(range, prefix) then
	return { ippool_rcode_fail }
end

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool

counter = 0
for addr in iptool.iter(range, prefix) do
	local ret = redis.call("ZADD", pool_key, "NX", 0, addr)
	local address_key = "{" .. KEYS[1] .. "}:" .. ippool_key.address .. ":" .. addr

	if ARGV[3] then
		ret = redis.call("HSET", address_key, "range", ARGV[3]) or ret
	else
		ret = redis.call("HDEL", address_key, "range") or ret
	end

	counter = counter + ret
end

return {
	ippool_rcode.success,
	counter
}
