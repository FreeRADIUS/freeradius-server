-- Lua script for showing pool stats
--
-- - KEYS[1] The pool name.
-- - ARGV[X] Optional expiry offsets to query in seconds
--
-- Returns array { <rcode>, <total>, <free>[, <free-offsets>, ... ] }
-- - IPPOOL_RCODE_SUCCESS
-- - IPPOOL_RCODE_NOT_FOUND

local pool_key

local time

pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key.pool

time = tonumber(redis.call("TIME")[1])

table.insert(ARGV, 1, 0)

local free = {}
for _, v in ipairs(ARGV) do
	table.insert(free, redis.call("ZCOUNT", pool_key, "-inf", time + tonumber(v)))
end

return {
	ippool_rcode.success,
	redis.call("ZCARD", pool_key),
	unpack(free)
}
