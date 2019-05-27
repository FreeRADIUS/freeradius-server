-- Get stats about leases
--
-- - KEYS[1] pool name
--
-- Returns @verbatim array { <rcode>, json{ total, free, exp1m, exp30m, exp1h, exp1d } } @endverbatim
-- - IPPOOL_RCODE_SUCCESS

local pool_key = "{" .. KEYS[1] .. "}:" .. ippool_key_pool

local time = redis.call("TIME")

local result = {}

result.total	= redis.call("ZCARD", pool_key)						-- total
result.free	= redis.call("ZCOUNT", pool_key, "-inf", time[1])			-- free
result.exp1m	= redis.call("ZCOUNT", pool_key, "-inf", time[1] + 60)			-- free in next  1m
result.exp30m	= redis.call("ZCOUNT", pool_key, "-inf", time[1] + 60 * 30)		-- free in next 30m
result.exp1h	= redis.call("ZCOUNT", pool_key, "-inf", time[1] + 60 * 60)		-- free in next  1h
result.exp1d	= redis.call("ZCOUNT", pool_key, "-inf", time[1] + 60 * 60 * 24)	-- free in next  1d

return {
	ippool_rcode_success,
	cjson.encode(result)
}
