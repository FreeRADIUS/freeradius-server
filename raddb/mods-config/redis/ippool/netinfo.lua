-- Lua script to update range id netinfo
--
-- - KEYS[1] pool name
-- - ARGV[1] range id
-- - ARGV[2] (optional) JSON encoded KV pairs (empty object means delete, null/boolean/zero-length value deletes key)
--
-- Returns @verbatim array { <rcode> } @endverbatim
-- - IPPOOL_RCODE_SUCCESS

local netinfo_key = "{" .. KEYS[1] .. "}:" .. ippool_key_netinfo .. ":" .. ARGV[1]

local t = {}

if ARGV[2] and type(ARGV[2]) == "string" then
	if ARGV[2]:len() > 0 then
		local t0 = cjson.decode(ARGV[2])
		for k,v in pairs(t0) do
			-- via application/x-www-form-urlencoded so we work with what we get
			if v == cjson.null or type(v) == "boolean" or (type(v) == "string" and v:len() == 0) then
				redis.call("HDEL", netinfo_key, k)
			else
				table.insert(t, k)
				table.insert(t, v)
			end
		end
	end

	if #t > 0 then
		redis.call("HMSET", netinfo_key, unpack(t))
	else
		redis.call("DEL", netinfo_key)
	end

	return {
		ippool_rcode_success
	}
else
	local t0 = redis.call("HGETALL", netinfo_key)
	for i = 1,#t0,2 do
		t[t0[i]] = t0[i+1]
	end

	return {
		ippool_rcode_success,
		cjson.encode(t)
	}
end

