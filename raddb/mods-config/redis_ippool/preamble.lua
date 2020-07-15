-- must match redis_ippool.h
local ippool_rcode = {
	success = 0,
	not_found = -1,
	expired = -2,
	device_mismatch = -3,
	pool_empty = -4,
	fail = -5
}

-- schema namespacing
local ippool_key = {
	pool = "pool",
	address = "ip",
	device = "device"
}

-- IPTOOL --
local function iptool_module ()
	local _M = {}

	-- redis runtime already includes this
	if not bit then
		local bit = require "bit"
	end

	local function shallowcopy(t)
		local c = {}
		for k, v in pairs(t) do
			c[k] = v
		end
		return c
	end

	local function toipn_from6 (ip)
		local n = {}
		local p0 = 0
		local p1 = 0

		for s in ip:gmatch("[^:]*") do
			if s:len() > 0 then
				table.insert(n, tonumber(s, 16))
				p0 = 0
			else
				if p0 == 0 then
					p0 = #n
				elseif p1 == 0 then
					p1 = #n
				end
			end
		end

		for o = 1, 8 - #n do
			table.insert(n, p1 + 1, 0)
		end

		if #n ~= 8 then
			error("invalid ip: " .. ip)
		end

		return n
	end

	local function toipn (ip)
		if string.find(ip, ":") then
			return toipn_from6(ip)
		end

		local n = 0
		local c = 0

		for s in ip:gmatch("[^%.]+") do
			n = n * 256 + tonumber(s)
			c = c + 1
		end

		if c ~= 4 then
			error("invalid ip: " .. ip)
		end

		return n
	end

	local function toa (ipn)
		local ip = {}

		if type(ipn) == "number" then
			for i=1,4 do
				table.insert(ip, 1, bit.band(ipn, 255))
				ipn = bit.rshift(ipn, 8)
			end

			return table.concat(ip, ".")
		else
			for i=1,8 do
				ip[i] = string.format("%04x", ipn[i])
			end

			return table.concat(ip, ":")
		end
	end
	_M.toa = toa

	local function cmp (a, b)
		if type(a) == "number" then
			if a < b then
				return -1
			elseif a == b then
				return 0
			else
				return 1
			end
		else
			for i = 1,8 do
				if a[i] < b[i] then
					return -1
				elseif a[i] > b[i] then
					return 1
				end
			end

			return 0
		end
	end

	local function add (a, v)
		if type(a) == "number" then
			return a + v
		else
			a = shallowcopy(a)
			local c = 0
			for i = 8,1,-1 do
				a[i] = a[i] + v[i] + c
				c = bit.rshift(a[i], 16)
				a[i] = bit.band(a[i], 65535)
			end
			if c > 0 then
				error("carry is non-zero")
			end
		end

		return a
	end

	local function parse (ip)
		local isrange = string.find(ip, "-")
		if isrange then
			local s = toipn(ip:sub(1, isrange - 1))
			local e = toipn(ip:sub(isrange + 1))

			if type(s) ~= type(e) then
				error("cannot mix v4/v6 in range")
			end

			if cmp(s, e) > 0 then
				error("start address higher than end address")
			end

			return {s, e}
		end

		local iscidr = string.find(ip, "/")
		if iscidr then
			local s = toipn(ip:sub(1, iscidr - 1))
			local p = tonumber(ip:sub(iscidr + 1))

			local m
			if type(s) == "number" then
				local o = 32 - p
				-- bitop is 32bit signed
				s = math.floor(s / 2^o)	-- right shift
				s = math.floor(s * 2^o)	-- left shift
				m = 2^o - 1
			else
				local o = 8 - math.floor((128 - p) / 16)

				m = {0,0,0,0,0,0,0,0}
				m[o] = 65536 - bit.lshift(1, (128 - p) % 16)
				for i=o-1,1,-1 do
					m[i] = 65535
				end
				for i=1,8 do
					s[i] = bit.band(s[i], m[i])
				end

				m = {0,0,0,0,0,0,0,0}
				m[o] = bit.lshift(1, (128 - p) % 16) - 1
				for i=o+1,8 do
					m[i] = 65535
				end
			end

			local e = add(s, m)

			return {s, e}
		end

		local ipn = toipn(ip)
		return {ipn, ipn}
	end
	_M.parse = parse

	local function iter (r, p)
		local s = r[1]
		local e = r[2]

		local step
		if type(s) == "number" then
			step = bit.lshift(1, 32 - p)
		else
			s = shallowcopy(s)
			step = {0,0,0,0,0,0,0,0}
			step[8 - math.floor((128 - p) / 16)] = bit.lshift(1, (128 - p) % 16)
		end

		return function ()
			if cmp(s, e) < 1 then
				local s0 = s
				s = add(s, step)
				return toa(s0)
			end
		end
	end
	_M.iter = iter

	local function norm (i)
		local r = parse(i)
		local a = toa(r[1])
		return a
	end
	_M.norm = norm

	return _M
end

local iptool = iptool_module()
------------

local function guard (range, prefix)
	local ippool_limit_entries = 65536

	local counter = 0
	for addr in iptool.iter(range, prefix) do
		counter = counter + 1

		if counter >= ippool_limit_entries then
			return { ippool_rcode.fail }
		end
	end

	return false
end

local function toprefix (ip, prefix0)
	local prefix = tonumber(prefix0)
	if prefix <= 0 then
		prefix = 0
	end
	if prefix == 0 then
		if string.find(ip, ":") then
			prefix = 64
		else
			prefix = 32
		end
	end
	return prefix
end
