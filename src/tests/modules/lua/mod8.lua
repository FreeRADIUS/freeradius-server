function authorize()
	print("#mod8.lua: init")

	-- fr {}
	print("# fr.{}")
	print("type(fr) = " .. type(fr))
	print("for k,v in pairs(fr)")
	for k,v in pairs(fr) do print("\t"..k, v) end
	print()

	-- fr.rcode {}
	print("# fr.rcode.{}")
	print("type(fr.rcode) = " .. type(fr.rcode))
	print("\tfr.rcode.noop       = " .. fr.rcode.noop)
	print("\tfr.rcode.handled    = " .. fr.rcode.handled)
	print("\tfr.rcode.ok         = " .. fr.rcode.ok)
	print("\tfr.rcode.reject     = " .. fr.rcode.reject)
	print("\tfr.rcode.fail       = " .. fr.rcode.fail)
	print("\tfr.rcode.invalid    = " .. fr.rcode.invalid)
	print("\tfr.rcode.disallow   = " .. fr.rcode.disallow)
	print("\tfr.rcode.notfound   = " .. fr.rcode.notfound)
	print("\tfr.rcode.updated    = " .. fr.rcode.updated)
	print()

	-- fr.log {}
	print("# fr.log.{}")
	print("type(fr.log) = " .. type(fr.log))
	print("for k,v in pairs(fr.log)")
	for k,v in pairs(fr.log) do print("\t"..k, v) end
	print()
	fr.log.debug("Powered by Luajit+FFI & fr_log()")
	fr.log.debug = "Tapioca"
	fr.log.debug("Powered by Luajit+FFI & fr_log()")

	-- fr.request {}
	print("# fr.request.{}")
	print("type(fr.request) = " .. type(fr.request))
	print("for k,v in fr.request.pairs()")
	for k,v in fr.request.pairs() do print("\t"..k, v) end
	print()

	print("#mod8.lua: returning fr.rcode.noop")

	return fr.rcode.noop
end
