function authorize()
	if not type(fr.rcode) == "table" then
		print("error: The 'fr.rcode.{}' should be table")
		return fr.rcode.fail
	end

	if not type(fr.log) == "table" then
		print("error: The 'fr.log.{}' should be table")
		return fr.rcode.fail
	end

	if not type(fr.request) == "table" then
		print("error: The 'fr.request.{}' should be table")
		return fr.rcode.fail
	end

	return fr.rcode.noop
end
