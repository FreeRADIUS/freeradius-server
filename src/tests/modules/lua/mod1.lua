function authorize()
	if not type(fr) == "table" then
		print("error: the 'fr' should be a table")
		return "fail"
	end

	return fr.rcode.ok
end
