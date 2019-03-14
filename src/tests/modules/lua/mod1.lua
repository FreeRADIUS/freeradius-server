function authorize()
	if not type(fr) == "table" then
		print("error: the 'fr' should be a table")
		return fr.fail
	end

	return fr.ok
end
