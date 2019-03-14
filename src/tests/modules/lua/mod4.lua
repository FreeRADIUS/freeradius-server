function authorize()
	for k, v in request.pairs() do
		if k == "User-Name" and v == "caipirinha" then
			return fr.ok
		end
	end
	return fr.fail
end
