function authorize()
	for k, v in fr.request.pairs() do
		if k == "User-Name" and v == "caipirinha" then
			return fr.rcode.ok
		end
	end
	return fr.rcode.fail
end
