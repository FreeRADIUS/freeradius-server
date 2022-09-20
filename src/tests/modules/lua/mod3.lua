function authorize()
	for k, v in fr.pairs() do
		if k == "Framed-IPv6-Prefix" and v == "11:22:33:44:55:66:77:88/128" then
			return fr.rcode.ok
		end
	end
	return fr.rcode.fail
end
