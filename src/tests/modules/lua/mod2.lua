function authorize()
	for k, v in pairs(fr) do
		-- print("debug: table fr = { k: "..k.. "=("..type(k).."), v: "..v.."=("..type(v)..") }")

		if not type(k) == "string" then
			print("error: the k should be a string")
			return fr.fail
		end

		if not type(v) == "number" then
			print("error: the v should be a number")
			return fr.fail
		end
	end

	return fr.ok
end
