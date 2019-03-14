function authorize()
	print("mod7: trying to overwrite fr.noop with 12345 (current value "..fr.noop..")")
	fr.noop = 12345
	print("mod7: Checking the fr.noop value: "..fr.noop)
	return fr.noop
end
