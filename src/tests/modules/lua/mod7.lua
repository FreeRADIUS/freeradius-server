function authorize()
	print("mod7: trying to overwrite fr.noop with 12345 (current value "..fr.rcode.noop..")")
	fr.rcode.noop = 12345
	print("mod7: Checking the fr.noop value: "..fr.rcode.noop)

	return fr.rcode.noop
end
