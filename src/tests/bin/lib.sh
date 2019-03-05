do_test() {
	if ! $@ 1> /dev/null 2>&1; then
		echo "Failed executing '$@' - error $?"
		exit 1 
	fi
}
