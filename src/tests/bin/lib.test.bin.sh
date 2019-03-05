do_test() {
	if ! $@ 1> /dev/null 2>&1; then
		echo "!! Problems to execute: $@"
		exit 1 
	fi
}
