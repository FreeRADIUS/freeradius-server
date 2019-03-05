do_test() {
	if ! $@ 1> /dev/null 2>&1; then
		echo "Failed executing '$@' - error $?"

		[ -n "$cb_do_test" ] && eval "$cb_do_test"

		exit 1 
	fi
}
