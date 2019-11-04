do_test() {
	if ! $@ 1> build/tests/bin/$(basename $0).log 2>&1; then
		echo "Failed executing '$@' - error $?"
		cat  build/tests/bin/$(basename $0).log

		[ -n "$cb_do_test" ] && eval "$cb_do_test"

		exit 1 
	fi
}
