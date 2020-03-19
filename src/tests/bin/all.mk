TEST	:= test.bin

FILES	:= \
	atomic_queue_test 	\
	dhcpclient		\
	message_set_test	\
	radclient		\
	radict 			\
	radmin			\
	radsniff 		\
	radsnmp 		\
	radwho 			\
	rbmonkey 		\
	ring_buffer_test 	\
	rlm_redis_ippool_tool 	\
	smbencrypt 		\
	unit_test_attribute 	\
	unit_test_map 		\
	unit_test_module


$(eval $(call TEST_BOOTSTRAP))

#
#  Files in the output dir depend on the bin tests, and on the binary
#  that we're running
#
$(BUILD_DIR)/tests/bin/%: % src/tests/bin/%
	@echo "BIN-TEST $(notdir $@)"
	${Q}if ! TESTBIN="$(TESTBIN)" DICT_DIR="$(top_srcdir)/share/dictionary" $<; then \
		echo TESTBIN=\"$(TESTBIN)\" DICT_DIR="$(top_srcdir)/share/dictionary" $<; \
		exit 1; \
	fi
	${Q}touch $@
