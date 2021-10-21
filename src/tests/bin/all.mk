TEST	:= test.bin

FILES	:= \
	atomic_queue_test 	\
	radclient		\
	radict 			\
	radmin			\
	radsniff 		\
	radsnmp 		\
	radwho 			\
	rbmonkey 		\
	rlm_redis_ippool_tool 	\
	unit_test_attribute 	\
	unit_test_map 		\
	unit_test_module

#	dhcpclient		\
#	message_set_test	\
#	radmin			\
#	radsniff 		\
#	radsnmp 		\
#	radwho 			\
#	ring_buffer_test 	\
#	smbencrypt 		\
#	unit_test_attribute 	\
#	unit_test_map 		\
#	unit_test_module

#
#  Add in all of the binary tests
#
FILES += $(filter %_tests,$(ALL_TGTS)))

$(eval $(call TEST_BOOTSTRAP))

#
#  Some tests take arguments, others do not.
#
radclient.ARGS = -h
radict.ARGS = -D $(top_srcdir)/share/dictionary User-Name
radmin.ARGS = -h
radsniff.ARGS =  -D $(top_srcdir)/share/dictionary -h
radsnmp.ARGS = -h
radwho.ARGS = -h
rlm_redis_ippool_tool.ARGS = -h
unit_test_attribute.ARGS = -h
unit_test_map.ARGS = -h
unit_test_module.ARGS = -h

#
#  Files in the output dir depend on the bin tests, and on the binary
#  that we're running
#
$(BUILD_DIR)/tests/bin/%: $(BUILD_DIR)/bin/local/%
	@echo "BIN-TEST $(notdir $@)"
	${Q}if ! $(TEST_BIN)/$(notdir $<) $($(notdir $@).ARGS) > $@.log 2>&1; then \
		echo $(TEST_BIN)/$(notdir $<) $($(notdir $@).ARGS); \
		echo LOG in $@.log; \
		cat $@.log; \
		exit 1; \
	fi
	${Q}touch $@
