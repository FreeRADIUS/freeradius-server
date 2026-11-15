#
#	Tests for the Bidirectional Forwarding Detection (BFD) listener, protocol, and process module against RFC 5880.
#
#	Each `*.py` file is a set of tests.  Each test starts its own radiusd and acts as the BFD peer from a UDP socket.
#	`bfdlib.py` implements the peer and the server start.  `README.md` lists the tests that are expected to fail.
#
#	The tests need `python3` and the BFD libraries named in `BFD_LIBS`.
#
#	To run the tests: `make test.bfd`.  `src/tests/bfd/README.md` documents the environment variables and the known failures.
#
BFD_LIBS := libfreeradius-bfd.la proto_bfd.la proto_bfd_udp.la process_bfd.la

ifneq "$(shell which python3)" ""
TEST  := test.bfd
FILES := $(filter-out bfdlib.py,$(subst $(DIR)/,,$(wildcard $(DIR)/*.py)))

$(eval $(call TEST_BOOTSTRAP))

#
#	The tests start the server themselves, so that each one has a session of
#	its own.  Tell them how to run it.
#
BFD_RADIUSD := $(TEST_BIN)/radiusd -D $(DICT_PATH)

#
#	The server loads its protocol and module libraries at run time, so make
#	needs to be told about them.
#
$(OUTPUT)/%.py: $(DIR)/%.py $(DIR)/bfdlib.py $(TEST_BIN_DIR)/radiusd $(addprefix $(BUILD_DIR)/lib/local/,$(BFD_LIBS))
	${Q}echo "BFD-TEST $(notdir $<)"
	${Q}if ! BFD_RADIUSD=$(call SHELL_QUOTE,$(BFD_RADIUSD)) OUTPUT=$(call SHELL_QUOTE,$(@D)) python3 $<; then \
		echo "FAILED $<"; \
		echo "Server logs are in $(@D)"; \
		exit 1; \
	fi
	${Q}touch $@
endif
