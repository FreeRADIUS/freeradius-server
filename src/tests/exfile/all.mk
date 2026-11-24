#
#  Test that the server survives a detail file it can't create, when
#  many threads try at once.  With "locking = no", exfile opens the
#  file without its mutex, so nothing it does then may change the
#  shared exfile_t.
#
EXFILE_DIR	:= $(DIR)
EXFILE_OUT	:= $(BUILD_DIR)/tests/exfile
EXFILE_PORT	:= 12360
EXFILE_RUN	:= sh $(EXFILE_DIR)/run.sh "$(TESTBIN)/radiusd" "$(TESTBIN)/radclient" $(EXFILE_DIR)/config $(DICT_PATH)

EXFILE_DEPS	:= $(EXFILE_DIR)/run.sh $(EXFILE_DIR)/config/radiusd.conf $(TESTBINDIR)/radiusd $(TESTBINDIR)/radclient

.PHONY: tests.exfile
tests.exfile: $(EXFILE_OUT)/mkdir

#
#  Concurrent Accounting-Requests, each failing to create the detail
#  file's directory.
#
$(EXFILE_OUT)/mkdir: $(EXFILE_DEPS)
	${Q}echo "EXFILE-TEST mkdir"
	${Q}$(EXFILE_RUN) $@.d $(EXFILE_PORT) 5
	${Q}touch $@

.PHONY: clean.tests.exfile
clean.tests.exfile:
	${Q}rm -rf $(EXFILE_OUT)

clean.test: clean.tests.exfile
