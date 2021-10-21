#
#  In order to use the fuzzer, you must build with:
#
#	./configure --enable-fuzzer ...
#
#  and then re-build *all* of the source.
#
#  Once the fuzzer is build, run it via:
#
#	make fuzzer.PROTOCOL
#

#
#  The libraries to be fuzzed MUST be explicitly linked to the protocol libraries.
#  Dynamic loading will NOT work.  In order to simplify the process, the protocol
#  libraries export a common test point.  We have one source / make file, which
#  then magically turns into different fuzzers.
#

TARGET		:= fuzzer_$(PROTOCOL)
SOURCES		:= fuzzer.c

TGT_PREREQS	:= libfreeradius-$(PROTOCOL).a

TGT_LDLIBS	:= $(LIBS) 

#
#  Ensure that the large data file is copied from git-lfs,
#  and then the files are extracted.
#
#  git-lfs fails to update the git index when multiple instances run
#  concurrently.
#
.PHONY:src/tests/fuzzer-corpus/$(PROTOCOL)
src/tests/fuzzer-corpus/$(PROTOCOL):
	${Q}if [ ! -e $@ ]; then \
		flock -F /tmp/git-lfs-mutex git -c 'lfs.fetchexclude=' -c 'lfs.fetchinclude=src/tests/fuzzer-corpus/$(PROTOCOL).tar' lfs pull; \
		cd src/tests/fuzzer-corpus; \
		tar -xf $(PROTOCOL).tar; \
	fi

.PHONY: $(FUZZER_ARTIFACTS)/$(PROTOCOL)
$(FUZZER_ARTIFACTS)/$(PROTOCOL):
	@mkdir -p $@

$(TEST_BIN_DIR)/fuzzer_$(PROTOCOL): $(BUILD_DIR)/lib/local/libfreeradius-$(PROTOCOL).la | $(FUZZER_ARTIFACTS)/$(PROTOCOL)

#
#  Run the fuzzer binary against the fuzzer corpus data files.
#
#  @todo - make `max_len` protocol-specific
#
#  We can also add
#
#	-use_value_profile=1
#
#  This will track values across compare instructions.  But it can slow down scanning by 2x, and
#  increase the size of the corpus by several times.
#
fuzzer.$(PROTOCOL): $(TEST_BIN_DIR)/fuzzer_$(PROTOCOL) | src/tests/fuzzer-corpus/$(PROTOCOL)
	${Q}$(TEST_BIN)/fuzzer_$(PROTOCOL) \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/$(PROTOCOL)/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-D share/dictionary \
		src/tests/fuzzer-corpus/$(PROTOCOL)

#
#  tests add a 10s timeout.  This is so that we can see if the fuzzers run _at all_.
#
ifeq "$(CI)" ""
test.fuzzer.$(PROTOCOL): $(TEST_BIN_DIR)/fuzzer_$(PROTOCOL) | src/tests/fuzzer-corpus/$(PROTOCOL)
	@echo TEST-FUZZER $(PROTOCOL) for $(FUZZER_TIMEOUT)s
	${Q}$(TEST_BIN)/fuzzer_$(PROTOCOL) \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/$(PROTOCOL)/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-max_total_time=$(FUZZER_TIMEOUT) \
		-D share/dictionary \
		src/tests/fuzzer-corpus/$(PROTOCOL)
else
test.fuzzer.$(PROTOCOL): $(TEST_BIN_DIR)/fuzzer_$(PROTOCOL) | src/tests/fuzzer-corpus/$(PROTOCOL)
	@echo TEST-FUZZER $(PROTOCOL) for $(FUZZER_TIMEOUT)s
	@mkdir -p $(BUILD_DIR)/fuzzer
	${Q}if ! $(TEST_BIN)/fuzzer_$(PROTOCOL) \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/$(PROTOCOL)/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-max_total_time=$(FUZZER_TIMEOUT) \
		-D share/dictionary \
		src/tests/fuzzer-corpus/$(PROTOCOL) > $(BUILD_DIR)/fuzzer/$(PROTOCOL).log 2>&1; then \
		tail -20 $(BUILD_DIR)/fuzzer/$(PROTOCOL).log; \
		echo FAILED; \
		exit 1; \
	fi
endif

test.fuzzer.$(PROTOCOL).crash: $(wildcard $(BUILD_DIR)/fuzzer/$(PROTOCOL)/crash-*) $(TEST_BIN_DIR)/fuzzer_$(PROTOCOL) | src/tests/fuzzer-corpus/$(PROTOCOL)
	$(TEST_BIN)/fuzzer_$(PROTOCOL) \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/$(PROTOCOL)/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-max_total_time=$(FUZZER_TIMEOUT) \
		-D share/dictionary \
		$<
