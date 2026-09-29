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

TARGET			:= $(FUZZER_NAME)_$(PROTOCOL)$(E)
SOURCES			:= $(FUZZER_NAME)_$(PROTOCOL).c common.c

TGT_PREREQS		:= libfreeradius-$(PROTOCOL)$(L) $(FUZZER_PROTO_LIBS)

SRC_CFLAGS		:= -fsanitize=fuzzer
TGT_LDFLAGS		:= -fsanitize=fuzzer
TGT_LDLIBS		:= $(LIBS)

#
#  OSX and Homebrew argue about things.  Homebrew LLVM uses the gnu23
#  C standard that Apple's default clang compiler doesn't support, and
#  some packages may have standard library linking issues.  As a
#  result, we add in the _homebrew_ versions of the C++ libraries
#  which are needed by the fuzzer.
#
#  But we should only do this when the C compiler is the homebrew one.
#
ifeq "$(shell uname -s)" "Darwin"
ifeq "$(findstring /opt/homebrew,$(shell which $(TARGET_CC)))" "/opt/homebrew"
SRC_CFLAGS	+= -Wno-unused-command-line-argument
LLVM_LOC	= /opt/homebrew/opt/llvm
TGT_LDFLAGS	+= -L/opt/homebrew/lib -L/opt/homebrew/opt/gettext/lib -L$(LLVM_LOC)/lib -L/opt/homebrew/opt/libomp/lib -stdlib=libc++ -Wl,-rpath,$(LLVM_LOC)/lib -L$(LLVM_LOC)/lib/c++ -lc++
endif
endif

ifneq "$(PROTOCOL)" "util"

FUZZER_CORPUS_DIR	:= src/tests/fuzzer-corpus
FUZZER_CORPUS_ID_DIR	:= $(FUZZER_CORPUS_DIR)/$(FUZZER_ID)

#
#  Ensure that the large data file is copied from git-lfs,
#  and then the files are extracted.
#
#  git-lfs fails to update the git index when multiple instances run
#  concurrently.  Unfortunately there's no equivalent command on macOS.
#
.PHONY:$(FUZZER_CORPUS_ID_DIR)
$(FUZZER_CORPUS_ID_DIR):
	${Q}if [ ! -e $@ ] || [ ! -e "$@/.extracted" ]; then \
		if which flock > /dev/null 2>&1; then flock -F /tmp/git-lfs-mutex git -c 'lfs.fetchexclude=' -c 'lfs.fetchinclude=$(FUZZER_CORPUS_ID_DIR).tar' lfs pull; \
		else git -c 'lfs.fetchexclude=' -c 'lfs.fetchinclude=$(FUZZER_CORPUS_ID_DIR).tar' lfs pull; fi; \
		cd src/tests/fuzzer-corpus; \
		if [ -f $(FUZZER_ID).tar ]; then \
			tar -xf $(FUZZER_ID).tar; \
		else \
			mkdir -p $(FUZZER_ID); \
		fi; \
		touch "$(FUZZER_ID)/.extracted"; \
	fi

.PHONY: $(FUZZER_ARTIFACTS)/$(FUZZER_ID)
$(FUZZER_ARTIFACTS)/$(FUZZER_ID):
	@mkdir -p $@

$(TEST_BIN_DIR)/$(TARGET): $(BUILD_DIR)/lib/local/libfreeradius-$(PROTOCOL).la | $(FUZZER_ARTIFACTS)/$(FUZZER_ID)

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
fuzzer.$(FUZZER_ID): $(TEST_BIN_DIR)/$(TARGET) | $(FUZZER_CORPUS_ID_DIR)
	${Q}$(TEST_BIN_NO_TIMEOUT)/$(TARGET) \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/$(FUZZER_ID)/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-D share/dictionary \
		$(FUZZER_CORPUS_ID_DIR)

#
#  tests add a 10s timeout.  This is so that we can see if the fuzzers run _at all_.
#
ifeq "$(CI)" ""
test.fuzzer.$(FUZZER_ID): $(TEST_BIN_DIR)/$(TARGET) | $(FUZZER_CORPUS_ID_DIR)
	@echo TEST-FUZZER $(FUZZER_ID) for $(FUZZER_TIMEOUT)s
	${Q}$(TEST_BIN_NO_TIMEOUT)/$(TARGET) \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/$(FUZZER_ID)/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-max_total_time=$(FUZZER_TIMEOUT) \
		-D share/dictionary \
		$(FUZZER_CORPUS_ID_DIR)
else
test.fuzzer.$(FUZZER_ID): $(TEST_BIN_DIR)/$(TARGET) | $(FUZZER_CORPUS_ID_DIR)
	@echo TEST-FUZZER $(FUZZER_ID) for $(FUZZER_TIMEOUT)s
	@mkdir -p $(BUILD_DIR)/fuzzer
	${Q}if ! $(TEST_BIN_NO_TIMEOUT)/$(TARGET) \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/$(FUZZER_ID)/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-max_total_time=$(FUZZER_TIMEOUT) \
		-D share/dictionary \
		$(FUZZER_CORPUS_ID_DIR) > $(BUILD_DIR)/fuzzer/$(FUZZER_ID).log 2>&1; then \
		tail -20 $(BUILD_DIR)/fuzzer/$(FUZZER_ID).log; \
		echo FAILED; \
		exit 1; \
	fi
endif

test.fuzzer.$(FUZZER_ID).merge: | $(FUZZER_CORPUS_ID_DIR)
	@echo MERGE-FUZZER-CORPUS $(FUZZER_ID)
	${Q}[ -e "$(FUZZER_CORPUS_ID_DIR)_new" ] || mkdir "$(FUZZER_CORPUS_ID_DIR)_new"
	${Q}$(TEST_BIN_NO_TIMEOUT)/$(TARGET) \
		-D share/dictionary \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-merge=1 \
		"$(FUZZER_CORPUS_ID_DIR)_new" "$(FUZZER_CORPUS_ID_DIR)"
	${Q}[ ! -e "$(FUZZER_CORPUS_ID_DIR).tar" ] || rm "$(FUZZER_CORPUS_ID_DIR).tar"
	${Q}rm -rf "$(FUZZER_CORPUS_ID_DIR)"
	${Q}mv "$(FUZZER_CORPUS_ID_DIR)_new" "$(FUZZER_CORPUS_ID_DIR)"
	${Q}tar -C "$(FUZZER_CORPUS_DIR)" -c -f "$(FUZZER_CORPUS_ID_DIR).tar" "$(FUZZER_ID)"
	${Q}rm -rf "$(FUZZER_CORPUS_ID_DIR)_new"

test.fuzzer.$(FUZZER_ID).crash: $(wildcard $(BUILD_DIR)/fuzzer/$(FUZZER_ID)/crash-*) $(wildcard $(BUILD_DIR)/fuzzer/$(FUZZER_ID)/timeout-*) $(wildcard $(BUILD_DIR)/fuzzer/$(FUZZER_ID)/slow-unit-*) $(TEST_BIN_DIR)/$(TARGET) | $(FUZZER_CORPUS_ID_DIR)
	$(TEST_BIN_NO_TIMEOUT)/$(TARGET) \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/$(FUZZER_ID)/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-max_total_time=$(FUZZER_TIMEOUT) \
		-D share/dictionary \
		$(filter $(BUILD_DIR)/fuzzer/$(FUZZER_ID)/crash-% $(BUILD_DIR)/fuzzer/$(FUZZER_ID)/timeout-% $(BUILD_DIR)/fuzzer/$(FUZZER_ID)/slow-unit-%, $?)

#
#
endif
