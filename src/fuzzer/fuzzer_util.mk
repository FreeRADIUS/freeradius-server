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

TARGET			:= fuzzer_util$(E)
SOURCES			:= fuzzer_util.c common.c

TGT_PREREQS		:= libfreeradius-util$(L)

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

ifneq "util" "util"

FUZZER_CORPUS_DIR	:= src/tests/fuzzer-corpus

#
#  Ensure that the large data file is copied from git-lfs,
#  and then the files are extracted.
#
#  git-lfs fails to update the git index when multiple instances run
#  concurrently.  Unfortunately there's no equivalent command on macOS.
#
.PHONY:src/tests/fuzzer-corpus/util
src/tests/fuzzer-corpus/util:
	${Q}if [ ! -e $@ ] || [ ! -e "$@/.extracted" ]; then \
		if which flock > /dev/null 2>&1; then flock -F /tmp/git-lfs-mutex git -c 'lfs.fetchexclude=' -c 'lfs.fetchinclude=src/tests/fuzzer-corpus/util.tar' lfs pull; \
		else git -c 'lfs.fetchexclude=' -c 'lfs.fetchinclude=src/tests/fuzzer-corpus/util.tar' lfs pull; fi; \
		cd src/tests/fuzzer-corpus; \
		if [ -f util.tar ]; then \
			tar -xf util.tar; \
		else \
			mkdir -p util; \
		fi; \
		touch "util/.extracted"; \
	fi

.PHONY: $(FUZZER_ARTIFACTS)/util
$(FUZZER_ARTIFACTS)/util:
	@mkdir -p $@

$(TEST_BIN_DIR)/fuzzer_util: $(BUILD_DIR)/lib/local/libfreeradius-util.la | $(FUZZER_ARTIFACTS)/util

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
fuzzer.util: $(TEST_BIN_DIR)/fuzzer_util | src/tests/fuzzer-corpus/util
	${Q}$(TEST_BIN_NO_TIMEOUT)/fuzzer_util \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/util/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-D share/dictionary \
		src/tests/fuzzer-corpus/util

#
#  tests add a 10s timeout.  This is so that we can see if the fuzzers run _at all_.
#
ifeq "$(CI)" ""
test.fuzzer.util: $(TEST_BIN_DIR)/fuzzer_util | src/tests/fuzzer-corpus/util
	@echo TEST-FUZZER util for $(FUZZER_TIMEOUT)s
	${Q}$(TEST_BIN_NO_TIMEOUT)/fuzzer_util \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/util/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-max_total_time=$(FUZZER_TIMEOUT) \
		-D share/dictionary \
		src/tests/fuzzer-corpus/util
else
test.fuzzer.util: $(TEST_BIN_DIR)/fuzzer_util | src/tests/fuzzer-corpus/util
	@echo TEST-FUZZER util for $(FUZZER_TIMEOUT)s
	@mkdir -p $(BUILD_DIR)/fuzzer
	${Q}if ! $(TEST_BIN_NO_TIMEOUT)/fuzzer_util \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/util/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-max_total_time=$(FUZZER_TIMEOUT) \
		-D share/dictionary \
		src/tests/fuzzer-corpus/util > $(BUILD_DIR)/fuzzer/util.log 2>&1; then \
		tail -20 $(BUILD_DIR)/fuzzer/util.log; \
		echo FAILED; \
		exit 1; \
	fi
endif

test.fuzzer.util.merge: | src/tests/fuzzer-corpus/util
	@echo MERGE-FUZZER-CORPUS util
	${Q}[ -e "$(FUZZER_CORPUS_DIR)/util_new" ] || mkdir "$(FUZZER_CORPUS_DIR)/util_new"
	${Q}$(TEST_BIN_NO_TIMEOUT)/fuzzer_util \
		-D share/dictionary \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-merge=1 \
		"$(FUZZER_CORPUS_DIR)/util_new" "$(FUZZER_CORPUS_DIR)/util"
	${Q}[ ! -e "$(FUZZER_CORPUS_DIR)/util.tar" ] || rm "$(FUZZER_CORPUS_DIR)/util.tar"
	${Q}rm -rf "$(FUZZER_CORPUS_DIR)/util"
	${Q}mv "$(FUZZER_CORPUS_DIR)/util_new" "$(FUZZER_CORPUS_DIR)/util"
	${Q}tar -C "$(FUZZER_CORPUS_DIR)" -c -f "$(FUZZER_CORPUS_DIR)/util.tar" "util"
	${Q}rm -rf "$(FUZZER_CORPUS_DIR)/util_new"

test.fuzzer.util.crash: $(wildcard $(BUILD_DIR)/fuzzer/util/crash-*) $(wildcard $(BUILD_DIR)/fuzzer/util/timeout-*) $(wildcard $(BUILD_DIR)/fuzzer/util/slow-unit-*) $(TEST_BIN_DIR)/fuzzer_util | src/tests/fuzzer-corpus/util
	$(TEST_BIN_NO_TIMEOUT)/fuzzer_util \
		-artifact_prefix="$(FUZZER_ARTIFACTS)/util/" \
		-max_len=512 $(FUZZER_ARGUMENTS) \
		-max_total_time=$(FUZZER_TIMEOUT) \
		-D share/dictionary \
		$(filter $(BUILD_DIR)/fuzzer/util/crash-% $(BUILD_DIR)/fuzzer/util/timeout-% $(BUILD_DIR)/fuzzer/util/slow-unit-%, $?)

#
#
endif
