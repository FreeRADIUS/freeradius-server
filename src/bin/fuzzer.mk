#
#  In order to use the fuzzer, you must build with:
#
#	./configure --enable-llvm-fuzzer-sanitizer ...
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

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-$(PROTOCOL).a

TGT_LDLIBS	:= $(LIBS) 

#
#  Ensure that the large data file is copied from git-lfs,
#  and then the files are extracted.
#
.PHONY:src/tests/fuzzer-corpus/$(PROTOCOL)
src/tests/fuzzer-corpus/$(PROTOCOL):
	${Q}if [ ! -e $@ ]; then \
		git -c 'lfs.fetchexclude=' -c 'lfs.fetchinclude=src/tests/fuzzer-corpus/$(PROTOCOL).tar' lfs pull; \
		cd src/tests/fuzzer-corpus; \
		tar -xf $(PROTOCOL).tar; \
	fi

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
fuzzer.$(PROTOCOL): ./build/bin/local/fuzzer_$(PROTOCOL) | src/tests/fuzzer-corpus/$(PROTOCOL)
	${Q}$(TEST_BIN)/fuzzer_$(PROTOCOL) -max_len=512 -D share/dictionary src/tests/fuzzer-corpus/$(PROTOCOL)

#
#  tests add a 10s timeout.  This is so that we can see if the fuzzers run _at all_.
#
test.fuzzer.$(PROTOCOL): ./build/bin/local/fuzzer_$(PROTOCOL) | src/tests/fuzzer-corpus/$(PROTOCOL)
	${Q}$(TEST_BIN)/fuzzer_$(PROTOCOL) -max_len=512 -timeout=10 -D share/dictionary src/tests/fuzzer-corpus/$(PROTOCOL)
