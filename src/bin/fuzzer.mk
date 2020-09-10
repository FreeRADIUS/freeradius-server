#
#  In order to use the fuzzer, you must build with:
#
#	./configure --enable-llvm-fuzzer-sanitizer ...
#
#  and then re-build *all* of the source.
#
#  Once the fuzzer is build, run it via:
#
#  ./build/make/jlibtool --mode=execute ./build/bin/local/fuzzer_radius -max_len=256 -D ./share/dictionary/ path/to/corpus/directory/
#

#
#  The libraries to be fuzzed MUST be explicitly linked to the protocol libraries.
#  Dynamic loading will NOT work.  In order to simplify the process, the protocol
#  libraries export a common test point.  We have one source / make file, which
#  then magically turns into different fuzzers.
#
#  However, because the *test point* functions are loaded dynamically,
#  you still have to tell the fuzzer which library it's supposed to
#  load.
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
	${Q}git -c 'lfs.fetchexclude=' -c 'lfs.fetchinclude=src/tests/fuzzer-corpus/$(PROTOCOL).tar' lfs pull
	${Q}cd src/tests/fuzzer-corpus && tar -xf $(PROTOCOL).tar

#
#  Run the fuzzer binary against the fuzzer corpus data files.
#
#  @todo - make `max_len` protocol-specific
#
fuzzer.$(PROTOCOL): ./build/bin/local/fuzzer_$(PROTOCOL) | src/tests/fuzzer-corpus/$(PROTOCOL)
	${Q}$(TEST_BIN)/fuzzer_$(PROTOCOL) -max_len=512 -D share/dictionary src/tests/fuzzer-corpus/$(PROTOCOL)
