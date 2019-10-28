#
#  In order to use the fuzzer, you must edit Make.inc to add:
#
#	CFLAGS += -fsanitize=fuzzer
#
#  and then re-build *all* of the source.
#
#  Once the fuzzer is build, run it via:
#
#  FR_LIBRARY_PATH=./build/lib/ FR_LIBRARY_FUZZ_PROTOCOL=radius FR_DICTIONARY_DIR=./share/dictionary/ ./build/make/jlibtool --mode=execute ./build/bin/local/fuzzer /path/to/corpus/directory/
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

SRC_CFLAGS	:= -fsanitize=fuzzer
TGT_LDFLAGS	:= -fsanitize=fuzzer
TGT_LDLIBS	:= $(LIBS) 
