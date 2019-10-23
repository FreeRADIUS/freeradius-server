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
#  Command-line option parsing will be added later.
#
TARGET		:= fuzzer
SOURCES		:= fuzzer.c

TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a

SRC_CFLAGS	:= -fsanitize=fuzzer
TGT_LDFLAGS	:= -fsanitize=fuzzer
TGT_LDLIBS	:= $(LIBS) 
