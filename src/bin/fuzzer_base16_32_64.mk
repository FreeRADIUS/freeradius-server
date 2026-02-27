TARGET                  := fuzzer_base16_32_64$(E)
SOURCES                 := fuzzer_base16_32_64.c

TGT_PREREQS             := libfreeradius-util$(L)

SRC_CFLAGS              := -fsanitize=fuzzer
TGT_LDFLAGS             := -fsanitize=fuzzer
TGT_LDLIBS              := $(LIBS)
