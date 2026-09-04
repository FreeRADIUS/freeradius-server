TARGET			:= fuzzer_value$(E)
SOURCES			:= fuzzer_value.c

TGT_PREREQS		:= $(LIBFREERADIUS_UTIL)

SRC_CFLAGS		:= -fsanitize=fuzzer
TGT_LDFLAGS		:= -fsanitize=fuzzer
TGT_LDLIBS		:= $(LIBS)

