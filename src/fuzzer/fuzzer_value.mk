TARGET			:= fuzzer_value$(E)
SOURCES			:= fuzzer_value.c

TGT_PREREQS		:= libfreeradius-util$(L)

SRC_CFLAGS		:= -fsanitize=fuzzer
TGT_LDFLAGS		:= -fsanitize=fuzzer

