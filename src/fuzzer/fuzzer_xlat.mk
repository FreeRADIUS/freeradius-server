TARGET			:= fuzzer_xlat$(E)
SOURCES			:= fuzzer_xlat.c

TGT_PREREQS		:= $(LIBFREERADIUS_SERVER)

SRC_CFLAGS		:= -fsanitize=fuzzer
TGT_LDFLAGS		:= -fsanitize=fuzzer
