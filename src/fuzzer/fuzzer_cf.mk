TARGET			:= fuzzer_cf$(E)
SOURCES			:= fuzzer_cf.c

TGT_PREREQS		:= $(LIBFREERADIUS_SERVER)

SRC_CFLAGS		:= -fsanitize=fuzzer
TGT_LDFLAGS		:= -fsanitize=fuzzer
TGT_LDLIBS		:= $(LIBS)
