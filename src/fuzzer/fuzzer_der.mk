TARGET			:= fuzzer_der$(E)
SOURCES			:= fuzzer_der.c common.c

TGT_PREREQS		:= libfreeradius-der$(L) $(FUZZER_PROTO_LIBS)

SRC_CFLAGS		:= -fsanitize=fuzzer
TGT_LDFLAGS		:= -fsanitize=fuzzer
TGT_LDLIBS		:= $(LIBS)
