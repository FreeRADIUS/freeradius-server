TARGET			:= fuzzer_tmpl$(E)
SOURCES			:= fuzzer_tmpl.c common.c

TGT_PREREQS		:= $(LIBFREERADIUS_SERVER)

SRC_CFLAGS		:= -fsanitize=fuzzer
TGT_LDFLAGS		:= -fsanitize=fuzzer
TGT_LDLIBS		:= $(LIBS)
