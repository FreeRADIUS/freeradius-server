TARGET			:= fuzzer_xlat$(E)
SOURCES			:= fuzzer_xlat.c

TGT_PREREQS		:= libfreeradius-unlang$(L) libfreeradius-util$(L) $(LIBFREERADIUS_SERVER)

SRC_CFLAGS		:= -fsanitize=fuzzer
TGT_LDFLAGS		:= -fsanitize=fuzzer
TGT_LDLIBS		:= $(LIBS)
