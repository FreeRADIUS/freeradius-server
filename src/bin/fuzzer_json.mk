TARGET			:= fuzzer_json$(E)
SOURCES			:= fuzzer_json.c

TGT_PREREQS		:= libfreeradius-json$(L) $(LIBFREERADIUS_SERVER) libfreeradius-io$(L) libfreeradius-util$(L)

SRC_CFLAGS		:= -fsanitize=fuzzer
SRC_CFLAGS		+= -I$(top_builddir)/src/lib/json/

TGT_LDFLAGS		:= -fsanitize=fuzzer
TGT_LDLIBS		:= $(LIBS) -ltalloc -ljson-c -ldl
