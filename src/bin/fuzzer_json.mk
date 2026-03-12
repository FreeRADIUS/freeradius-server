TARGET                  := fuzzer_json$(E)
SOURCES                 := fuzzer_json.c

TGT_PREREQS             := libfreeradius-json$(L) libfreeradius-server$(L) \
                           libfreeradius-util$(L) libfreeradius-unlang$(L) \
                           libfreeradius-io$(L)

SRC_CFLAGS              := -fsanitize=fuzzer
SRC_CFLAGS              += -I$(top_builddir)/src/lib/json/
SRC_CFLAGS              += -I/usr/include/json-c

TGT_LDFLAGS             := -fsanitize=fuzzer
TGT_LDLIBS              := $(LIBS) -ltalloc -ljson-c -ldl
