TARGET      := pair_server_tests
SOURCES     := pair_server_tests.c

TGT_PREREQS += libfreeradius-util.a libfreeradius-radius.a libfreeradius-server.a libfreeradius-unlang.a

TGT_LDLIBS  := $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS := $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
