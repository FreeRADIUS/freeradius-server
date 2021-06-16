TARGET      := pair_server_tests
SOURCES     := pair_server_tests.c

TGT_LDLIBS  := $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS := $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS := libfreeradius-util.la libfreeradius-radius.a libfreeradius-server.a libfreeradius-unlang.a
