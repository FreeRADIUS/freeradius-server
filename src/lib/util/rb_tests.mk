TARGET      := rb_tests
SOURCES     := rb_tests.c

TGT_PREREQS += libfreeradius-util.a

TGT_LDLIBS  := $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS := $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
