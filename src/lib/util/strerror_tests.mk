TARGET		:= strerror_tests

SOURCES		:= strerror_tests.c time.c

SRC_CFLAGS	:= -O2
TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)

TGT_PREREQS	+= libfreeradius-util.a
