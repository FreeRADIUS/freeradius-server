TARGET		:= base_16_32_64_tests

SOURCES		:= base_16_32_64_tests.c

TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS	:= libfreeradius-util.a
