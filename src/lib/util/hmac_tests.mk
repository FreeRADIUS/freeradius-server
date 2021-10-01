TARGET		:= hmac_tests

SOURCES		:= hmac_tests.c

TGT_LDLIBS	:= $(LIBS)
TGT_LDFLAGS	:= $(LDFLAGS)
TGT_PREREQS	:= libfreeradius-util.a
