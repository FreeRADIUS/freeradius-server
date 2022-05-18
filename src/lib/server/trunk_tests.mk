TARGET		:= trunk_tests$(E)
SOURCES		:= trunk_tests.c

TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)

ifneq ($(OPENSSL_LIBS),)
TGT_PREREQS	:= libfreeradius-tls$(L)
endif

TGT_PREREQS	+= libfreeradius-util$(L) libfreeradius-server$(L) libfreeradius-unlang$(L)
SRC_CFLAGS	+= -DTESTING_TRUNK
