TARGET		:= cf_tests$(E)
SOURCES		:= cf_tests.c

TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS	:= libfreeradius-util$(L) libfreeradius-server$(L) libfreeradius-unlang$(L)

TGT_INSTALLDIR	:=
