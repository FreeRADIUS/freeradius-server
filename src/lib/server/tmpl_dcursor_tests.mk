TARGET		:= tmpl_dcursor_tests$(E)
SOURCES		:= tmpl_dcursor_tests.c

TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS	:= libfreeradius-util$(L) libfreeradius-server$(L) libfreeradius-unlang$(L)
