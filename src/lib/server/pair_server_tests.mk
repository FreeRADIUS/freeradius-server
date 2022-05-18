TARGET      	:= pair_server_tests$(E)
SOURCES     	:= pair_server_tests.c

TGT_LDLIBS  	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS 	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS 	:= libfreeradius-util$(L) libfreeradius-radius$(L) libfreeradius-server$(L) libfreeradius-unlang$(L)
