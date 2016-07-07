TARGET		:= unit_test_map
SOURCES		:= unit_test_map.c ${top_srcdir}/src/main/modcall.c ${top_srcdir}/src/main/interpreter.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
