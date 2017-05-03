TARGET		:= unit_test_map
SOURCES		:= unit_test_map.c ${top_srcdir}/src/main/unlang_compile.c ${top_srcdir}/src/main/unlang_interpret.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-util.a libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
