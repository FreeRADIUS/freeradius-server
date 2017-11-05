TARGET		:= unit_test_map
SOURCES		:= unit_test_map.c ${top_srcdir}/src/main/unlang_compile.c ${top_srcdir}/src/main/unlang_interpret.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS)
