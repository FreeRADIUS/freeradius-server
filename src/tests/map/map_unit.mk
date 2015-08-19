TARGET		:= map_unit
SOURCES		:= map_unit.c ${top_srcdir}/src/main/modcall.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
