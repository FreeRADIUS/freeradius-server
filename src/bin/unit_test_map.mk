TARGET		:= unit_test_map
SOURCES		:= unit_test_map.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-unlang.a
TGT_LDLIBS	:= $(LIBS)
