TARGET		:= unit_test_attribute
SOURCES		:= unit_test_attribute.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a libfreeradius-dhcp.a
TGT_LDLIBS	:= $(LIBS)
