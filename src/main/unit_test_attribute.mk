TARGET		:= unit_test_attribute
SOURCES		:= unit_test_attribute.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-util.a libfreeradius-dhcp.a libfreeradius-tacacs.a
TGT_LDLIBS	:= $(LIBS)
