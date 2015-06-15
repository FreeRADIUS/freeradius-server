TARGET		:= radattr
SOURCES		:= radattr.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a libfreeradius-dhcp.a
TGT_LDLIBS	:= $(LIBS)
