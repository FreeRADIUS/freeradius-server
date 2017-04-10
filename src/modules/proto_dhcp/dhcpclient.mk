TARGET		:= dhcpclient
SOURCES		:= dhcpclient.c dhcp.c

TGT_PREREQS	:= libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS)
