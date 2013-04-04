TARGET		:= dhclient
SOURCES		:= dhclient.c dhcp.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
