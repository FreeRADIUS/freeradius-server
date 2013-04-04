TARGET		:= dhclient
SOURCES		:= dhclient.c

TGT_PREREQS	:= libfreeradius-radius.a
TGT_LDLIBS	:= $(LIBS)
