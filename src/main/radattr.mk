TARGET		:= radattr
SOURCES		:= radattr.c

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a

ifneq "$(WITH_DHCP)" "no"
TGT_PREREQS	+= libfreeradius-dhcp.a
endif

TGT_LDLIBS	:= $(LIBS)
