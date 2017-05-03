TARGETNAME  := radmin

ifneq "$(LIBREADLINE)" ""
TARGET		:= $(TARGETNAME)
endif

SOURCES		:= radmin.c conduit.c

TGT_INSTALLDIR  := ${sbindir}
TGT_PREREQS	:= libfreeradius-util.a libfreeradius-radius.a libfreeradius-server.a
TGT_LDLIBS	:= $(LIBS) $(LIBREADLINE)
