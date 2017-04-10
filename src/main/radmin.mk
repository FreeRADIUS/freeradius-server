TARGETNAME  := radmin

ifneq "$(LIBREADLINE)" ""
TARGET		:= $(TARGETNAME)
endif

SOURCES		:= radmin.c conduit.c

TGT_INSTALLDIR  := ${sbindir}
TGT_PREREQS	:= libfreeradius-server.a libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS) $(LIBREADLINE)
