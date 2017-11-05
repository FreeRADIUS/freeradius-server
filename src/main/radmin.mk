TARGETNAME  := radmin

ifneq "$(LIBREADLINE)" ""
TARGET		:= $(TARGETNAME)
endif

SOURCES		:= radmin.c conduit.c

TGT_INSTALLDIR  := ${sbindir}
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a
TGT_LDLIBS	:= $(LIBS) $(LIBREADLINE)
