TARGETNAME  := radmin

ifneq "$(LIBREADLINE)" ""
TARGET		:= $(TARGETNAME)
endif

SOURCES		:= radmin.c

TGT_INSTALLDIR  := ${sbindir}
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a libfreeradius-control.a
TGT_LDLIBS	:= $(LIBS) $(LIBREADLINE)
