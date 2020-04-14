TARGETNAME  := radmin

ifneq "$(LIBREADLINE)" ""
TARGET		:= $(TARGETNAME)
endif

SOURCES		:= radmin.c

SRC_CFLAGS	:= $(LIBREADLINE_CFLAGS)

TGT_INSTALLDIR  := ${sbindir}
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.a libfreeradius-control.a libfreeradius-io.a
TGT_LDLIBS	:= $(LIBS) $(LIBREADLINE)
TGT_LDFLAGS	:= $(LDFLAGS) $(LIBREADLINE_LDFLAGS)
