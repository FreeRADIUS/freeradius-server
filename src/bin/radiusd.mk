TARGET	:= radiusd
SOURCES := \
    radiusd.c \
    radmin.c

SRC_CFLAGS	:= $(LIBREADLINE_CFLAGS)

TGT_INSTALLDIR  := ${sbindir}
TGT_LDLIBS	:= $(LIBS) $(SYSTEMD_LIBS) $(LIBREADLINE)
TGT_LDFLAGS	:= $(LDFLAGS) $(SYSTEMD_LDFLAGS) $(LIBREADLINE_LDFLAGS)
TGT_PREREQS	:= libfreeradius-unlang.a libfreeradius-io.a
