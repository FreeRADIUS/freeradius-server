TARGET	:= radiusd
SOURCES := \
    auth.c \
    crypt.c \
    users_file.c \
    radiusd.c \
    radmin.c \
    state.c \
    stats.c \
    snmp.c \
    process.c

SRC_CFLAGS	:=

TGT_INSTALLDIR  := ${sbindir}
TGT_LDLIBS	:= $(LIBS) $(LCRYPT) $(SYSTEMD_LIBS) $(LIBREADLINE)
TGT_LDFLAGS	:= $(LDFLAGS) $(SYSTEMD_LDFLAGS)
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a libfreeradius-util.a
