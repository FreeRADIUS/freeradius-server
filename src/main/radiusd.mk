TARGET	:= radiusd
SOURCES := \
    auth.c \
    conduit.c \
    client.c \
    crypt.c \
    users_file.c \
    mainconfig.c \
    radiusd.c \
    state.c \
    stats.c \
    soh.c \
    snmp.c \
    process.c

SRC_CFLAGS	:=

TGT_INSTALLDIR  := ${sbindir}
TGT_LDLIBS	:= $(LIBS) $(LCRYPT) $(SYSTEMD_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(SYSTEMD_LDFLAGS)
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a libfreeradius-util.a
