TARGET	:= radiusd
SOURCES := \
    auth.c \
    conduit.c \
    client.c \
    crypt.c \
    files.c \
    mainconfig.c \
    modules.c \
    radiusd.c \
    state.c \
    stats.c \
    soh.c \
    snmp.c \
    unlang_compile.c \
    unlang_interpret.c \
    virtual_servers.c \
    process.c

SRC_CFLAGS	:=

TGT_INSTALLDIR  := ${sbindir}
TGT_LDLIBS	:= $(LIBS) $(LCRYPT) $(SYSTEMD_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(SYSTEMD_LDFLAGS)
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a libfreeradius-util.a

# Libraries can't depend on libraries (oops), so make the binary
# depend on the EAP code...
ifneq "$(filter rlm_eap_%,${ALL_TGTS})" ""
TGT_PREREQS	+= libfreeradius-eap.a
endif
