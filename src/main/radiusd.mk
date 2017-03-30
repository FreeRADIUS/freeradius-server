TARGET	:= radiusd
SOURCES := acct.c \
    auth.c \
    channel.c \
    client.c \
    crypt.c \
    detail.c \
    files.c \
    interpreter.c \
    listen.c \
    mainconfig.c \
    modules.c \
    modcall.c \
    radiusd.c \
    realms.c \
    state.c \
    stats.c \
    soh.c \
    session.c \
    snmp.c \
    threads.c \
    process.c

ifneq ($(OPENSSL_LIBS),)
include ${top_srcdir}/src/main/tls.mk
SOURCES += tls_listen.c
endif

SRC_CFLAGS	:= -DHOSTINFO=\"${HOSTINFO}\"

TGT_INSTALLDIR  := ${sbindir}
TGT_LDLIBS	:= $(LIBS) $(LCRYPT) $(SYSTEMD_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(SYSTEMD_LDFLAGS)
TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a

# Libraries can't depend on libraries (oops), so make the binary
# depend on the EAP code...
ifneq "$(filter rlm_eap_%,${ALL_TGTS})" ""
TGT_PREREQS	+= libfreeradius-eap.a
endif
