TARGET	:= radiusd
SOURCES := acct.c auth.c client.c conffile.c crypt.c exec.c files.c \
		  listen.c log.c mainconfig.c modules.c modcall.c \
		  radiusd.c stats.c soh.c connection.c \
		  session.c threads.c util.c valuepair.c version.c  \
		  xlat.c process.c realms.c evaluate.c vmps.c detail.c
ifneq ($(OPENSSL_LIBS),)
SOURCES	+= cb.c tls.c tls_listen.c
endif

SRC_CFLAGS	:= -DHOSTINFO=\"${HOSTINFO}\"
TGT_INSTALLDIR  := ${sbindir}
TGT_LDLIBS	:= $(LIBS) $(LCRYPT) $(OPENSSL_LIBS)
TGT_PREREQS	:= libfreeradius-radius.a

# Libraries can't depend on libraries (oops), so make the binary
# depend on the EAP code...
ifneq "$(filter rlm_eap_%,${ALL_TGTS})" ""
TGT_PREREQS	+= libfreeradius-eap.a
endif
