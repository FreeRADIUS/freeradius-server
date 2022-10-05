TARGETNAME	:= libfreeradius-tls

ifneq ($(OPENSSL_LIBS),)
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES	:= \
	base.c \
	bio.c \
	cache.c \
	cert.c \
	conf.c \
	ctx.c \
	engine.c \
	log.c \
	pairs.c \
	session.c \
	strerror.c \
	utils.c \
	verify.c \
	version.c \
	virtual_server.c

TGT_PREREQS := libfreeradius-internal$(L) libfreeradius-util$(L)

# This lets the linker determine which version of the SSLeay functions to use.
TGT_LDLIBS  := $(LIBS) $(OPENSSL_LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS := $(OPENSSL_FLAGS) $(GPERFTOOLS_LDFLAGS)

src/lib/tls/base.h: src/lib/tls/base-h src/include/autoconf.sed src/include/autoconf.h
	${Q}$(ECHO) HEADER $@
	${Q}sed -f src/include/autoconf.sed < $< > $@


src/lib/tls/conf.h: src/lib/tls/conf-h src/include/autoconf.sed src/include/autoconf.h
	${Q}$(ECHO) HEADER $@
	${Q}sed -f src/include/autoconf.sed < $< > $@

src/freeradius-devel: | src/lib/tls/base.h src/lib/tls/conf.h
