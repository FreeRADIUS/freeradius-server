TARGETNAME	:= libfreeradius-tls

ifneq ($(OPENSSL_LIBS),)
TARGET		:= $(TARGETNAME).a
endif

SOURCES	:= \
	base.c \
	cache.c \
	conf.c \
	ctx.c \
	engine.c \
	log.c \
	ocsp.c \
	pairs.c \
	session.c \
	utils.c \
	validate.c \
	virtual_server.c

TGT_PREREQS := libfreeradius-internal.a libfreeradius-util.a

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
