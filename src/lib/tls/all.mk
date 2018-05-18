TARGETNAME	:= libfreeradius-tls

ifneq ($(OPENSSL_LIBS),)
TARGET		:= $(TARGETNAME).a
endif

SOURCES	:= \
	cache.c \
	conf.c \
	ctx.c \
	global.c \
	log.c \
	ocsp.c \
	session.c \
	utils.c \
	validate.c \

TGT_PREREQS := libfreeradius-util.la

# This lets the linker determine which version of the SSLeay functions to use.
TGT_LDLIBS  := $(LIBS) $(OPENSSL_LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS := $(OPENSSL_FLAGS) $(GPERFTOOL_FLAGS)

src/lib/tls/tls.h: src/lib/tls/tls-h src/include/autoconf.sed src/include/autoconf.h
	${Q}$(ECHO) HEADER $@
	${Q}sed -f src/include/autoconf.sed < $< > $@

src/freeradius-devel: | src/lib/tls/tls.h
