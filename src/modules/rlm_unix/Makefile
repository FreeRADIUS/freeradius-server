TARGET	= rlm_unix
SRCS	= rlm_unix.c cache.c

include ../rules.mak

CFLAGS		+= -DLOGDIR=\"$(LOGDIR)\"

rlm_unix.c: config.h

include config.mak

LIBS += $(LIBSHADOW) $(LIBCRYPT)

config: config.mak

config.mak config.h:
	@../checkconfig -c LIBCRYPT crypt
	@../checkconfig -I HAVE_CRYPT_H crypt.h
	@../checkconfig -l LIBCRYPT crypt -lcrypt
	@../checkconfig -c HAVE_GETSPNAM getspnam
	@../checkconfig -l LIBSHADOW getspnam -lshadow
	@../checkconfig -f ETC_SHADOW /etc/shadow
	@../checkconfig -I HAVE_SHADOW_H shadow.h
	@../checkconfig -c HAVE_GETUSERSHELL getusershell
