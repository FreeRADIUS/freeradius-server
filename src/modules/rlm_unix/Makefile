include config.mak

TARGET	= rlm_unix
SRCS	= rlm_unix.c cache.c

#
#  If no /etc/passwd, then we don't use this module.
#
ifndef ETC_PASSWD
TARGET	=
endif

include ../rules.mak

LIBS	= $(LIBSHADOW) $(LIBCRYPT)


rlm_unix.c: config.h

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
	@../checkconfig -f ETC_PASSWD /etc/passwd
