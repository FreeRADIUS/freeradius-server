#
# Makefile	Radius Makefile for Linux (2.0.x, lib5 or libc6)
#
#

#
#	Autoselect -lshadow and -lcrypt
#
ifneq ($(wildcard /usr/lib/libshadow.a),)
LSHADOW	= -lshadow
endif
ifneq ($(wildcard /usr/lib/libcrypt.a),)
LCRYPT	= -lcrypt
endif

CC	= gcc
CFLAGS	= -Wall -g # -DNOSHADOW
LDFLAGS	= # -s # tatic
LIBS	= $(LSHADOW)

DBM	= -DNDBM
DBMLIB	= -ldb

# Uncomment these if you want PAM support
#PAM	= -DPAM
#PAMLIB	= -lpam -ldl

BINDIR  = /usr/local/bin
SBINDIR = /usr/local/sbin

include Make.inc
