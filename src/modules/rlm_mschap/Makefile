#
# Makefile
#
# Version:	$Id$
#

TARGET		= rlm_mschap
SRCS		= rlm_mschap.c smbdes.c
HEADERS		=
RLM_CFLAGS	=
RLM_LDFLAGS	=
RLM_UTILS   	= smbencrypt
RLM_INSTALL 	= smbencrypt-install

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(LT_OBJS): $(HEADERS)

smbencrypt: smbencrypt.lo smbdes.lo $(HEADERS)
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) -o smbencrypt smbencrypt.lo smbdes.lo ../../lib/libradius.la $(LIBS)

smbencrypt-install:
	$(INSTALL) -d -m 755 $(R)$(bindir)
	$(LIBTOOL) --mode=install $(INSTALL) -m 755 $(INSTALLSTRIP) smbencrypt$(EXEEXT) $(R)$(bindir)
