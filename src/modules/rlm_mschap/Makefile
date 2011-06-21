#
# Makefile
#
# Version:	$Id$
#

TARGET		= rlm_mschap
SRCS		= rlm_mschap.c mschap.c smbdes.c opendir.c
HEADERS		= mschap.h smbdes.h
RLM_CFLAGS	= -F /System/Library/PrivateFrameworks
RLM_LDFLAGS	=
# libtool doesn't seem to pass the -F option to the linker so provide the full path to nt framework
RLM_LIBS	= -framework OpenDirectory /System/Library/PrivateFrameworks/nt.framework/nt
RLM_UTILS   	= smbencrypt
RLM_INSTALL 	= smbencrypt-install

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(LT_OBJS): $(HEADERS)

smbencrypt: smbencrypt.lo smbdes.lo $(LIBRADIUS)
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $(RLM_LDFLAGS) \
		-o $@ $^ $(RLM_LIBS) $(LIBS)

smbencrypt-install:
	$(INSTALL) -d -m 755 $(R)$(bindir)
	$(LIBTOOL) --mode=install $(INSTALL) -m 755 $(INSTALLSTRIP) \
		smbencrypt$(EXEEXT) $(R)$(bindir)
