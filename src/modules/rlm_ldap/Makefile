#
#  This file is just like 'Makefile', but with the comments stripped out.
#  It shows just how small the 'Makefile' really can be.
#
include config.mak

TARGET		= rlm_ldap
SRCS		= rlm_ldap.c
HEADERS		= config.h
RLM_CFLAGS	= $(LIBLDAP_CFLAGS)
RLM_LIBS	= $(LIBLDAP) $(LIBLBER)

# check for LDAP
#
# This should be where your LDAP LIBS are installed
#
# This is the default location for OpenLDAP libs
LDAP_LOCATION=/usr/local
# This is the default location for mozilla libs (at least on my system)
#LDAP_LOCATION=/usr

ifeq ($(LIBLDAP),)
TARGET=
endif

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

config.mak config.h:
	@../checkconfig -l LIBLDAP ldap_init -lldap "-L$(LDAP_LOCATION)/lib -I$(LDAP_LOCATION)/include"
	@../checkconfig -l LIBLDAP ldap_init "-lldap -llber -L$(LDAP_LOCATION)/lib" "-I$(LDAP_LOCATION)/include"
# This should check for the mozilla sdk.  I have only used the procompiled
# binary, I still need to try to compile it from source and see if it will
# work with this
	@../checkconfig -l LIBLDAP ldap_init "-lpthread -lldapssl30"
