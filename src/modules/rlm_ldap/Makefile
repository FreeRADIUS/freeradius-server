#
#  This file is just like 'Makefile', but with the comments stripped out.
#  It shows just how small the 'Makefile' really can be.
#
include config.mak

TARGET		= rlm_ldap
SRCS		= rlm_ldap.c
HEADERS		= config.h
RLM_CFLAGS	= $(LIBLDAP_CFLAGS)
LIBS		= $(LIBLDAP)

# check for LDAP
#
# This should be where your LDAP LIBS are installed
#
# This is the default location for OpenLDAP libs
LDAP_LOCATION=/usr/local/ldap
# This is the default location for mozilla libs (at least on my system)
#LDAP_LOCATION=/usr/lib

ifeq ($(LIBLDAP),)
TARGET=
endif

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

config.mak config.h:
	@../checkconfig -l LIBLDAP ldap_init -lldap  "-L$(LDAP_LOCATION)/lib -llber -I$(LDAP_LOCATION)/include"
