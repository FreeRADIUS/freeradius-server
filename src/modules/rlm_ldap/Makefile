#
#  This file is just like 'Makefile', but with the comments stripped out.
#  It shows just how small the 'Makefile' really can be.
#
include config.mak

TARGET		= rlm_ldap
SRCS		= rlm_ldap
HEADERS		= config.h
RLM_CFLAGS	= $(LIBLDAP_CFLAGS)
LIBS		=

# check for LDAP
# NOTE: The following filename is WRONG for your system!
# You'll have to replace the ' /a1/aland/src/ldap/' name
# with something like '/usr/local/'
#
#  That is, would someone with LDAP installed PLEASE fix this
# to be something sane.
#
LDAP_LOCATION=/a1/aland/src/ldap

ifeq ($(LIBLDAP),)
TARGET=
endif

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

config.mak config.h:
	@../checkconfig -l LIBLDAP ldap_init -lldap  "-L$(LDAP_LOCATION)/lib -llber -I$(LDAP_LOCATION)/include"
