#
#  This file is just like 'Makefile', but with the comments stripped out.
#  It shows just how small the 'Makefile' really can be.
#
include config.mak

TARGET		= rlm_ldap
SRCS		= rlm_ldap.c
HEADERS		= config.h
RLM_CFLAGS	= $(LIBLDAP_CFLAGS)
RLM_LIBS	= $(LIBLDAP)

# check for LDAP
#
# This should be where your LDAP dependancies are installed
#
# This is the default location for OpenLDAP libs
LDAP_LOCATION=/usr/local
# This is the default location for OpenSSL libs 
#OpenSSL_LOCATION=/usr/local
OpenSSL_LOCATION=/usr
# This is the default location for Cyrus-SASL libs
SASL_LOCATION=/usr/local

ifeq ($(LIBLDAP),)
TARGET=
endif

# over-ride the previous assignment if we're not building anything
include ../rules.mak

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

config.mak config.h:
	@../checkconfig -l LIBLDAP ldap_init "-pthread -lldap_r -llber -L$(LDAP_LOCATION)/lib -lsasl -L$(SASL_LOCATION)/lib -lssl -lcrypto -L$(OpenSSL_LOCATION)/lib" "-I$(LDAP_LOCATION)/include -pthread -DHAVE_TLS -I$(OpenSSL_LOCATON)/include -I$(SASL_LOCATION)/include"
	@../checkconfig -l LIBLDAP ldap_init "-pthread -lldap_r -llber -L$(LDAP_LOCATION)/lib -lssl -lcrypto -L$(OpenSSL_LOCATION)/lib" "-I$(LDAP_LOCATION)/include -pthread -DHAVE_TLS -I$(OpenSSL_LOCATON)/include"
