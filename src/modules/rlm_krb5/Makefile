# must be first
include config.mak

TARGET		= rlm_krb5
SRCS		= rlm_krb5.c
HEADERS         = config.h
RLM_LIBS	= $(LIBKRB5)
RLM_CFLAGS      = $(LIBKRB5_CFLAGS)

# This is the default location for OpenLDAP libs
KRB5_LOCATION=/home/local/krb5

# over-ride the previous assignment if we're not building anything
ifeq ($(LIBKRB5),)
TARGET	=
endif

include ../rules.mak

# Look for kerberos libs, enable if found
config.mak:
	@../checkconfig -l LIBKRB5 krb5_init_context "-L$(KRB5_LOCATION)/lib -lkrb5 -lk5crypto -lcom_err" "-I$(KRB5_LOCATION)/include"
	@../checkconfig -l LIBKRB5 krb5_init_context "-L$(KRB5_LOCATION)/lib -lkrb5 -lcrypto -lcom_err" "-I$(KRB5_LOCATION)/include"

