TARGETNAME	:= libfreeradius-ldap

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= libfreeradius-ldap.c control.c directory.c edir.c util.c 

SRC_CFLAGS	:=     
TGT_LDLIBS	:=  -lldap 
