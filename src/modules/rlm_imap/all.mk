TARGETNAME	:= rlm_imap
ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME).a
endif
SOURCES		:= $(TARGETNAME).c 
SRC_CFLAGS	:=
TGT_LDLIBS	:=  -lc
#
#  We don't want to install this module.  No one will use it.
#
TGT_INSTALLDIR	:=
4:16
TGT_PREREQS = libfreeradius-curl.a
