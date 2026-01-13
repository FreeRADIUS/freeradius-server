#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-radius-stats$(L)

SOURCES		:= base.c

TGT_PREREQS	:= libfreeradius-util$(L) libfreeradius-radius$(L)

TGT_POSTCLEAN	:= $(wildcard src/stats/radius/*.cache)

$(eval $(call DICT_STATS,radius,auth_serv,mib-2.radiusAuthServ,1.3.6.1.2.1.67.1.1.1.1))
