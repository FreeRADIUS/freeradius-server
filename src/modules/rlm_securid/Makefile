#
# Makefile
#
#  You MUST edit this file by hand to make it work.
#  There is NO "configure" script available.
#
# Version:	$Id$
#

#
#	SET THE TARGET
#
TARGET	    =
#TARGET      = rlm_securid

SRCS        = rlm_securid.c mem.c

#
#	SET THE CORRECT PATH TO THE SECURID FILES 
#
ACE_PATH = /path/to/SECURID81
ARCH = lnx

HEADERS    = rlm_securid.h
RLM_LIBS   = -laceclnt 

#
#  YOU WILL PROBABLY NEED TO COPY $(ACE_PATH/lib/$(ARCH) to /usr/lib
#
RLM_CFLAGS =     -I$(ACE_PATH)/inc -DUNIX

include ../rules.mak

$(LT_OBJS): $(HEADERS)
