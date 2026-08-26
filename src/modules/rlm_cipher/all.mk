#######################################################################
#
# TARGET should be set by autoconf only.  Don't touch it.
#
# The SOURCES definition should list ALL source files.
#
# SRC_CFLAGS defines addition C compiler flags.  You usually don't
# want to modify this, though.  Get it from autoconf.
#
# The TGT_LDLIBS definition should list ALL required libraries.
#
#######################################################################

TARGETNAME	:= rlm_cipher

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER)
LOG_ID_LIB	= 65
