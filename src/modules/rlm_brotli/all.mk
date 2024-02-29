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

TARGETNAME	:= rlm_brotli

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c

SRC_CFLAGS	:= -isystem /opt/homebrew/include/ -isystem /opt/homebrew/include/ 
TGT_LDLIBS	:=  -lbrotlidec -L/opt/homebrew/lib -Wl,-rpath,/opt/homebrew/lib -lbrotlienc 
LOG_ID_LIB	= 61
