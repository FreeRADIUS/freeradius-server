#######################################################################
#
# This rule should be first.
#
# If the file 'config.mak' doesn't exist,
# GNU Make will look for a makefile rule to build it,
# and then execute that rule.
#
#######################################################################
include config.mak

#######################################################################
#
# This section sets the general names of things.  Each Makefile SHOULD
# include all of these definitions.  Note that there's no 'OBJS'
# definition.  The 'rules.mak' file handles that.
#
# Set the target library to make.  Note that it is WITHOUT the '.a'
# or '.so'.  Some systems do not have these endings (e.g. AIX & Windows)
#
# The SRCS definition should list ALL source files.
#
# The HEADERS definition should list ALL header files
#
# RLM_CFLAGS defines addition C compiler flags.  You usually don't
# want to modify this, though.
#
# The LIBS definition should list ALL required libraries.
# These libraries really should be pulled from the 'config.mak'
# definitions, if at all possible.  These definitions are also
# echoed into another file in ../lib, where they're picked up by
# ../main/Makefile for building the version of the server with
# statically linked modules.
#
#######################################################################
TARGET		= rlm_example
SRCS		= rlm_example.c other.c
HEADERS		= config.h other.h

#
#  Use the following flags if the compiler is GCC, and you're
#  extremely paranoid.
#
#RLM_CFLAGS	= -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align \
#		  -Wwrite-strings -Wconversion -Wstrict-prototypes \
#		  -Wmissing-prototypes -Wmissing-declarations \
#		  -Wnested-externs
RLM_CFLAGS	=
LIBS		= $(LIBC_STRCPY)

#######################################################################
#
#  over-ride the previous assignment of TARGET if we don't have a
#  definition for LIBC_STRCPY.
#
#  The general use for this rule is to NOT build this module if the
#  libraries it needs aren't installed on the system.  e.g. If there's
#  no LDAP libraries, the rlm_ldap TARGET should be empty.
#
#######################################################################
ifeq ($(LIBC_STRCPY),)
TARGET=
endif

#######################################################################
#
#  Grab the generic rules file for making everything.
#
#######################################################################
include ../rules.mak

#######################################################################
#
#  We've got a 'config.h' file, so the objects depend on it.
#  This is so we can reconfigure on the fly, and automatically rebuild
#  the libraries.
#
#  Note that we DO NOT list the '.a' or '.so' files here.  This
#  will make our life easier on systems which do not use '.a' or '.so'.
#
#  The file '../rules.mak' defines STATIC_OBJS and DYNAMIC_OBJS
#  from our SRCS definition, above.  This should hopefully hide any
#  platform-dependent cruft in ../rules.mak.
#
#######################################################################
$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

#######################################################################
#
#  A fake example: is strcpy() in libc?
#  If so, echo 'HAVE_STRCPY=-lc' > ./config.mak
#  and    echo '#define HAVE_STRCPY 1' > ./config.h
#
#######################################################################
config.mak config.h:
	@../checkconfig -l LIBC_STRCPY strcpy -lc
