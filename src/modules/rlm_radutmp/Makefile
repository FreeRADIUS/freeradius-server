include config.mak

#
#  This module is NOT built by default, as it's in a REALLY alpha
#  development stage, and doesn't integrate well with the rest of the
#  system.
#
#TARGET	= rlm_radutmp
#SRCS	= rlm_radutmp.c

include ../rules.mak

rlm_radutmp.c: config.h

config: config.mak

# Just a dummy entry for now, but someday it'll use mmap
config.mak config.h:
	@../checkconfig -I HAVE_SYS_MMAN_H sys/mman.h
