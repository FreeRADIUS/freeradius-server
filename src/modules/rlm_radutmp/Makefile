include config.mak

TARGET	= rlm_radutmp
SRCS	= rlm_radutmp.c

include ../rules.mak

rlm_radutmp.c: config.h

config: config.mak

# Just a dummy entry for now, but someday it'll use mmap
config.mak config.h:
	@../checkconfig -I HAVE_SYS_MMAN_H sys/mman.h
