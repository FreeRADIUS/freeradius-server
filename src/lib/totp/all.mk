TARGETNAME  := libfreeradius-totp
TARGET      := $(TARGETNAME)$(L)

SOURCES	    := totp.c

src/freeradius-devel: | src/lib/totp/base.h
