TARGET	:= radiusd
SOURCES := \
    radiusd.c \
    radmin.c

SRC_CFLAGS	:= $(LIBREADLINE_CFLAGS)

TGT_INSTALLDIR  := ${sbindir}
TGT_LDLIBS	:= $(LIBS) $(SYSTEMD_LIBS) $(LIBREADLINE) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(SYSTEMD_LDFLAGS) $(LIBREADLINE_LDFLAGS)
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a libfreeradius-util.a

# Flags needed when linking main executables that link against LuaJIT
ifneq (,$(findstring darwin,$(TARGET_SYSTEM)))
TGT_LDLIBS	+= -pagezero_size 10000 -image_base 100000000
endif
