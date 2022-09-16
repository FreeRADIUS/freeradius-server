TARGET		:= radiusd$(E)
SOURCES		:= \
			radiusd.c \
			radmin.c

SRC_CFLAGS	:= $(LIBREADLINE_CFLAGS)

TGT_INSTALLDIR  := ${sbindir}
TGT_LDLIBS	:= $(LIBS) $(SYSTEMD_LIBS) $(LIBREADLINE) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(SYSTEMD_LDFLAGS) $(LIBREADLINE_LDFLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)

# Flags needed when linking main executables that link against LuaJIT
TGT_LDLIBS	+= $(LUAJIT_LDLIBS)
