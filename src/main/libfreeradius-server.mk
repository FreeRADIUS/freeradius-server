TARGET	:= libfreeradius-server.a

SOURCES	:=	conffile.c \
		evaluate.c \
		exec.c \
		exfile.c \
		log.c \
		parser.c \
		map.c \
		regex.c \
		tmpl.c \
		util.c \
		version.c \
		pair.c \
		xlat.c

# This lets the linker determine which version of the SSLeay functions to use.
TGT_LDLIBS      := $(OPENSSL_LIBS)

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
