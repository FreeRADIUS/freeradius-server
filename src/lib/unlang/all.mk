TARGET		:= libfreeradius-unlang.a

SOURCES	:=	compile.c \
		foreach.c \
		interpret.c \
		io.c \
		op.c \
		load_balance.c \
		map.c \
		module.c \
		parallel.c \
		subrequest.c \
		xlat.c

HEADERS		:= $(subst src/lib/,,$(wildcard src/lib/unlang/*.h))

TGT_PREREQS	+= libfreeradius-util.a libfreeradius-server.a

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
