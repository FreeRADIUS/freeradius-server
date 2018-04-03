TARGET		:= libfreeradius-unlang.a

SOURCES	:=	compile.c \
		interpret.c \
		op.c \
		map.c \
		module.c \
		xlat.c

TGT_PREREQS	+= libfreeradius-util.a libfreeradius-server.a

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
