TARGET		:= libfreeradius-unlang.a

SOURCES	:=	base.c \
		call.c \
		compile.c \
		condition.c \
		foreach.c \
		function.c \
		group.c \
		interpret.c \
		io.c \
		load_balance.c \
		map.c \
		module.c \
		parallel.c \
		return.c \
		subrequest.c \
		switch.c \
		tmpl.c \
		xlat.c \
		xlat_builtin.c \
		xlat_eval.c \
		xlat_inst.c \
		xlat_tokenize.c

HEADERS		:= $(subst src/lib/,,$(wildcard src/lib/unlang/*.h))

TGT_PREREQS	+= libfreeradius-util.a libfreeradius-server.a

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
