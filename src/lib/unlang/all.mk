TARGET		:= libfreeradius-unlang.a

SOURCES	:=	base.c \
		call.c \
		caller.c \
		compile.c \
		condition.c \
		detach.c \
		foreach.c \
		function.c \
		group.c \
		interpret.c \
		interpret_synchronous.c \
		io.c \
		load_balance.c \
		map.c \
		module.c \
		parallel.c \
		return.c \
		subrequest.c \
		subrequest_child.c \
		switch.c \
		tmpl.c \
		xlat.c \
		xlat_builtin.c \
		xlat_eval.c \
		xlat_inst.c \
		xlat_tokenize.c \
		xlat_pair.c

HEADERS		:= $(subst src/lib/,,$(wildcard src/lib/unlang/*.h))

TGT_PREREQS	:= libfreeradius-util.la libfreeradius-server.a

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
