TARGET		:= libfreeradius-unlang$(L)

SOURCES	:=	base.c \
		call.c \
		caller.c \
		compile.c \
		condition.c \
		detach.c \
		edit.c \
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
		xlat_expr.c \
		xlat_inst.c \
		xlat_tokenize.c \
		xlat_pair.c \
		xlat_purify.c

HEADERS		:= $(subst src/lib/,,$(wildcard src/lib/unlang/*.h))

TGT_PREREQS	:= libfreeradius-util$(L) libfreeradius-server$(L)

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif

# ID of this library
LOG_ID_LIB	:= 2

# different pieces of this library
$(call DEFINE_LOG_ID_SECTION,compile,	1,compile.c)
$(call DEFINE_LOG_ID_SECTION,keywords,	2,call.c caller.c condition.c detach.c foreach.c function.c group.c io.c load_balance.c map.c module.c parallel.c return.c subrequest.c subrequest_child.c switch.c)
$(call DEFINE_LOG_ID_SECTION,interpret,	3, interpret.c interpret_synchronous.c)
$(call DEFINE_LOG_ID_SECTION,expand,	4,tmpl.c xlat.c xlat_builtin.c xlat_eval.c xlat_inst.c xlat_pair.c xlat_tokenize.c)
