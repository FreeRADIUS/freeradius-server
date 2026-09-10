TARGET		:= libfreeradius-unlang$(L)
TGT_CATEGORY	:= lib-util

SOURCES	:=	base.c \
		call.c \
		call_env.c \
		caller.c \
		catch.c \
		child_request.c \
		compile.c \
		condition.c \
		detach.c \
		edit.c \
		finally.c \
		foreach.c \
		function.c \
		group.c \
		interpret.c \
		interpret_synchronous.c \
		io.c \
		limit.c \
		load_balance.c \
		map.c \
		map_builtin.c \
		mod_action.c \
		module.c \
		parallel.c \
		return.c \
		subrequest.c \
		switch.c \
		timeout.c \
		tmpl.c \
		try.c \
		transaction.c \
		xlat.c \
		xlat_alloc.c \
		xlat_builtin.c \
		xlat_eval.c \
		xlat_expr.c \
		xlat_func.c \
		xlat_inst.c \
		xlat_pair.c \
		xlat_profiling.c \
		xlat_purify.c \
		xlat_redundant.c \
		xlat_tokenize.c

HEADERS		:= $(subst src/lib/,,$(wildcard src/lib/unlang/*.h))

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL) libfreeradius-server$(L)

#  xlat_profiling.c controls two profilers.  gperftools needs libprofiler,
#  because ProfilerStart() and the other control functions live in that
#  library.  Callgrind needs no library: every CALLGRIND_* macro in
#  valgrind/callgrind.h expands to an inline assembly client request that
#  the valgrind core recognises and a natively running CPU ignores.
TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_LDFLAGS)

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif

# ID of this library
LOG_ID_LIB	:= 2

# different pieces of this library
$(call DEFINE_LOG_ID_SECTION,compile,	1,compile.c)
$(call DEFINE_LOG_ID_SECTION,keywords,	2,call.c caller.c condition.c detach.c foreach.c function.c group.c io.c load_balance.c map.c map_builtin.c module.c parallel.c return.c subrequest.c subrequest_child.c switch.c)
$(call DEFINE_LOG_ID_SECTION,interpret,	3, interpret.c interpret_synchronous.c)
$(call DEFINE_LOG_ID_SECTION,expand,	4,tmpl.c xlat.c xlat_builtin.c xlat_eval.c xlat_inst.c xlat_pair.c xlat_profiling.c xlat_tokenize.c)
