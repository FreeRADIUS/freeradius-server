TARGET		:= libfreeradius-server.a

SOURCES	:=	cond_eval.c \
		cond_tokenize.c \
		cf_file.c \
		cf_parse.c \
		cf_util.c \
		connection.c \
		dl.c \
		exec.c \
		exfile.c \
		log.c \
		map_proc.c \
		map.c \
   		modules.c \
		regex.c \
		request.c \
		trigger.c \
		tmpl.c \
		util.c \
		version.c \
   		virtual_servers.c \
		pair.c \
		pool.c \
    		unlang_compile.c \
    		unlang_interpret.c \
		xlat_eval.c \
		xlat_func.c \
		xlat_tokenize.c

# This lets the linker determine which version of the SSLeay functions to use.
TGT_LDLIBS	:= $(LIBS) $(OPENSSL_LIBS) $(GPERFTOOLS_FLAGS) $(GPERFTOOLS_LIBS)

ifneq ($(OPENSSL_LIBS),)
TGT_PREREQS	:= libfreeradius-tls.a
endif

TGT_PREREQS	+= libfreeradius-util.a

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
