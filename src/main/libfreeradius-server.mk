TARGET		:= libfreeradius-server.a

SOURCES	:=	client.c \
		cond_eval.c \
		cond_tokenize.c \
		cf_file.c \
		cf_parse.c \
		cf_util.c \
		connection.c \
		command.c \
		dl.c \
		dependency.c \
		exec.c \
		exfile.c \
		log.c \
		mainconfig.c \
		map_proc.c \
		map.c \
		module.c \
		pairmove.c \
		regex.c \
		request.c \
		trigger.c \
		tmpl.c \
		util.c \
		virtual_servers.c \
		paircmp.c \
		pool.c \
		xlat_eval.c \
		xlat_func.c \
		xlat_inst.c \
		xlat_tokenize.c \

# This lets the linker determine which version of the SSLeay functions to use.
TGT_LDLIBS	:= $(LIBS) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(GPERFTOOLS_FLAGS)

ifneq ($(OPENSSL_LIBS),)
TGT_PREREQS	:= libfreeradius-tls.a
endif

TGT_PREREQS	+= libfreeradius-util.a

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
