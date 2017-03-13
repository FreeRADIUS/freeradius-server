TARGET	:= libfreeradius-server.a

SOURCES	:=	cond_eval.c \
		cond_tokenize.c \
		conf_file.c \
		connection.c \
		dl.c \
		exec.c \
		exfile.c \
		log.c \
		map_proc.c \
		map.c \
		regex.c \
		request.c \
		trigger.c \
		tmpl.c \
		util.c \
		version.c \
		pair.c \
		xlat_eval.c \
		xlat_func.c \
		xlat_tokenize.c

# This lets the linker determine which version of the SSLeay functions to use.
TGT_LDLIBS  := $(LIBS) $(OPENSSL_LIBS) $(GPERFTOOLS_FLAGS) $(GPERFTOOLS_LIBS)
TGT_PREREQS	:= libfreeradius-radius.la

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
