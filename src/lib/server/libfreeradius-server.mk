TARGET		:= libfreeradius-server.a

SOURCES	:= \
	auth.c \
	base.c \
	cf_file.c \
	cf_parse.c \
	cf_util.c \
	client.c \
	command.c \
	cond_eval.c \
	cond_tokenize.c \
	connection.c \
	dependency.c \
	dl_module.c \
	exec.c \
	exec_legacy.c \
	exfile.c \
	log.c \
	main_config.c \
	main_loop.c \
	map.c \
	map_async.c \
	map_proc.c \
	method.c \
	module.c \
	paircmp.c \
	pairmove.c \
	password.c \
	pool.c \
	rcode.c \
	regex.c \
	request.c \
	request_data.c \
	snmp.c \
	state.c \
	stats.c \
	tmpl_eval.c \
	tmpl_tokenize.c \
	trigger.c \
	trunk.c \
	users_file.c \
	util.c \
	virtual_servers.c

HEADERS		:= $(subst src/lib/,,$(wildcard src/lib/server/*.h))

# This lets the linker determine which version of the SSLeay functions to use.
TGT_LDLIBS	:= $(LIBS) $(SYSTEMD_LIBS) $(GPERFTOOLS_LIBS) $(LCRYPT)
TGT_LDFLAGS	:= $(LDFLAGS) $(SYSTEMD_LDFLAGS) $(GPERFTOOLS_LDFLAGS)

ifneq ($(OPENSSL_LIBS),)
TGT_PREREQS	:= libfreeradius-tls.a
endif

TGT_PREREQS	+= libfreeradius-util.a

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
