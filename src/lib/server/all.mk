TARGET		:= libfreeradius-server.a

SOURCES	:= \
	base.c \
	auth.c \
	cf_file.c \
	cf_parse.c \
	cf_util.c \
	client.c \
	command.c \
	cond_eval.c \
	cond_tokenize.c \
	connection.c \
	crypt.c \
	dependency.c \
	dl_module.c \
	exec.c \
	exfile.c \
	log.c \
	main_config.c \
	main_loop.c \
	map_proc.c \
	map.c \
	module.c \
	paircmp.c \
	pairmove.c \
	password.c \
	pool.c \
	rcode.c \
	regex.c \
	request.c \
	snmp.c \
	state.c \
	stats.c \
	tmpl.c \
	trigger.c \
	users_file.c \
	util.c \
	virtual_servers.c \
	xlat_builtin.c \
	xlat_eval.c \
	xlat_inst.c \
	xlat_tokenize.c

HEADERS		:= $(subst src/lib/,,$(wildcard src/lib/server/*.h))

# This lets the linker determine which version of the SSLeay functions to use.
TGT_LDLIBS	:= $(LIBS) $(SYSTEMD_LIBS) $(GPERFTOOLS_LIBS) $(LCRYPT)
TGT_LDFLAGS	:= $(LDFLAGS) $(SYSTEMD_LDFLAGS) $(GPERFTOOLS_FLAGS)

ifneq ($(OPENSSL_LIBS),)
TGT_PREREQS	:= libfreeradius-tls.a
endif

TGT_PREREQS	+= libfreeradius-util.a

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
