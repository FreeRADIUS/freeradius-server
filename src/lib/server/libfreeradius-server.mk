TARGET		:= libfreeradius-server$(L)

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
	global_lib.c \
	log.c \
	main_config.c \
	main_loop.c \
	map.c \
	map_async.c \
	map_proc.c \
	method.c \
	module.c \
	module_rlm.c \
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
	tmpl_dcursor.c \
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
TGT_PREREQS	:= libfreeradius-tls$(L)
endif

TGT_PREREQS	+= libfreeradius-util$(L)

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif

# ID of this library
LOG_ID_LIB	:= 1

# different pieces of this library
$(call DEFINE_LOG_ID_SECTION,config,	1,cf_file.c cf_parse.c cf_util.c)
$(call DEFINE_LOG_ID_SECTION,conditions,2,conf_eval.c cond_tokenize.c)
$(call DEFINE_LOG_ID_SECTION,exec,	3,exec.c exec_legacy.c)
$(call DEFINE_LOG_ID_SECTION,modules,	4,dl_module.c module.c module_rlm.c method.c)
$(call DEFINE_LOG_ID_SECTION,map,	5,map.c map_proc.c map_async.c)
$(call DEFINE_LOG_ID_SECTION,snmp,	6,snmp.c)
$(call DEFINE_LOG_ID_SECTION,templates,	7,tmpl_eval.c tmpl_tokenize.c)
$(call DEFINE_LOG_ID_SECTION,triggers,	8,trigger.c)
$(call DEFINE_LOG_ID_SECTION,trunk,	9,trunk.c)
$(call DEFINE_LOG_ID_SECTION,virtual_servers,10,virtual_servers.c)
