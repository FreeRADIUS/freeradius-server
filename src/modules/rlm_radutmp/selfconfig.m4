dnl  There's no runtime magic here.  This is included at compile time to make
dnl  a default etc/raddb/radiusd.conf for installation.
dnl
INSERT_GLOBAL_CONFIG(5)dnl
dnl nothing
INSERT_MODULE_INSTANTIATION(5)dnl
	#
	# Needs definition.
	# radutmp {
	# }
INSERT_DEF_AUTHENTICATION(5)dnl
dnl nothing
INSERT_DEF_AUTHORIZATION(5)dnl
dnl nothing
INSERT_DEF_PREACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_ACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_SESSION(6)dnl
	# radutmp
