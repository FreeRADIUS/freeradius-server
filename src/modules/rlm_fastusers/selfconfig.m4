dnl  There's no runtime magic here.  This is included at compile time to make
dnl  a default etc/raddb/radiusd.conf for installation.
dnl
INSERT_GLOBAL_CONFIG(5)dnl
dnl nothing
INSERT_MODULE_INSTANTIATION(5)dnl
	#
	# See README.rlm_fastusers before using this
	# module or changing these values.
	fastusers {
		usersfile = ${confdir}/users_fast
		hashsize = 1000
		compat = no
		# Reload the hash every 600 seconds (10mins)
		reload_hash = 600
	}
INSERT_DEF_AUTHENTICATION(5)dnl
dnl nothing
INSERT_DEF_AUTHORIZATION(5)dnl
dnl nothing
INSERT_DEF_PREACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_ACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_SESSION(5)dnl
dnl nothing
