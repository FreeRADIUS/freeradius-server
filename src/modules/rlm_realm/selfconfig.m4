dnl  There's no runtime magic here.  This is included at compile time to make
dnl  a default etc/raddb/radiusd.conf for installation.
dnl
INSERT_GLOBAL_CONFIG(5)dnl
dnl nothing
INSERT_MODULE_INSTANTIATION(5)dnl
	#
	#  You can have multiple instances of the realm module to
	#  support multiple realm syntaxs at the same time.  The
	#  search order is defined the order in the authorize and
	#  preacct blocks after the module config block.
	#
	#  Two config options:
	#       format     -  must be 'prefix' or 'suffix'
	#       delimiter  -  must be a single character
	#
	#  'username@realm'
	#
	realm suffix {
		format = suffix
		delimiter = "@"
	}

	#
	#  'realm/username'
	#
	#  Using this entry, IPASS users have their realm set to "IPASS".
	#
	#realm prefix {
	#	format = prefix
	#	delimiter = "/"
	#}

	#
	#  'username%realm'
	#
	#realm percent {
	#	format = suffix
	#	delimiter = "%"
	#}
INSERT_DEF_AUTHENTICATION(5)dnl
dnl nothing
INSERT_DEF_AUTHORIZATION(1)dnl  important that it come early
	suffix
INSERT_DEF_PREACCOUNTING(1)dnl
	suffix
INSERT_DEF_ACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_SESSION(5)dnl
dnl nothing
