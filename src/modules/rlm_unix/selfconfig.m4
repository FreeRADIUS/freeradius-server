dnl  There's no runtime magic here.  This is included at compile time to make
dnl  a default etc/raddb/radiusd.conf for installation.
dnl
INSERT_GLOBAL_CONFIG(5)dnl
dnl nothing
INSERT_MODULE_INSTANTIATION(5)dnl
	#
	unix {
		#
		#  Cache /etc/passwd, /etc/shadow, and /etc/group
		#
		#  The default is to NOT cache them.  However, caching them can
		#  speed up system authentications by a substantial amount.
		#
		# allowed values: {no, yes}
		cache = no

		#
		#  Define the locations of the normal passwd, shadow, and
		#  group files.
		#
		#  'shadow' is commented out by default, because not all
		#  systems have shadow passwords.
		#
		passwd = /etc/passwd
		#	shadow = /etc/shadow
		group = /etc/group

		#
		#  Where the 'wtmp' file is located.
		#  This will be moved to it's own module soon..
		#
		radwtmp = ${logdir}/radwtmp
	}
INSERT_DEF_AUTHENTICATION(8)dnl  this should come late, as it's inefficient
	unix
INSERT_DEF_AUTHORIZATION(6)dnl
dnl nothing
INSERT_DEF_PREACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_ACCOUNTING(5)dnl
	unix
INSERT_DEF_SESSION(5)dnl
dnl nothing
