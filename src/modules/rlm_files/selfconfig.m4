dnl  There's no runtime magic here.  This is included at compile time to make
dnl  a default etc/raddb/radiusd.conf for installation.
dnl
INSERT_GLOBAL_CONFIG(5)dnl
dnl nothing
INSERT_MODULE_INSTANTIATION(5)dnl
	#
	files {
		usersfile = ${confdir}/users
		acctusersfile = ${confdir}/acct_users

		#  If you want to use the old Cistron 'users' file
		#  with FreeRADIUS, you should change the next line
		#  to 'compat = cistron'.  You can the copy your 'users'
		#  file from Cistron.
		compat = no
	}
INSERT_DEF_AUTHENTICATION(5)dnl
dnl nothing
INSERT_DEF_AUTHORIZATION(5)dnl
	files
INSERT_DEF_PREACCOUNTING(5)dnl
	files
INSERT_DEF_ACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_SESSION(5)dnl
dnl nothing
