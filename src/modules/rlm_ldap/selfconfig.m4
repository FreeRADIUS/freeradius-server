dnl  There's no runtime magic here.  This is included at compile time to make
dnl  a default etc/raddb/radiusd.conf for installation.
dnl
INSERT_GLOBAL_CONFIG(5)dnl
dnl nothing
INSERT_MODULE_INSTANTIATION(5)dnl
	#
	# Uncomment this if you want to use ldap (Auth-Type = LDAP)
	# Also uncomment it in the authenticate{} block below
	#ldap {
	#	server = localhost
	#	login = "cn=admin,o=My Org,c=US"
	#	password = mypass
	#	basedn = "o=My Org,c=US"
	#	filter = "(uid=%u)"
	#}
INSERT_DEF_AUTHENTICATION(5)dnl
	#ldap
INSERT_DEF_AUTHORIZATION(5)dnl
dnl nothing
INSERT_DEF_PREACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_ACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_SESSION(5)dnl
dnl nothing
