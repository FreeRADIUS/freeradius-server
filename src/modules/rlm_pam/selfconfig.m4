dnl  There's no runtime magic here.  This is included at compile time to make
dnl  a default etc/raddb/radiusd.conf for installation.
dnl
INSERT_GLOBAL_CONFIG(5)dnl
dnl nothing
INSERT_MODULE_INSTANTIATION(5)dnl
	#
	pam {
		#
		#  The name to use for PAM authentication.
		#  PAM looks in /etc/pam.d/${pam_auth_name}
		#  or /etc/pam.conf for it's configuration.
		#
		#  Note that any Pam-Auth attribute set in the 'users'
		#  file over-rides this one.
		#
		pam_auth = radiusd
	}
INSERT_DEF_AUTHENTICATION(4)dnl earlier than unix
	pam
INSERT_DEF_AUTHORIZATION(5)dnl
dnl nothing
INSERT_DEF_PREACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_ACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_SESSION(5)dnl
dnl nothing
