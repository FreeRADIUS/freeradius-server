dnl  There's no runtime magic here.  This is included at compile time to make
dnl  a default etc/raddb/radiusd.conf for installation.
dnl
INSERT_GLOBAL_CONFIG(5)dnl
dnl nothing
INSERT_MODULE_INSTANTIATION(5)dnl
#######################################################################
#
#  Configuration for the example module.  Uncommenting it will cause it
#  to get loaded and initialized, but should have no real effect as long
#  it is not referencened in one of the autz/auth/preacct/acct sections
#
	example {
	#
	#  Boolean variable.
	#
	# allowed values: {no, yes}
	#
		boolean = yes

	#
	#  An integer, of any value.
	#
		integer = 16

	#
	#  A string.
	#
		string = "This is an example configuration string"

	#
	# An IP address, either in dotted quad (1.2.3.4) or hostname
	# (example.com)
	#
		ipaddr = 127.0.0.1

	#
	# A subsection
	#
		mysubsection {
			anotherinteger = 1000
	#
	# They nest
	#
			deeply nested {
				string = "This is a different string"
			}
		}
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
