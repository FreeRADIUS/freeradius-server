dnl  There's no runtime magic here.  This is included at compile time to make
dnl  a default etc/raddb/radiusd.conf for installation.
dnl
INSERT_GLOBAL_CONFIG(5)dnl
dnl nothing
INSERT_MODULE_INSTANTIATION(5)dnl
	#
	preprocess {
		huntgroups = ${confdir}/huntgroups
		hints = ${confdir}/hints

		#
		# This hack changes Ascend's wierd port numberings
		# to standard 0-??? port numbers so that the "+" works
		# for IP address assignments.
		#
		with_ascend_hack = no
		ascend_channels_per_line = 23

		#
		# Windows NT machines often authenticate themselves as
		# NT_DOMAIN\username
		#
		# If this is set to 'yes', then the NT_DOMAIN portion
		# of the user-name is silently discarded.
		#
		with_ntdomain_hack = no

		#
		# Specialix Jetstream 8500 24 port access server.
		#
		# If the user name is 10 characters or longer, a "/"
		# and the excess characters after the 10th are
		# appended to the user name.
		#
		# If you're not running that NAS, you don't need
		# this hack.
		#
		with_specialix_jetstream_hack = no
	}
INSERT_DEF_AUTHENTICATION(5)dnl
dnl nothing
INSERT_DEF_AUTHORIZATION(5)dnl
dnl nothing
INSERT_DEF_PREACCOUNTING(8)dnl
	preprocess
INSERT_DEF_ACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_SESSION(5)dnl
dnl nothing
