dnl  this is included in 
dnl
dnl
INSERT_GLOBAL_CONFIG(5)dnl
dnl nothing
INSERT_MODULE_INSTANTIATION(5)dnl
	#
	# This module will add a (probably) unique session id 
	# to an accounting packet based on the attributes listed
	# below found in the packet.  see doc/README.rlm_acct_unique
	acct_unique {
		key = "User-Name, Acct-Session-Id, NAS-IP-Address, NAS-Port-Id"
	}
INSERT_DEF_AUTHENTICATION(5)dnl
dnl nothing
INSERT_DEF_AUTHORIZATION(5)dnl
dnl nothing
INSERT_DEF_PREACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_ACCOUNTING(5)dnl
	# acct_unique
INSERT_DEF_SESSION(5)dnl
