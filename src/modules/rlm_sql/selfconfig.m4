dnl  There's no runtime magic here.  This is included at compile time to make
dnl  a default etc/raddb/radiusd.conf for installation.
dnl
INSERT_GLOBAL_CONFIG(5)dnl
dnl nothing
INSERT_MODULE_INSTANTIATION(5)dnl
	#
	#  Configuration for the SQL module.
	#
	sql {
		# Connect info
		server		= "localhost"
		login		= "root"
		password	= "rootpass"

		# Database table configuration
		radius_db	= "radius"
		acct_table	= "radacct"

		authcheck_table = "radcheck"
		authreply_table = "radreply"

		groupcheck_table = "radgroupcheck"
		groupreply_table = "radgroupreply"

		usergroup_table	= "usergroup"

		realms_table 	= "realms"
		realmgroup_table = "realmgroup"

		# Check case on usernames
		sensitiveusername = no

		# Remove stale session if checkrad does not see a double login
		deletestalesessions = yes

		# Print all SQL statements when in debug mode (-x)
		sqltrace	= no
		sqltracefile = ${logdir}/sqltrace.sql

		# number of sql connections to make to server
		num_sql_socks = 5
	}

	#
	#  A second instance of the same module, with the name "sql2" to identify it
	#
	sql sql2 {
	
		# Connect info
		server = "myothersever"
		login = "root"
		password = "rootpass"
		
		# Database table configuration
		radius_db = "radius"
		acct_table = "radacct"
		
		authcheck_table = "radcheck"
		authreply_table = "radreply"
		
		groupcheck_table = "radgroupcheck"
		groupreply_table = "radgroupreply"
		
		usergroup_table = "usergroup"
		
		realms_table = "realms"
		realmgroup_table = "realmgroup"
		
		# Check case on usernames
		sensitiveusername = no
	
		# Remove stale session if checkrad does not see a double login
		deletestalesessions = yes
	
		# Print all SQL statements when in debug mode (-x)
		sqltrace = no
	}
INSERT_DEF_AUTHENTICATION(5)dnl
	#
	# By grouping modules together in an authtype block, that authtype will be
	# tried on each module in sequence until one returns REJECT or OK. This
	# allows authentication failover if the first SQL server has crashed, for
	# example.
	#authtype SQL {
	#	sql
	#	sql2
	#}
INSERT_DEF_AUTHORIZATION(5)dnl
dnl nothing
INSERT_DEF_PREACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_ACCOUNTING(5)dnl
dnl nothing
INSERT_DEF_SESSION(5)dnl
dnl nothing
