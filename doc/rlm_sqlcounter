	#  This module is an SQL enabled version of the counter module.
	#  
	#  Rather than maintaining seperate (GDBM) databases of accounting info
	#  	for each counter, this module uses the data stored in the raddacct
	#  	table by the sql modules. This module NEVER does any database 
	#	INSERTs or UPDATEs.  It is totally dependent on the SQL module
	#	to process Accounting packets.
	#
	#  The 'sqlmod_inst' parameter holds the instance of the sql module to use 
	#	when querying the SQL database. Normally it is just "sql".
	#	If you define more and one SQL module instance 
	#	(usually for failover situations), you can specify which module
	#	has access to the Accounting Data (radacct table).
	#
	#  The 'reset' parameter defines when the counters are all reset to
	#  	zero.  It can be hourly, daily, weekly, monthly or never.
	#  	It can also be user defined. It should be of the form:
	#  	num[hdwm] where:
	#  	h: hours, d: days, w: weeks, m: months
	#  	If the letter is ommited days will be assumed. In example:
	#  	reset = 10h (reset every 10 hours)
	#  	reset = 12  (reset every 12 days)
	#
	#  The 'key' parameter specifies the unique identifier for the counters
	#	records (usually 'User-Name'). 
	#
	# The 'query' parameter specifies the SQL query used to get the 
	#	current Counter value from the database. There are 3 parameters
	#	that can be used in the query:
	#		%k	'key' parameter
	#		%b	unix time value of beginning of reset period 
	#		%e	unix time value of end of reset period
	#
	#  The 'check-name' parameter is the name of the 'check' attribute to use to access
	#	the counter in the 'users' file or SQL radcheck or radcheckgroup 
	#	tables.
	#
	#  DEFAULT  Max-Daily-Session > 3600, Auth-Type = Reject
	#      Reply-Message = "You've used up more than one hour today"
	#1

	sqlcounter dailycounter {
		counter-name = Daily-Session-Time
		check-name = Max-Daily-Session
		sqlmod-inst = sqlcca3
		key = User-Name
		reset = daily

		# This query properly handles calls that span from the previous reset period
		# into the current period but involves more work for the SQL server than those below
		query = "SELECT SUM(AcctSessionTime - GREATEST((%b - UNIX_TIMESTAMP(AcctStartTime)), 0)) FROM radacct WHERE UserName='%{%k}' AND UNIX_TIMESTAMP(AcctStartTime) + AcctSessionTime > '%b'"

		# This query ignores calls that started in a previous reset period and 
		# continue into into this one. But it is a little easier on the SQL server 
		# query = "SELECT SUM(AcctSessionTime) FROM radacct WHERE UserName='%{%k}' AND AcctStartTime > FROM_UNIXTIME('%b')"

		# This query is the same as above, but demonstrates an additional 
		# counter parameter '%e' which is the timestamp for the end of the period
		# query = "SELECT SUM(AcctSessionTime) FROM radacct WHERE UserName='%{%k}' AND AcctStartTime BETWEEN FROM_UNIXTIME('%b') AND FROM_UNIXTIME('%e')"		
	}

	sqlcounter monthlycounter {
		counter-name = Monthly-Session-Time
		check-name = Max-Monthly-Session
		sqlmod-inst = sqlcca3
		key = User-Name
		reset = monthly

		# This query properly handles calls that span from the previous reset period
		# into the current period but involves more work for the SQL server than those below
		query = "SELECT SUM(AcctSessionTime - GREATEST((%b - UNIX_TIMESTAMP(AcctStartTime)), 0)) FROM radacct WHERE UserName='%{%k}' AND UNIX_TIMESTAMP(AcctStartTime) + AcctSessionTime > '%b'"

		# This query ignores calls that started in a previous reset period and 
		# continue into into this one. But it is a little easier on the SQL server 
		# query = "SELECT SUM(AcctSessionTime) FROM radacct WHERE UserName='%{%k}' AND AcctStartTime > FROM_UNIXTIME('%b')"

		# This query is the same as above, but demonstrates an additional 
		# counter parameter '%e' which is the timestamp for the end of the period
		# query = "SELECT SUM(AcctSessionTime) FROM radacct WHERE UserName='%{%k}' AND AcctStartTime BETWEEN FROM_UNIXTIME('%b') AND FROM_UNIXTIME('%e')"		
	}


# Authorization. First preprocess (hints and huntgroups files),
# then realms, and finally look in the "users" file.
# The order of the realm modules will determine the order that
# we try to find a matching realm.
# Make *sure* that 'preprocess' comes before any realm if you 
# need to setup hints for the remote radius server
authorize {
	preprocess
#	attr_filter
#	eap
	suffix
	files
        group {
                sql1 {
                        fail     = 1
                        notfound = return
                        noop     = 2
                        ok       = return
                        updated  = 3
                        reject   = return
                        userlock = 4
                        invalid  = 5
                        handled  = 6
                }
                sql2 {
                        fail     = 1
                        notfound = return
                        noop     = 2
                        ok       = return
                        updated  = 3
                        reject   = return
                        userlock = 4
                        invalid  = 5
                        handled  = 6
                }
        }
	dailycounter
	monthlycounter
#	mschap
}


# Authentication.
#
# This section lists which modules are available for authentication.
# Note that it does NOT mean 'try each module in order'.  It means
# that you have to have a module from the 'authorize' section add
# a configuration attribute 'Auth-Type := FOO'.  That authentication type
# is then used to pick the apropriate module from the list below.
authenticate {
#	pam
#	unix
#	ldap
	mschap
#	pap
#	eap
}


# Pre-accounting. Look for proxy realm in order of realms, then 
# acct_users file, then preprocess (hints file).
preacct {
	suffix
	files
	preprocess
}


# Accounting. Log to detail file, and to the radwtmp file, and maintain
# radutmp.
accounting {
	acct_unique
	detail
	sqlcca1
#	counter
#	unix
	radutmp
#	sradutmp
}


# Session database, used for checking Simultaneous-Use. The radutmp module
# handles this
session {
	radutmp
}
