#
#  Test the mysql module
#

# Don't test sql_mysql if TEST_SERVER ENV is not set
sql_mysql_require_test_server := 1

#  MODULE.test is the main target for this module.
sql_mysql.test:
	@echo OK: sql_mysql.test

