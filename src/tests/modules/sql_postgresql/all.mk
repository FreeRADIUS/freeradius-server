#
#  Test the postgresql module
#

# Don't test sql_postgresql if TEST_SERVER ENV is not set
sql_postgresql_require_test_server := 1

#  MODULE.test is the main target for this module.
sql_postgresql.test:
	@echo OK: sql_postgresql.test
