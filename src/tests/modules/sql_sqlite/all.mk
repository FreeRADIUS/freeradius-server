#
#  Test the sqlite module
#

#  MODULE.test is the main target for this module.
sql_sqlite.test:
	@echo OK: sql_sqlite.test

SQLITE_TESTDIR := $(BUILD_DIR)/tests/modules/sql_sqlite

$(SQLITE_TESTDIR)/acct_2_stop: $(SQLITE_TESTDIR)/acct_1_update

$(SQLITE_TESTDIR)/acct_1_update: $(SQLITE_TESTDIR)/acct_0_start

