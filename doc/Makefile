#
# Makefile
#
# Version:	$Id$
#

include ../Make.inc

SUBDIRS		= rfc
WHAT_TO_MAKE	= all

DOCS = aaa.txt ascend Autz-Type bay bugs cisco coding-methods.txt configurable_failover DIFFS duplicate-users MACOSX module_interface OS2 performance-testing processing_users_file proxy RADIUS-LDAP.schema RADIUS-LDAPv3.schema RADIUS-SQL.schema radrelay README Simultaneous-Use supervise-radiusd.txt tuning_guide variables.txt


all:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f include/*~ *~

install:
	$(INSTALL) -d -m 755	$(R)$(datadir)/doc
	$(INSTALL) -d -m 755	$(R)$(datadir)/doc/freeradius-$(RADIUSD_VERSION)
	for i in $(DOCS) rlm_*; do \
		$(INSTALL) -m 644 $$i $(R)$(datadir)/doc/freeradius-$(RADIUSD_VERSION); \
	done
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

common:
	@for dir in $(SUBDIRS); do \
		echo "Making $(WHAT_TO_MAKE) in $$dir..."; \
		(cd $$dir && $(MAKE) $(MFLAGS) $(WHAT_TO_MAKE)) || exit 1;\
	done
