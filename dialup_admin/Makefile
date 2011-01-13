#
# Makefile
#
# Version:	$Id$
#

include ../Make.inc

DIALUP_PREFIX := /usr/local/dialup_admin
DIALUP_DOCDIR := $(DIALUP_PREFIX)/doc
DIALUP_CONFDIR := $(DIALUP_PREFIX)/conf

all:

install:
	install -d -m 0755 $(R)/$(DIALUP_PREFIX)
	install -d -m 0755 $(R)/$(DIALUP_DOCDIR)
	install -d -m 0755 $(R)/$(DIALUP_CONFDIR)
	install -d -m 0755 $(R)/$(DIALUP_PREFIX)/bin
	find doc Changelog README -name CVS -prune -o -type f -print0 | \
	  xargs -0 install -m 0644 -t $(R)/$(DIALUP_DOCDIR)
	find conf -name CVS -prune -o -type f -print0 | \
	  xargs -0 install -m 0644 -t $(R)/$(DIALUP_CONFDIR)
	find htdocs html lib sql -name CVS -prune -o -print | \
	  while read file; do \
	    if [ -d "$$file" ]; then \
	      install -d -m 0755 "$(R)/$(DIALUP_PREFIX)/$$file"; \
	    else \
	      install -m 0644 "$$file" "$(R)/$(DIALUP_PREFIX)/$$file"; \
	    fi; \
	  done
	sed -e 's#/usr/local/dialup_admin#$(DIALUP_PREFIX)#' \
	    -e 's#/usr/local/radiusd#$(prefix)#' \
	    -e 's#general_raddb_dir: %{general_radiusd_base_dir}/etc/raddb#general_raddb_dir: $(raddbdir)#' \
	    -e 's#general_clients_conf: /usr/local/etc/raddb/clients.conf#general_clients_conf: $(raddbdir)/clients.conf#' \
	    -e 's#%{general_base_dir}/conf#$(DIALUP_CONFDIR)#' \
	    -e 's#/usr/local/bin#$(bindir)#' \
	    conf/admin.conf > $(R)/$(DIALUP_CONFDIR)/admin.conf
	sed -e 's#../../README#$(DIALUP_DOCDIR)/README#' \
	    htdocs/help/help.php > $(R)/$(DIALUP_PREFIX)/htdocs/help/help.php
	for binfile in backup_radacct clean_radacct clearsession log_badlogins monthly_tot_stats showmodem snmpfinger sqlrelay_query tot_stats truncate_radacct; do \
	  sed -e 's#/usr/local/bin/#${bindir}#' \
	      -e 's#/usr/local/dialup_admin/conf/#$(DIALUP_CONFDIR)/#' \
	      bin/$$binfile > $(R)/$(DIALUP_PREFIX)/bin/$$binfile ; \
	  chmod 0755 $(R)/$(DIALUP_PREFIX)/bin/$$binfile; \
	done
	sed -e 's#/usr/local/dialup_admin#$(DIALUP_PREFIX)#' \
	    bin/dialup_admin.cron > $(R)/$(DIALUP_PREFIX)/bin/dialup_admin.cron

.PHONY: all install
