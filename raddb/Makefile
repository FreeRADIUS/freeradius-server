#
# Makefile
#
# Version:      $Id$
#

include ../Make.inc

#
#  The list of files to install.
#
FILES = acct_users attrs attrs.access_reject attrs.accounting_response \
	attrs.pre-proxy clients.conf dictionary	\
	eap.conf experimental.conf hints huntgroups ldap.attrmap	\
	mssql.conf naspasswd oraclesql.conf otp.conf postgresql.conf	\
	preproxy_users proxy.conf radiusd.conf radrelay.conf		\
	realms snmp.conf sql.conf sqlippool.conf users

all:

install:
	$(INSTALL) -d -m 750	$(R)$(raddbdir)
	@echo "Creating/updating files in $(R)$(raddbdir)"; \
	for i in $(FILES); do \
		[ ! -f $(R)$(raddbdir)/$$i ] && $(INSTALL) -m 640 $$i $(R)$(raddbdir); \
		if [ "`find $$i -newer $(R)$(raddbdir)/$$i`" ]; then \
			echo "** $(R)$(raddbdir)/$$i"; \
			nt=1; \
		fi; \
	done; \
	if [ "$$nt" ]; then \
		echo "**";\
		echo "** WARNING ** WARNING ** WARNING ** WARNING ** WARNING ** WARNING ** WARNING **";\
		echo "** WARNING ** WARNING ** WARNING ** WARNING ** WARNING ** WARNING ** WARNING **";\
		echo "**";\
		echo "** The sample configuration files in `pwd`";\
		echo "** are newer than those in $(R)$(raddbdir)";\
		echo "**";\
		echo "** Please investigate and manually copy (if appropriate) the files listed above.";\
		echo "**";\
		echo "** WARNING ** WARNING ** WARNING ** WARNING ** WARNING ** WARNING ** WARNING **";\
		echo "** WARNING ** WARNING ** WARNING ** WARNING ** WARNING ** WARNING ** WARNING **";\
	fi
	chmod 640 $(R)$(raddbdir)/naspasswd $(R)$(raddbdir)/clients.conf
	if [ ! -d $(R)$(raddbdir)/certs ]; then \
		$(INSTALL) -d -m 750	$(R)$(raddbdir)/certs; \
		for i in Makefile README xpextensions ca.cnf server.cnf client.cnf; do \
			$(INSTALL) -m 640 certs/$$i $(R)$(raddbdir)/certs; \
		done; \
	fi
	if [ ! -d $(R)$(raddbdir)/sql ]; then \
		mkdir $(R)$(raddbdir)/sql; \
		cp sql/* $(R)$(raddbdir)/sql 2>/dev/null || true; \
	fi

clean:
