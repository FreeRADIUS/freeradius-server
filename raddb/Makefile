include ../Make.inc

#
#  The list of files to install.
#
FILES	= acct_users attrs clients clients.conf dictionary eap.conf \
	  experimental.conf hints huntgroups ldap.attrmap \
	  mssql.conf naslist naspasswd oraclesql.conf postgresql.conf \
	  preproxy_users proxy.conf radiusd.conf realms snmp.conf \
	  sql.conf sqlippool.conf users otp.conf otppasswd.sample

all:

install:
	$(INSTALL) -d -m 755	$(R)$(raddbdir)
	@echo "Creating/updating files in $(R)$(raddbdir)"; \
	for i in $(FILES); do \
		[ ! -f $(R)$(raddbdir)/$$i ] && $(INSTALL) -m 644 $$i $(R)$(raddbdir); \
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
	chmod 640 $(R)$(raddbdir)/naspasswd $(R)$(raddbdir)/clients $(R)$(raddbdir)/clients.conf
	if [ ! -d $(R)$(raddbdir)/certs ]; then \
		mkdir $(R)$(raddbdir)/certs; \
		mkdir $(R)$(raddbdir)/certs/demoCA; \
		cp certs/demoCA/* $(R)$(raddbdir)/certs/demoCA || true; \
		cp certs/* $(R)$(raddbdir)/certs 2>/dev/null || true; \
	fi

clean:

