#
# Makefile
#
# Version:      $Id$
#

include ../Make.inc

#
#  The list of files to install.
#
FILES = acct_users attrs attrs.access_reject attrs.accounting_response	\
	attrs.pre-proxy clients.conf dictionary templates.conf	\
	experimental.conf hints huntgroups ldap.attrmap			\
	policy.txt preproxy_users proxy.conf radiusd.conf trigger.conf	\
	users	policy.conf attrs.access_challenge

DEFAULT_SITES = default inner-tunnel
ifneq "${OPENSSL_INCLUDE}" ""
DEFAULT_SITES += tls
endif

DEFAULT_MODULES = acct_unique always attr_filter attr_rewrite chap checkval \
		counter cui detail detail.log digest dynamic_clients eap \
		echo exec expiration expr files inner-eap linelog logintime \
		mschap ntlm_auth pap passwd preprocess radutmp realm \
		replicate soh sradutmp unix utf8 wimax

#
#	This target is here for local debugging
#
all: sites-enabled mods-enabled

.PHONY: sites-enabled
sites-enabled:
	@if [ ! -d sites-enabled ]; then \
		mkdir sites-enabled; \
	fi
	@cd sites-enabled/; \
	 for x in $(DEFAULT_SITES); do \
	    if [ ! -f $$x ]; then \
		ln -s ../sites-available/$$x; \
	    fi; \
	done

.PHONY: mods-enabled
mods-enabled:
	@if [ ! -d mods-enabled ]; then \
		mkdir mods-enabled; \
	fi
	@cd mods-enabled/; \
	 for x in $(DEFAULT_MODULES); do \
	    if [ ! -f $$x ]; then \
		ln -s ../mods-available/$$x; \
	    fi; \
	done

install:
	$(INSTALL) -d -m 750	$(R)$(raddbdir)
	$(INSTALL) -d -m 750	$(R)$(raddbdir)/sites-available
	$(INSTALL) -d -m 750	$(R)$(raddbdir)/sites-enabled
	$(INSTALL) -d -m 750	$(R)$(raddbdir)/mods-available
	$(INSTALL) -d -m 750	$(R)$(raddbdir)/mods-enabled
	@echo "Creating/updating files in $(R)$(raddbdir)"; \
	for i in $(FILES) `find sites-available/ mods-available/ -type f -print | sed 's/.*~//;s/.*#.*//' `; do \
		[ ! -f $(R)$(raddbdir)/$$i ] && $(INSTALL) -m 640 $$i $(R)$(raddbdir)/$$i; \
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
	chmod 640 $(R)$(raddbdir)/clients.conf
	if [ ! -d $(R)$(raddbdir)/certs ]; then \
		$(INSTALL) -d -m 750	$(R)$(raddbdir)/certs; \
		$(INSTALL) -m 750 certs/bootstrap $(R)$(raddbdir)/certs; \
		for i in Makefile README xpextensions ca.cnf server.cnf client.cnf; do \
			$(INSTALL) -m 640 certs/$$i $(R)$(raddbdir)/certs; \
		done; \
		$(MAKE) -C $(R)$(raddbdir)/certs; \
	fi
	if [ ! -d $(R)$(raddbdir)/sql ]; then \
		find sql -name CVS -prune -o -print | \
		  while read file; do \
		    if [ -d "$$file" ]; then \
		      $(INSTALL) -d -m 750 "$(R)$(raddbdir)/$$file"; \
		    else \
		      $(INSTALL) -m 640 "$$file" "$(R)$(raddbdir)/$$file"; \
		    fi; \
		  done; \
	fi
	@cd $(R)$(raddbdir)/sites-enabled/; \
	 for x in $(DEFAULT_SITES); do \
	    if [ ! -f $$x ]; then \
		ln -s ../sites-available/$$x; \
	    fi; \
	done
	@cd $(R)$(raddbdir)/mods-enabled/; \
	 for x in $(DEFAULT_MODULES); do \
	    if [ ! -f $$x ]; then \
		ln -s ../mods-available/$$x; \
	    fi; \
	done

clean:
	@rm -rf *~ $(addprefix sites-enabled/,$(DEFAULT_SITES)) \
		$(addprefix mods-enabled/,$(DEFAULT_MODULES))

triggers:
	@grep exec_trigger `find ../src -name "*.c" -print` | grep '"' | sed -e 's/.*,//' -e 's/ *"//' -e 's/");.*//'
