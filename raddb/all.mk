#
#  The list of files to install.
#
LOCAL_FILES := acct_users clients.conf dictionary templates.conf \
		experimental.conf hints huntgroups \
		preproxy_users proxy.conf radiusd.conf trigger.conf \
		users README.rst

DEFAULT_SITES := default inner-tunnel
LOCAL_SITES   := $(addprefix raddb/sites-enabled/,$(DEFAULT_SITES))

DEFAULT_MODULES := always attr_filter attr_rewrite cache_eap chap checkval \
		counter cui detail detail.log digest dhcp dynamic_clients eap \
		echo exec expiration expr files inner-eap linelog logintime \
		mschap ntlm_auth pap passwd preprocess radutmp realm \
		replicate soh sradutmp unix utf8 wimax

LOCAL_MODULES   := $(addprefix raddb/mods-enabled/,$(DEFAULT_MODULES))

LOCAL_CERT_FILES := Makefile bootstrap README xpextensions \
		    ca.cnf server.cnf client.cnf

RADDB_DIRS := sites-available sites-enabled mods-available mods-enabled \
		filter policy.d certs

# Installed directories
INSTALL_RADDB_DIRS := $(R)$(raddbdir)/ $(addprefix $(R)$(raddbdir)/, \
			$(RADDB_DIRS) $(shell find raddb/sql -type d -print))

# Grab files from the various subdirectories
INSTALL_FILES := $(wildcard raddb/sites-available/* raddb/mods-available/*) \
		 $(LOCAL_SITES) $(LOCAL_MODULES) \
		 $(addprefix raddb/,$(LOCAL_FILES)) \
		 $(addprefix raddb/certs/,$(LOCAL_CERT_FILES)) \
		 $(wildcard raddb/policy.d/* raddb/filter/*) \
		 $(shell find raddb/sql -type f -print)


# Re-write local files to installed files, filtering out editor backups
INSTALL_RADDB := $(patsubst raddb/%,$(R)$(raddbdir)/%,\
			$(filter-out %~,$(INSTALL_FILES)))

all: build.raddb

build.raddb: $(LOCAL_SITES) $(LOCAL_MODULES)

clean: clean.raddb

install: install.raddb

# Local build rules
raddb/sites-enabled raddb/mods-enabled:
	@echo MKDIR $@
	@mkdir -p $@

# Set up the default modules for running in-source builds
raddb/mods-enabled/%: raddb/mods-available/% | raddb/mods-enabled
	@echo LN-S $@
	@cd $(dir $@) && ln -sf ../mods-available/$(notdir $@)

# Set up the default sites for running in-source builds
raddb/sites-enabled/%: raddb/sites-available/% | raddb/sites-enabled
	@echo LN-S $@
	@cd $(dir $@) && ln -sf ../sites-available/$(notdir $@)

# Installation rules for directories.  Note permissions are 750!
$(INSTALL_RADDB_DIRS):
	@echo INSTALL $(patsubst $(R)$(raddbdir)%,raddb%,$@)
	@$(INSTALL) -d -m 750 $@

#  The installed files have ORDER dependencies.  This means that they
#  will be installed if the target doesn't exist.  And they won't be
#  installed if the target already exists, even if it is out of date.
#
#  This dependency lets us install the server on top of an existing
#  system, hopefully without breaking anything.

# Installation rules for mods-enabled.  Note ORDER dependencies
$(R)$(raddbdir)/mods-enabled/%: | $(R)$(raddbdir)/mods-available/%
	@cd $(dir $@) && ln -sf ../mods-available/$(notdir $@)

# Installation rules for sites-enabled.  Note ORDER dependencies
$(R)$(raddbdir)/sites-enabled/%: | $(R)$(raddbdir)/sites-available/%
	@cd $(dir $@) && ln -sf ../mods-available/$(notdir $@)

# Installation rules for plain modules.
$(R)$(raddbdir)/%: | raddb/%
	@echo INSTALL $(patsubst $(R)$(raddbdir)/%,raddb/%,$@)
	@$(INSTALL) -m 640 $(patsubst $(R)$(raddbdir)/%,raddb/%,$@) $@

# Bootstrap is special
$(R)$(raddbdir)/certs/bootstrap: | raddb/certs/bootstrap
	@echo INSTALL $(patsubst $(R)$(raddbdir)/%,raddb/%,$@)
	@$(INSTALL) -m 750 $(patsubst $(R)$(raddbdir)/%,raddb/%,$@) $@

#  List directories before the file targets.
#  It's not clear why GNU Make doesn't deal well with this.
install.raddb: $(INSTALL_RADDB_DIRS) $(INSTALL_RADDB)

clean.raddb:
	@rm -f *~ $(addprefix raddb/sites-enabled/,$(DEFAULT_SITES)) \
		$(addprefix raddb/mods-enabled/,$(DEFAULT_MODULES))

#
#  A handy target to find out which triggers are where.
#  Should only be run by SNMP developers.
#
triggers:
	@grep exec_trigger `find src -name "*.c" -print` | grep '"' | sed -e 's/.*,//' -e 's/ *"//' -e 's/");.*//'
