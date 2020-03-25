#
#  The list of files to install.
#
LOCAL_FILES :=		clients.conf dictionary experimental.conf \
			radiusd.conf trigger.conf panic.gdb

DEFAULT_SITES :=	default inner-tunnel
LOCAL_SITES :=		$(addprefix raddb/sites-enabled/,$(DEFAULT_SITES))

DEFAULT_MODULES :=	always attr_filter cache_eap chap client \
			delay detail detail.log digest dhcpv4 eap \
			eap_inner echo escape exec expiration expr files linelog logintime \
			mschap ntlm_auth pap passwd radius radutmp \
			soh sradutmp stats unix unpack utf8

LOCAL_MODULES :=	$(addprefix raddb/mods-enabled/,$(DEFAULT_MODULES))

INSTALL_CERT_FILES :=	Makefile README.md xpextensions \
			ca.cnf server.cnf ocsp.cnf inner-server.cnf \
			client.cnf bootstrap

LOCAL_CERT_FILES :=	dh \
			rsa/ca.key \
			rsa/ca.pem \
			rsa/client.crt \
			rsa/client.key \
			rsa/client.pem \
			rsa/ocsp.key \
			rsa/ocsp.pem \
			rsa/server.crt \
			rsa/server.key \
			rsa/server.pem \
			ecc/ca.key \
			ecc/ca.pem \
			ecc/client.crt \
			ecc/client.key \
			ecc/client.pem \
			ecc/ocsp.key \
			ecc/ocsp.pem \
			ecc/server.crt \
			ecc/server.key \
			ecc/server.pem

GENERATED_CERT_FILES := $(addprefix ${top_srcdir}/raddb/certs/,$(LOCAL_CERT_FILES))

INSTALL_CERT_PRODUCTS := $(addprefix $(R)$(raddbdir)/certs/,$(INSTALL_CERT_FILES))

ifeq ("$(TEST_CERTS)","yes")
INSTALL_CERT_PRODUCTS += $(addprefix $(R)$(raddbdir)/certs/,$(LOCAL_CERT_FILES))
endif

LEGACY_LINKS :=		$(addprefix $(R)$(raddbdir)/,users)

BUILD_RADDB := $(strip $(foreach x,install clean,$(findstring $(x),$(MAKECMDGOALS))))
ifneq "$(BUILD_RADDB)" ""
RADDB_DIRS :=		certs mods-available mods-enabled policy.d template.d \
			sites-available sites-enabled \
			$(patsubst raddb/%,%,$(call FIND_DIRS,raddb/mods-config))

# Installed directories
INSTALL_RADDB_DIRS :=	$(R)$(raddbdir)/ $(addprefix $(R)$(raddbdir)/,$(RADDB_DIRS))

# Grab files from the various subdirectories
INSTALL_FILES := 	$(wildcard raddb/sites-available/* raddb/mods-available/*) \
			$(addprefix raddb/,$(LOCAL_FILES)) \
			$(addprefix raddb/certs/,$(INSTALL_CERT_FILES)) \
			$(call FIND_FILES,raddb/mods-config) \
			$(call FIND_FILES,raddb/policy.d) \
			$(call FIND_FILES,raddb/template.d)

# Re-write local files to installed files, filtering out editor backups
INSTALL_RADDB :=	$(patsubst raddb/%,$(R)$(raddbdir)/%,$(INSTALL_FILES))
endif

all: build.raddb

build.raddb: $(LOCAL_SITES) $(LOCAL_MODULES)

clean: clean.raddb

install: install.raddb

# Local build rules
raddb/sites-enabled raddb/mods-enabled:
	${Q}echo INSTALL $@
	${Q}$(INSTALL) -d -m 750 $@

# Set up the default modules for running in-source builds
raddb/mods-enabled/%: raddb/mods-available/% | raddb/mods-enabled
	${Q}echo "LN-S $@"
	${Q}cd $(dir $@) && ln -sf ../mods-available/$(notdir $@)

# Set up the default sites for running in-source builds
raddb/sites-enabled/%: raddb/sites-available/% | raddb/sites-enabled
	${Q}echo "LN-S $@"
	${Q}cd $(dir $@) && ln -sf ../sites-available/$(notdir $@)

ifneq "$(BUILD_RADDB)" ""
# Installation rules for directories.  Note permissions are 750!
$(INSTALL_RADDB_DIRS):
	${Q}echo INSTALL $(patsubst $(R)$(raddbdir)%,raddb%,$@)
	${Q}$(INSTALL) -d -m 750 $@

#  The installed files have ORDER dependencies.  This means that they
#  will be installed if the target doesn't exist.  And they won't be
#  installed if the target already exists, even if it is out of date.
#
#  This dependency lets us install the server on top of an existing
#  system, hopefully without breaking anything.

ifeq "$(wildcard $(R)$(raddbdir)/mods-available/)" ""
INSTALL_RADDB +=	$(patsubst raddb/%,$(R)$(raddbdir)/%,\
			$(filter-out %~,$(LOCAL_MODULES)))

# Installation rules for mods-enabled.  Note ORDER dependencies
$(R)$(raddbdir)/mods-enabled/%: | $(R)$(raddbdir)/mods-available/%
	${Q}cd $(dir $@) && ln -sf ../mods-available/$(notdir $@)
endif

ifeq "$(wildcard $(R)$(raddbdir)/sites-available/)" ""
INSTALL_RADDB +=	$(patsubst raddb/%,$(R)$(raddbdir)/%,\
			$(filter-out %~,$(LOCAL_SITES)))

# Installation rules for sites-enabled.  Note ORDER dependencies
$(R)$(raddbdir)/sites-enabled/%: | $(R)$(raddbdir)/sites-available/%
	${Q}cd $(dir $@) && ln -sf ../sites-available/$(notdir $@)
endif

# Installation rules for plain modules.
$(R)$(raddbdir)/%: | raddb/%
	${Q}echo INSTALL $(patsubst $(R)$(raddbdir)/%,raddb/%,$@)
	${Q}$(INSTALL) -m 640 $(patsubst $(R)$(raddbdir)/%,raddb/%,$@) $@

$(R)$(raddbdir)/users: $(R)$(modconfdir)/files/authorize
	${Q}[ -e $@ ] || echo LN-S $(patsubst $(R)$(raddbdir)/%,raddb/%,$@)
	${Q}[ -e $@ ] || ln -s $(patsubst $(R)$(raddbdir)/%,./%,$<) $@
endif

ifeq ("$(PACKAGE)","")
#
#  Always create the test certs for normal development.
#
build.raddb: $(GENERATED_CERT_FILES)


.PHONY: ${top_srcdir}/raddb/certs/rsa
${top_srcdir}/raddb/certs/rsa:
	@mkdir -p $@

.PHONY: ${top_srcdir}/raddb/certs/ecc
${top_srcdir}/raddb/certs/ecc:
	@mkdir -p $@

define BUILD_CERT
${1}/${2}/${3}.key: ${1}/${3}.cnf $$(dir $$@)
	$${Q}echo CERT-KEY ${1}
	$${Q}$$(MAKE) -C $${top_srcdir}/raddb/certs/ ${2}/${3}.key

${1}/${2}/${3}.csr: ${1}/${2}/${3}.key
	$${Q}echo CERT-CSR ${1}
	$${Q}$$(MAKE) -C $${top_srcdir}/raddb/certs/ ${2}/${3}.csr

${1}/${2}/${3}.pem: ${1}/${2}/${3}.key
	$${Q}echo CERT-PEM ${1}
	$${Q}$$(MAKE) -C $${top_srcdir}/raddb/certs/ ${2}/${3}.pem

${1}/${2}/${3}.crt: ${1}/${2}/${3}.csr ${1}/${2}/${3}.pem
	$${Q}echo CERT-CRT ${1}
	$${Q}$$(MAKE) -C $${top_srcdir}/raddb/certs/ ${2}/${3}.crt

ifneq "${3}" "ca"
#  client, server, and OCSP certs need the CA key.
${1}/${2}/${3}.crt: ${1}/${2}/ca.crt
endif

endef

#
#  Generate local certificate products when doing a non-package
#  (i.e. developer) build.
#
$(foreach dir,rsa ecc,$(foreach file,ca server client ocsp,$(eval $(call BUILD_CERT,${top_srcdir}/raddb/certs,${dir},${file}))))

.PHONY: ${top_srcdir}/raddb/certs/dh
${top_srcdir}/raddb/certs/dh:
	${Q}echo CERT-DH $@
	${Q}$(MAKE) -C ${top_srcdir}/raddb/certs/ $(notdir $@)

#
#  If we're not packaging the server, install the various
#  certificate files
#
INSTALL_RADDB += $(INSTALL_CERT_PRODUCTS)

else
#
#  If we are creating packages, then don't generate any local testing certs.
#
endif

#
#  Install the bootstrap script so that installations can run it
#  to generate test certs.
#
$(R)$(raddbdir)/certs/bootstrap: raddb/certs/bootstrap
	${Q}echo INSTALL $(patsubst $(R)$(raddbdir)/%,raddb/%,$@)
	${Q}$(INSTALL) -m 750 $(patsubst $(R)$(raddbdir)/%,raddb/%,$@) $@

#  List directories before the file targets.
#  It's not clear why GNU Make doesn't deal well with this.
install.raddb: | $(INSTALL_RADDB_DIRS) $(INSTALL_RADDB) $(LEGACY_LINKS)

clean.raddb:
	${Q}rm -f *~ $(addprefix raddb/sites-enabled/,$(DEFAULT_SITES)) \
		$(addprefix raddb/mods-enabled/,$(DEFAULT_MODULES))

#
#  A handy target to find out which triggers are where.
#  Should only be run by SNMP developers.
#
triggers:
	${Q}grep exec_trigger `find src -name "*.c" -print` | grep '"' | sed -e 's/.*,//' -e 's/ *"//' -e 's/");.*//'
