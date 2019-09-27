#
#  Check if we should build the documentation.
#
#  Running "shell" is expensive on OSX.  Building the documentation
#  requires running a bunch of shell commands, because we're too lazy
#  to fix that.  So, only run those shell scripts if we're going to
#  build the documentation.
#
WITH_DOC := $(strip $(foreach x,doc html pdf doxygen,$(findstring $(x),$(MAKECMDGOALS))))
ifneq "$(WITH_DOC)" ""

#
#  We're building a documentation target, but there's no "asciidoc".
#
ifeq "$(ASCIIDOCTOR)" ""
$(error asciidoc is required to build the documentation)
endif

#
#  We're building a documentation target, but there's no "pandoc".
#
ifeq "$(PANDOC)" ""
$(error pandoc is required to build the documentation)
endif

#
#  We're building a documentation target, but there's no "antora".
#  Which we ONLY need for "docsite"
#
ifeq "$(ANTORA)" ""
ifneq "$(findstring docsite,$(MAKECMDGOALS))" ""
$(error antora is required to build the documentation)
endif
endif

#
#  We're installing the documentation, but there's no "docdir".
#
ifeq "$(docdir)" "no"
ifneq "$(findstring install,$(WITH_DOC))" ""
$(error 'docdir' is required to do 'make install')
endif
endif

#
#	TODO: The 'pdf' target is broken. we should enable here soon.
#
all.doc: html docsite

install: install.doc install.doc.man

clean: clean.doc

#
#  Our "conf to asciidoc" stuff.
#
CONF_FILES := $(filter-out %~,$(wildcard raddb/*conf raddb/mods-available/* raddb/sites-available/* raddb/dictionary))
BASE_ADOC_FILES := $(wildcard doc/*.adoc doc/*/*.adoc doc/*/*/*.adoc) doc/raddb/mods-available/all_modules.adoc
AUTO_ADOC_FILES := $(patsubst raddb/%,doc/raddb/%.adoc,$(CONF_FILES))
ADOC_FILES	:= $(BASE_ADOC_FILES) $(AUTO_ADOC_FILES)
PDF_FILES := $(patsubst doc/%.adoc,doc/%.pdf,$(ADOC_FILES))
HTML_FILES := $(filter %html,$(patsubst doc/%.adoc,doc/%.html,$(ADOC_FILES)) \
              $(subst %home.adoc,index.html,$(ADOC_FILES)))

#
#	Our "conf to Doxygen" stuff.
#
DOXYGEN_DIR = doc/doxygen
DOXYGEN_HTML_DIR = $(DOXYGEN_DIR)/html/

#
#  There are a number of pre-built files in the doc/ directory.  Find those.
#
DOC_FILES	:= $(filter-out %~ %/all.mk %.gitignore doc/rfc/update.sh doc/developers/%,$(shell find doc -type f))

#
#  We sort the list of files, because the "find" command above will
#  output pre-build ADOC / HTML files that may be laying around.  We
#  don't want duplicate rules.  We do want to build and install the
#  ADOC / HTML files, even if they don't (or do ) already exist.
#
#  We remove the "doc/" prefix, because the documentation files are
#  installed into $(docdir)/foo, and not $(docdir)/doc/.
#
ALL_DOC_FILES	:= $(patsubst doc/%,%,$(sort $(DOC_FILES) $(ADOC_FILES) $(HTML_FILES)))

#
#  Install doc/FOO into $(R)/$(docdir)/FOO
#
$(foreach FILE,$(ALL_DOC_FILES),$(eval $(call ADD_INSTALL_RULE.file,doc/${FILE},$(R)/$(docdir)/${FILE})))

#
#  Have a "doc" install target for testing.
#
install.doc: $(addprefix $(R)/$(docdir)/,$(ALL_DOC_FILES))

#
#  For now, list each "man" page individually.  They are all generated from source
#  "adoc" files.  And "make" isn't smart enough to figure that out.
#
#  We install doc/man/foo.? into $(R)/$(mandir)/man?/foo.?
#
#  Because GNU Make sucks at string substitution, we have stupid rules to do that.
#
#  Not all of the "man" files have been converted to asciidoc, so we have a "install.doc.man"
#  rule here, instead of overloading the "install.man" rule.
#
MAN_FILES := doc/man/radclient.1 doc/man/radiusd.8
INSTALL_MAN_FILES := $(join $(patsubst .%,$(R)/$(mandir)/man%/,$(suffix $(MAN_FILES))),$(patsubst doc/man/%,%,$(MAN_FILES)))

$(foreach FILE,$(MAN_FILES),$(eval $(call ADD_INSTALL_RULE.file,${FILE},$(R)/$(mandir)/$(join $(patsubst .%,man%/,$(suffix ${FILE})),$(patsubst doc/man/%,%,${FILE})))))

install.doc.man: $(INSTALL_MAN_FILES)

.PHONY: clean.doc
clean.doc:
	${Q}rm -f doc/*~ doc/rfc/*~ doc/examples/*~ $(AUTO_ADOC_FILES) $(HTML_FILES) $(PDF_FILES) $(MAN_FILES)
	${Q}rm -rf $(DOXYGEN_HTML_DIR) $(BUILD_DIR)/site

#
#	Sanity checks
#
update-check.doc:
	${Q}echo "TEST-DOC UPDATE XLAT & RADDB DATABASE"
	${Q}./scripts/build/missing-xlat-doc.sh ${top_srcdir}/scripts/build/missing-xlat-doc.txt
	${Q}./scripts/build/missing-raddb-mod-conf.sh > ${top_srcdir}/scripts/build/missing-raddb-mod-conf.txt

check.doc:
	${Q}echo "TEST-DOC RADDB CHECK";                                          \
	check_xlatA="${top_srcdir}/scripts/build/missing-raddb-mod-conf.txt";    \
	check_xlatB="${BUILD_DIR}/tests/missing-raddb-mod-conf.txt";              \
	./scripts/build/missing-raddb-mod-conf.sh > $${check_xlatB};             \
	if ! diff $${check_xlatA} $${check_xlatB}; then                           \
		echo "FAILED: RADDB MISSING DOCUMENTATION: $$check_xlatA != $$check_xlatB"; \
		exit 1;                                                               \
	fi

.PHONY: test.doc
test.doc:
	${Q}echo TEST-DOC ALL
	${Q}${MAKE} all.doc 3>&1 2>&1 > ${BUILD_DIR}/doc_stderr.log
	${Q}if egrep -qi "(asciidoctor|pandoc).*(error|failed)" ${BUILD_DIR}/doc_stderr.log; then \
		${Q}echo "TEST-DOC ERROR"                                                           \
		cat ${BUILD_DIR}/doc_stderr.log;                                                    \
		exit 1;                                                                             \
	fi
	${Q}if egrep -qi '^warning:' ${BUILD_DIR}/doc_stderr.log; then \
		${Q}echo "TEST-DOC DOXYGEN ERROR"                       \
		cat ${BUILD_DIR}/doc_stderr.log;                        \
		exit 1;                                                 \
	fi
	${Q}echo TEST-DOC SANITY CHECK
	${Q}if ! ${MAKE} check.doc; then exit 1; fi

#
#  Project documentation generated by Doxygen
#
ifneq "$(DOXYGEN)" ""
ifneq "$(GRAPHVIZ_DOT)" ""
.PHONY: doxygen
doxygen:
	@echo DOXYGEN $(DOXYGEN_DIR)
	${Q}mkdir -p $(DOXYGEN_HTML_DIR)
	${Q}(cd $(DOXYGEN_DIR) && $(DOXYGEN))

#
#  If we do have doxygen, then add it to the "all documentation"
#  target.
#
all.doc: doxygen
endif
endif

#
#  antora rebuilds the entire documentation site on each run
#  so we need to pick a single file to compare dependency
#  timestamps against.
#
#  we use sitemap.xml as it'll be regenerated on every antora
#  run.
#
build/docsite/sitemap.xml: $(ADOC_FILES)
	@echo ANTORA site.yml
	${Q}$(ANTORA) site.yml

#
#  Markdown files get converted to asciidoc via pandoc.
#
#  Many documentation files are in markdown because it's a simpler
#  format to read/write than asciidoc.  But we want a consistent "look
#  and feel" for the documents, so we make all of them asciidoc.
#
doc/raddb/%.adoc: raddb/%.md
	@echo PANDOC $^
	${Q}mkdir -p $(dir $@)
	${Q}$(PANDOC) --filter=scripts/asciidoc/pandoc-filter -w asciidoc -o $@ $^

doc/%.adoc: doc/%.md
	@echo PANDOC $^
	${Q}mkdir -p $(dir $@)
	${Q}$(PANDOC) --filter=scripts/asciidoc/pandoc-filter -w asciidoc -o $@ $^
	${Q}perl -p -i -e 's,/\.adoc,/,' $@

#
#  Conf files get converted to Asciidoc via our own magic script.
#
doc/raddb/%.adoc: raddb/%
	@echo ADOC $^
	${Q}mkdir -p $(dir $@)
	${Q}perl -pi -e 's/^# ([^ \t])/#  $$1/;s/^([ \t]+)# ([^ \t])/$$1#  $$2/;s/[ \t]+$$//' $^
	${Q}./scripts/asciidoc/conf2adoc -t -a ${top_srcdir}/asciidoc -o $@ < $^

#
#  Filter out test modules, and ones we don't care about.
#
IGNORE_MODULES := $(patsubst %,src/modules/%/README.md,rlm_dict rlm_example rlm_securid rlm_sigtran rlm_test)
README_MODULES := $(filter-out $(IGNORE_MODULES), $(wildcard src/modules/rlm_*/README.md))
doc/raddb/mods-available/all_modules.adoc: $(README_MODULES)
	@echo ADOC mods-available/all_modules.adoc
	${Q}./scripts/asciidoc/mod_readme2adoc $(README_MODULES) > $@

#
#	Converting *.adoc to *.html
#
#	Note that we need to make the BASEDIR relative, so that it works for both
#	file:// links and http:// links.
#
DOC_BASEDIR = $(subst $() $(),,$(foreach x,$(subst /, ,$1),../))
DOC_UPDATED_LABEL = "FreeRADIUS ${RADIUSD_VERSION_STRING} - \#$(shell git rev-parse --short HEAD) - Last updated"

doc/%.html: doc/%.adoc
	@echo HTML $^
	$(eval BASEDIR := $(call DOC_BASEDIR,$(subst doc/,,$(dir $^))))
	$(eval BASEDIR := $(if $(BASEDIR),$(BASEDIR),./))
	${Q}$(ASCIIDOCTOR) $< -w                                         \
	                      -a toc="left"                              \
	                      -a docinfodir="$(BASEDIR)/templates"       \
	                      -a basedir="$(BASEDIR)"                    \
	                      -a docinfo="shared,private"                \
	                      -a last-update-label=${DOC_UPDATED_LABEL}  \
	                      -a stylesdir="$(BASEDIR)/css"              \
	                      -a stylesheet="freeradius.css"             \
	                      -a favicon="$(BASEDIR)/images/favicon.png" \
	                      -a linkcss                                 \
	                      -b html5 -o $@ $<
	${Q}perl -p -i -e 's,\.adoc,\.html,g; s,/.html",/",g; s/\.md\.html/\.html/g' $@

doc/%.pdf: doc/%.adoc
	@echo PDF $^
	${Q}$(ASCIIDOCTOR) $< -b docbook5 -o - | \
		$(PANDOC) -f docbook -t latex --${PANDOC_ENGINE}-engine=xelatex \
			-V papersize=letter \
			-V images=yes \
			--template=./scripts/asciidoc/freeradius.template -o $@

doc/%.pdf: doc/%.md
	@echo PDF $^
	${Q}$(PANDOC) -f markdown -t latex --${PANDOC_ENGINE}-engine=xelatex \
		-V papersize=letter \
		--template=./scripts/asciidoc/freeradius.template -o $@ $<

doc/man/%.8: doc/man/%.adoc
	@echo MAN $^
	@${Q}${ASCIIDCOCTOR} asciidoctor -b manpage $<

doc/man/%.1: doc/man/%.adoc
	@echo MAN $^
	@${Q}${ASCIIDCOCTOR} asciidoctor -b manpage $<

.PHONY: asciidoc html pdf clean clean.doc
asciidoc: $(ADOC_FILES)
docsite: build/docsite/sitemap.xml
html: $(HTML_FILES)
pdf: $(PDF_FILES)

endif
