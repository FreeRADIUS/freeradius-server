#
#  Check if we should build the documentation.
#
#  Running "shell" is expensive on OSX.  Building the documentation
#  requires running a bunch of shell commands, because we're too lazy
#  to fix that.  So, only run those shell scripts if we're going to
#  build the documentation.
#
WITH_DOC := $(strip $(foreach x,install doc html man pdf doxygen,$(findstring $(x),$(MAKECMDGOALS))))

#
#  Convert adoc to man, and then let "install.man" deal with things.
#  This means a bare "make install.man" after "configure" won't get the
#  right things, but oh well.
#
ADOC2MAN_FILES := $(filter-out %/index.adoc,$(wildcard doc/antora/modules/reference/pages/man/*.adoc))
$(BUILD_DIR)/make/man.mk: $(ADOC2MAN_FILES) | $(BUILD_DIR)/make
	@rm -f $@
	${Q}for x in $^; do \
		y=$$(grep :manvolnum: $$x | awk '{print $$2}'); \
		z=$$(basename $$x | sed 's/.adoc//'); \
		echo "AUTO_MAN_FILES += man/man$$y/$$z.$$y" >> $@; \
		echo "man/man$$y/$$z.$$y: $$x" >> $@; \
		printf "\t"'@echo AUTO-MAN $$(notdir $$@)'"\n" >> $@; \
		printf "\t"'@mkdir -p $$(dir $$@)'"\n" >> $@; \
		printf "\t"'@asciidoctor -b manpage $$< -o $$@'"\n" >> $@; \
		echo "" >> $@; \
	done

-include $(BUILD_DIR)/make/man.mk
ALL_INSTALL += $(AUTO_MAN_FILES)

#
#  Skip documentation if any of the necessary prerequisites are missing.
#
ifeq "$(ASCIIDOCTOR)" ""
WITH_DOC=
endif

ifeq "$(PANDOC)" ""
WITH_DOC=
endif

ifneq "$(findstring install,$(WITH_DOC))" ""
ifeq "$(docdir)" "no"
WITH_DOC=
endif
endif

ifneq "$(findstring docsite,$(WITH_DOC))" ""
ifeq "$(ANTORA)" ""
WITH_DOC=
endif
endif

#
#  If we still decide to build the documentation, then add in all of the documentation rules.
#
ifneq "$(WITH_DOC)" ""
#
#	TODO: The 'pdf' target is broken. we should enable here soon.
#
all.doc: html docsite

install: install.doc

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
#  There are a number of pre-built files in the doc/ directory.  Find
#  those in addition to the ones which are in git.
#
#  We skip symlinks, as we don't want to walk through the same files
#  many times.
#
#  We also prune the generated doxygen files, as there are too many of them
#  and it slows down the build.
#
BASE_DOC_FILES	:= $(filter-out doc/doxygen/html/%,$(shell find $$(find doc -maxdepth 1 '!' -type l) -type f))
DOC_FILES	:= $(filter-out %~ %/all.mk %.gitignore doc/rfc/update.sh doc/developers/%,$(BASE_DOC_FILES))

#
#  We sort the list of files, because the "find" command above will
#  output pre-build ADOC / HTML files that may be laying around.  We
#  don't want duplicate rules.  We do want to build and install the
#  ADOC / HTML files, even if they don't (or do ) already exist.
#
#  We remove the "doc/" prefix, because the documentation files are
#  installed into $(docdir)/foo, and not $(docdir)/doc/.
#
ALL_DOC_FILES	:= $(patsubst doc/%,%,$(sort $(DOC_FILES) $(ADOC_FILES)))

#
#  Install doc/FOO into $(R)$(docdir)/FOO
#
$(foreach FILE,$(ALL_DOC_FILES),$(eval $(call ADD_INSTALL_RULE.file,doc/${FILE},$(R)$(docdir)/${FILE})))

#
#  Have a "doc" install target for testing.
#
install.doc: $(addprefix $(R)$(docdir)/,$(ALL_DOC_FILES))

.PHONY: clean.doc
clean.doc:
	${Q}rm -f doc/*~ doc/rfc/*~ doc/examples/*~ $(AUTO_ADOC_FILES) $(HTML_FILES) $(PDF_FILES) $(MAN_FILES)
	${Q}rm -rf $(DOXYGEN_HTML_DIR) $(BUILD_DIR)/site

#
#	Sanity checks
#
update-check.doc:
	@echo "TEST-DOC UPDATE XLAT & RADDB DATABASE"
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
	@echo TEST-DOC ALL
	${Q}${MAKE} all.doc 3>&1 2>&1 > ${BUILD_DIR}/doc_stderr.log
	${Q}if egrep -qi "(asciidoctor|pandoc).*(error|failed)" ${BUILD_DIR}/doc_stderr.log; then \
		echo "TEST-DOC ERROR";                                                           \
		cat ${BUILD_DIR}/doc_stderr.log;                                                    \
		exit 1;                                                                             \
	fi
	${Q}if egrep -qi '^warning:' ${BUILD_DIR}/doc_stderr.log; then \
		echo "TEST-DOC DOXYGEN ERROR";                       \
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
doxygen doc/doxygen/html/index.html:
	@echo DOXYGEN $(DOXYGEN_DIR)
	${Q}mkdir -p $(DOXYGEN_HTML_DIR)
	${Q}(cd $(DOXYGEN_DIR) && $(DOXYGEN))

#
#  Ensure that the installation directory gets created
#
$(eval $(call ADD_INSTALL_RULE.file,doc/doxygen/html/index.html,$(R)$(docdir)/doxygen/html/index.html))

#
#  Make sure that the base directory is build, and then just copy all
#  of the files over manually.
#
install.doxygen: $(R)$(docdir)/doxygen/html/index.html
	${Q}cp -RP doc/doxygen/html $(R)$(docdir)/doxygen/


#
#  Add the doxygen files to the install targt
#
install.doc: install.doxygen

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
	${Q}$(ANTORA) $(ANTORA_FLAGS) site.yml

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
IGNORE_MODULES := $(patsubst %,src/modules/%/README.md,rlm_dict rlm_securid rlm_sigtran rlm_test)
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
	${Q}${ASCIIDCOCTOR} asciidoctor -b manpage $<

doc/man/%.1: doc/man/%.adoc
	@echo MAN $^
	${Q}${ASCIIDCOCTOR} asciidoctor -b manpage $<

.PHONY: asciidoc html pdf clean clean.doc
asciidoc: $(ADOC_FILES)
docsite: build/docsite/sitemap.xml
html: $(HTML_FILES)
pdf: $(PDF_FILES)

doc: build/docsite/sitemap.xml $(HTML_FILES)

# end of WITH_DOC
endif
