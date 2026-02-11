#
#  Check if we should build the documentation.
#
#  Running "shell" is expensive on OSX.  Building the documentation
#  requires running a bunch of shell commands, because we're too lazy
#  to fix that.  So, only run those shell scripts if we're going to
#  build the documentation.
#
WITH_DOC := $(strip $(foreach x,doc man doxygen,$(findstring $(x),$(MAKECMDGOALS))))

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
all.doc: docsite

install: install.doc

clean: clean.doc

DOC_RADDB	:= doc/antora/modules/reference/pages/raddb

#
#  Our "conf to asciidoc" stuff.
#
CONF_FILES := $(filter-out %~,$(wildcard raddb/*conf raddb/mods-available/* raddb/sites-available/* raddb/dictionary))
BASE_ADOC_FILES := $(wildcard doc/*.adoc doc/*/*.adoc doc/*/*/*.adoc) $(DOC_RADDB)/mods-available/all_modules.adoc

ADOC_FILES	:= $(BASE_ADOC_FILES) $(AUTO_ADOC_FILES)

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
	${Q}rm -f doc/*~ doc/rfc/*~ doc/examples/*~ $(AUTO_ADOC_FILES) $(MAN_FILES)
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
#  Add the doxygen files to the install target
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
#  Conf files get converted to Asciidoc via our own magic script.
#
$(DOC_RADDB)/%.adoc: raddb/%
	@echo ADOC $^
	${Q}mkdir -p $(dir $@)
	${Q}perl -pi -e 's/^# ([^ \t])/#  $$1/;s/^([ \t]+)# ([^ \t])/$$1#  $$2/;s/[ \t]+$$//' $^
	${Q}./scripts/asciidoc/conf2adoc -t -o $@ < $^

#
#  Simple rule for lazy people.
#
.PHONY: doc.raddb
doc.raddb: $(patsubst raddb/%,$(DOC_RADDB)/%.adoc,$(CONF_FILES))

#
#  We re-run antora if any of the input files change.  Antora can't do partial updates.
#
ifneq "$(ANTORA)" ""
build/docsite/sitemap.xml: $(ADOC_FILES)
	@echo ANTORA site.yml
	${Q}$(ANTORA) $(ANTORA_FLAGS) site.yml
else
.PHONY: build/docsite/sitemap.xml
build/docsite/sitemap.xml: $(ADOC_FILES)
	@echo No antora is installed
	false
endif


#
#  Only re-build the adoc files if specifically told to.
#
ifneq "$(findstring asciidoc,$(MAKECMDGOALS))" ""
#
#  Markdown files get converted to asciidoc via pandoc.
#
#  Many documentation files are in markdown because it's a simpler
#  format to read/write than asciidoc.  But we want a consistent "look
#  and feel" for the documents, so we make all of them asciidoc.
#
doc/%.adoc: doc/%.md
	@echo PANDOC $^
	${Q}mkdir -p $(dir $@)
	${Q}$(PANDOC) --filter=scripts/asciidoc/pandoc-filter -w asciidoc -o $@ $^
	${Q}perl -p -i -e 's,/\.adoc,/,' $@

#
#  Conf files get converted to Asciidoc via our own magic script.
#
$(DOC_RADDB)/%.adoc: raddb/%
	@echo ADOC $^
	${Q}mkdir -p $(dir $@)
	${Q}perl -pi -e 's/^# ([^ \t])/#  $$1/;s/^([ \t]+)# ([^ \t])/$$1#  $$2/;s/[ \t]+$$//' $^
	${Q}./scripts/asciidoc/conf2adoc -t -a ${top_srcdir}/asciidoc -o $@ < $^

#
#  Filter out test modules, and ones we don't care about.
#
IGNORE_MODULES := $(patsubst %,src/modules/%/README.md,rlm_dict rlm_securid rlm_sigtran rlm_test)
README_MODULES := $(filter-out $(IGNORE_MODULES), $(wildcard src/modules/rlm_*/README.md))
$(DOC_RADDB)/mods-available/all_modules.adoc: $(README_MODULES)
	@echo ADOC mods-available/all_modules.adoc
	${Q}./scripts/asciidoc/mod_readme2adoc $(README_MODULES) > $@
endif

doc/man/%.8: doc/man/%.adoc
	@echo MAN $^
	${Q}${ASCIIDCOCTOR} asciidoctor -b manpage $<

doc/man/%.1: doc/man/%.adoc
	@echo MAN $^
	${Q}${ASCIIDCOCTOR} asciidoctor -b manpage $<

.PHONY: asciidoc html clean clean.doc
asciidoc: $(ADOC_FILES)
docsite: build/docsite/sitemap.xml

#
#  OSX: pcregrep --color
#  Linux: grep --color='auto' -P -n
#

.PHONY: doc.ascii
doc.ascii:
	@pcregrep --color  '[\x80-\xFF]'  $$(find doc/antora -name "*.adoc" -print)

.PHONY: doc.fixascii
doc.fixascii:
	@perl -p -i -e "s,‘,',g;s,’,',g;s,–,-,g;s,—,-,g;s, , ,g;s:…:,:g;s,“,\",g;s,”,\",g;s,≤,<=,g;s,≥,>=,g;s,→,->,g" $$(find doc/antora -name "*.adoc" -print)


doc: build/docsite/sitemap.xml

# end of WITH_DOC
else
.PHONY: docsite
docsite:
	@echo 'make docsite' requires antora and asciidoctor.
	@echo Please read the output of 'configure' for more information.
	@false
endif
