ifneq "$(docdir)" "no"

#
#  Running "shell" is expensive on OSX.  Building the documentation
#  requires running a bunch of shell commands, because we're too lazy
#  to fix that.  So, only run those shell scripts if we're going to
#  build the documentation.
#
BUILD_DOC := $(strip $(foreach x,doc html pdf adoc install clean,$(findstring $(x),$(MAKECMDGOALS))))
ifneq "$(BUILD_DOC)" ""

install: install.doc

clean: clean.doc

#
#  Our "conf to asciidoc" stuff.
#
CONF_FILES := $(filter-out %~,$(wildcard raddb/*conf raddb/mods-available/* raddb/sites-available/* raddb/dictionary))
ADOC_FILES := $(patsubst raddb/%,doc/raddb/%.adoc,$(CONF_FILES))
ADOC_FILES += $(patsubst raddb/%.md,doc/raddb/%.adoc,$(shell find raddb -name "*\.md" -print))
PDF_FILES := $(patsubst doc/raddb/%.adoc,doc/raddb/%.pdf,$(ADOC_FILES))
HTML_FILES := $(patsubst doc/raddb/%.adoc,doc/raddb/%.html,$(ADOC_FILES))

#
#  Older documentastion, likely needs updating.
#
DOCDIRS		:= $(patsubst doc/%,$(R)$(docdir)/%,$(filter-out doc/source%,$(shell find doc -type d)))
DOCFILES	:= $(filter-out %~ %/all.mk %.gitignore doc/rfc/update.sh doc/source/%,$(shell find doc -type f))
DOCINSTALL	:= $(patsubst doc/%,$(R)$(docdir)/%,$(DOCFILES))

#  Create the directories
$(DOCDIRS):
	${Q}echo INSTALL $(patsubst $(R)$(docdir)/%,doc/%,$@)
	${Q}$(INSTALL) -d -m 755 $@

#  Files depend on directories (order only).
#  We don't care if the directories change.
$(DOCINSTALL): | $(DOCDIRS)

#  Wildcard installation rule
$(R)$(docdir)/%: doc/%
	${Q}echo INSTALL $<
	${Q}$(INSTALL) -m 644 $< $@

install.doc: $(DOCINSTALL)

.PHONY: clean.doc
clean.doc:
	${Q}rm -f *~ rfc/*~ examples/*~ $(ADOC_FILES) $(HTML_FILES) $(PDF_FILES)

depends.doc:
ifeq ($(PANDOC),)
$(error You need to install 'pandoc')
endif
ifeq ($(ASCIIDOCTOR),)
$(error You need to install 'asciidoctor')
endif

#
#  Markdown files get converted to asciidoc via pandoc.
#
#  Many documentation files are in markdown because it's a simpler
#  format to read/write than asciidoc.  But we want a consistent "look
#  and feel" for the documents, so we make all of them asciidoc.
#
doc/raddb/%.adoc: raddb/%.md
	@echo PANDOC $^
	@mkdir -p $(dir $@)
	@$(PANDOC) --filter=scripts/asciidoc/pandoc-filter -w asciidoc -o $@ $^

#
#  Conf files get converted to Asciidoc via our own magic script.
#
doc/raddb/%.adoc: raddb/%
	@echo ADOC $^
	@mkdir -p $(dir $@)
	@perl -pi -e 's/^# ([^ \t])/#  $$1/;s/^([ \t]+)# ([^ \t])/$$1#  $$2/;s/[ \t]+$$//' $^
	@./scripts/asciidoc/conf2adoc -a ${top_srcdir}/asciidoc -o $@ < $^

doc/%.html: doc/%.adoc
	@echo HTML $^
	@$(ASCIIDOCTOR) $< -b html5 -o $@ $<

doc/%.pdf: doc/%.adoc
	@echo PDF $^
	@$(ASCIIDOCTOR) $< -b docbook5 -o - | \
		$(PANDOC) -f docbook -t latex --${PANDOC_ENGINE}-engine=xelatex \
			-V papersize=letter \
			-V images=yes \
			--template=./scripts/asciidoc/freeradius.template -o $@

doc/%.pdf: doc/%.md
	@echo PDF $^
	$(PANDOC) -f markdown -t latex --${PANDOC_ENGINE}-engine=xelatex \
		-V papersize=letter \
		--template=./scripts/asciidoc/freeradius.template -o $@ $<

.PHONY: depends.doc asciidoc html pdf clean clean.doc
asciidoc: $(ADOC_FILES)
html: $(HTML_FILES)
pdf: $(PDF_FILES)
endif
endif
