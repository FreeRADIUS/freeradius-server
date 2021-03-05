ifneq "$(docdir)" "no"
install: install.doc

clean: clean.doc

DOCDIRS		:= $(patsubst doc/%,$(R)$(docdir)/%,$(filter-out doc/source%,$(shell find doc -type d)))
DOCFILES	:= $(filter-out %~ %/all.mk %.gitignore doc/rfc/update.sh doc/source/%,$(shell find doc -type f))
DOCINSTALL	:= $(patsubst doc/%,$(R)$(docdir)/%,$(DOCFILES))

#  Create the directories
$(DOCDIRS):
	@echo INSTALL $(patsubst $(R)$(docdir)/%,doc/%,$@)
	@$(INSTALL) -d -m 755 $@

#  Files depend on directories (order only).
#  We don't care if the directories change.
$(DOCINSTALL): | $(DOCDIRS)

#  Wildcard installation rule
$(R)$(docdir)/%: doc/% | $(dir $@)
	@echo INSTALL $<
	@$(INSTALL) -m 644 $< $@

install.doc: $(DOCINSTALL)

.PHONY: clean.doc
clean.doc:
	@rm -rf doc/*~ doc/rfc/*~ build/docsite

#
#  Deal with these later
#
DOCRST := $(wildcard *.rst)
%.html: %.rst
	@rst2html.py $^ > $@

.PHONY: html
html: $(DOCRST:.rst=.html)

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


docsite: build/docsite/sitemap.xml

endif
