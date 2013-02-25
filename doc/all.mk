ifneq "$(docdir)" "no"
install: install.doc

clean: clean.doc

DOCFILES	:= $(filter-out %~ %/Makefile doc/00-OLD doc/examples doc/rfc doc/source,$(wildcard doc/* doc/rfc/*.txt doc/examples/*))
DOCINSTALL	:= $(patsubst doc/%,$(R)$(docdir)/%,$(DOCFILES))

DOCDIRS		:= $(R)/$(docdir)/ $(R)/$(docdir)/rfc/ $(R)/$(docdir)/examples/


#  Create the directories
$(DOCDIRS):
	@echo INSTALL $@
	@$(INSTALL) -d -m 755 $@

#  Files depend on directories (order only).
#  We don't care if the directories change.
$(DOCINSTALL): | $(DOCDIRS)

#  Wildcard installation rule
$(R)$(docdir)/%: doc/%
	@echo INSTALL $<
	@$(INSTALL) -m 644 $< $@

install.doc: $(DOCINSTALL)

.PHONY: clean.doc
clean.doc:
	@rm -f *~ rfc/*~ examples/*~

#
#  Deal with these later
#
DOCRST := $(wildcard *.rst)
%.html: %.rst
	@rst2html.py $^ > $@

.PHONY: html
html: $(DOCRST:.rst=.html)

endif
