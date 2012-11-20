install: install.radlast

.PHONY: install.radlast

install.radlast:
	@echo INSTALL radlast
	$(INSTALL) -m 755 src/main/radlast $(R)$(bindir)