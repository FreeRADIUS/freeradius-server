install: install.radtest

.PHONY: install.radtest

install.radtest:
	@echo INSTALL radtest
	@$(INSTALL) -m 755 src/main/radtest $(R)$(bindir)