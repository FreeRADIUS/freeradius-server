install: install.checkrad

.PHONY: install.checkrad

install.checkrad:
	@echo INSTALL checkrad
	@$(INSTALL) -m 755 src/main/checkrad $(R)$(sbindir)