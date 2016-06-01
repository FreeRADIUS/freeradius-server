SUBMAKEFILES := rlm_winbind.mk

src/modules/rlm_winbind/rlm_winbind.mk: src/modules/rlm_winbind/rlm_winbind.mk.in src/modules/rlm_winbind/configure
	@echo CONFIGURE $(dir $<)
	@cd $(dir $<) && ./configure $(CONFIGURE_ARGS)
