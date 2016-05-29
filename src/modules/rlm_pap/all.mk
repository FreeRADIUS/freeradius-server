SUBMAKEFILES := rlm_pap.mk

src/modules/rlm_pap/rlm_pap.mk: src/modules/rlm_pap/rlm_pap.mk.in src/modules/rlm_pap/configure
	@echo CONFIGURE $(dir $<)
	@cd $(dir $<) && ./configure $(CONFIGURE_ARGS)
