SUBMAKEFILES := rlm_mschap.mk smbencrypt.mk

src/modules/rlm_mschap/rlm_mschap.mk: src/modules/rlm_mschap/rlm_mschap.mk.in src/modules/rlm_mschap/configure
	@ECHO CONFIGURE $(dir $<)
	@cd $(dir $<) && ./configure $(CONFIGURE_ARGS)
