


all:
	$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

common: 
	@for mod in rlm_sql*; do \
		what=$(WHAT_TO_MAKE); \
		[ "$$what" = "all" ] && what="$(TARGET_LIBS)"; \
		echo "Making $$what in $$mod..."; \
		(cd $$mod && $(MAKE) $(MFLAGS) $$what) || exit 1;\
	done

