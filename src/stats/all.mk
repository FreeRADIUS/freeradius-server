RADICT := $(BUILD_DIR)/make/jlibtool --silent --mode=execute $(BUILD_DIR)/bin/local/radict -D share/dictionary

#
#  $(eval $(call DICT_STATS,radius,auth_serv,mib-2.radiusAuthServ,1.3.6.1.2.1.67.1.1.1.1))
#
#  We don't want the outputs to be updated if the build fails.  So we use an intermediate filename.
#  And we use ".cache", because that's ignored by the top level ".gitignore"
#
define DICT_STATS

#
#  Re-build the files if the dictionary changes.
#
#  Ensure that the protocol library is built before the statistics
#  library, as radict needs it.
#
#  Ensure that radict is built before the statistics library, as we
#  run radict to generate the output files.
#

#
#  Define the structures and declare the extern variables
#
src/stats/${1}/${2}_stats.h: share/dictionary/${1}/dictionary.stats $(BUILD_DIR)/lib/local/libfreeradius-${1}.la $(BUILD_DIR)/bin/local/radict$(E)
	@echo STATS ${1} ${2} - structs
	${Q}$(RADICT) -F stats.h -M ${4} -p ${1} ${3} > $$@.cache && mv $$@.cache $$@

#
#  define the "attr_foo" definitions for the dictionary autoload to populate
#
src/stats/${1}/${2}_da_def.c: share/dictionary/${1}/dictionary.stats $(BUILD_DIR)/lib/local/libfreeradius-${1}.la $(BUILD_DIR)/bin/local/radict$(E)
	@echo STATS ${1} ${2} - define variables
	${Q}$(RADICT) -F da_def -M ${4} -p ${1} ${3} > $$@.cache && mv $$@.cache $$@

#
#  define the autoload structures which point to the "attr_foo" defintions
#
src/stats/${1}/${2}_da_autoload.c: share/dictionary/${1}/dictionary.stats $(BUILD_DIR)/lib/local/libfreeradius-${1}.la $(BUILD_DIR)/bin/local/radict$(E)
	@echo STATS ${1} ${2} - autoload
	${Q}$(RADICT) -F attr_autoload -M ${4} -p ${1} ${3} > $$@.cache && mv $$@.cache $$@

#
#  define the linking structure between the statistics structure and the DAs.
#
src/stats/${1}/${2}_stats.c: share/dictionary/${1}/dictionary.stats $(BUILD_DIR)/lib/local/libfreeradius-${1}.la $(BUILD_DIR)/bin/local/radict$(E)
	@echo STATS ${1} ${2} - link
	${Q}$(RADICT) -F stats_link -M ${4} -p ${1} ${3} > $$@.cache && mv $$@.cache $$@

#
#  The output OBJ has to be rebuilt if any of the input files have changed.
#
$(BUILD_DIR)/objs/src/stats/${1}/base.${OBJ_EXT}: src/stats/${1}/${2}_stats.h src/stats/${1}/${2}_da_def.c src/stats/${1}/${2}_da_autoload.c src/stats/${1}/${2}_stats.c

endef

SUBMAKEFILES := $(wildcard ${top_srcdir}/src/stats/*/all.mk)
