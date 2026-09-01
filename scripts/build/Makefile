#
#  Generate the structure alignment reports for src/lib/util.
#
#  usage:
#	make -f scripts/build/Makefile
#	make -f scripts/build/Makefile clean
#	make -f scripts/build/Makefile src/lib/util/pair.md
#
#  Every header gets a report, as src/lib/util/<name>.md, and each one
#  is a target in its own right.  Changing one header rewrites one
#  report.  A header which declares no structures gets a short report
#  saying so, rather than no file, so that make has something to name.
#
#  The reports say how each structure is laid out, how much of its size
#  is padding, and whether reordering its fields would make it smaller.
#  They are produced by scripts/build/alignment.py, which reads the
#  headers but does not follow #include, so every type a structure uses
#  has to be named below.
#

#
#  The top of the tree, worked out from where this file is, so the
#  reports can be made from any directory.
#
TOP_ABS		:= $(patsubst %/scripts/build/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

#
#  Run from the top of the tree, which is the usual way, the paths below
#  come out relative.  That matters because a target has to be spelled
#  the same way on the command line as it is in this file, and
#
#	make -f scripts/build/Makefile src/lib/util/pair.md
#
#  is how anyone would ask for one report.  Run from anywhere else the
#  paths stay absolute, and a single report has to be named in full.
#
TOP		:= $(if $(filter $(CURDIR),$(TOP_ABS)),.,$(TOP_ABS))

#
#  "./src/lib/util" and "src/lib/util" are the same directory but not
#  the same target name.
#
here		= $(patsubst ./%,%,$(TOP)/$(1))

#
#  CFLAGS and CPPFLAGS, as configure left them.  struct_sizes has to be
#  built the same way as the rest of the tree, or the sizes it prints
#  are not the sizes the tree uses.
#
include $(TOP)/Make.inc

#
#  Make.inc names the compiler TARGET_CC.  It is not always the same as
#  cc, which is what CC defaults to, and the two disagree about how much
#  C23 they will accept without complaining.
#
COMPILER	:= $(if $(TARGET_CC),$(TARGET_CC),$(CC))

#
#  The same two variables src/lib/alloc/all.mk sets.  Repeated rather
#  than included, because all.mk is written for boilermake and does not
#  stand on its own.
#
ifneq "$(WITH_LIBALLOC)" "no"
FR_ALLOC_DEBUG	:= -DFR_ALLOC_DEBUG=1
TALLOC_CFLAGS	:= -DTALLOC_EXTENSIONS="'<freeradius-devel/alloc/talloc.h>'" $(FR_ALLOC_DEBUG)
endif

ALIGNMENT	:= $(call here,scripts/build/alignment.py)
SIZES		:= $(call here,build/bin/struct_sizes)
SIZES_SRC	:= $(call here,src/lib/alloc/struct_sizes.c)
UTIL		:= $(call here,src/lib/util)
HEADERS		:= $(sort $(wildcard $(UTIL)/*.h))
REPORTS		:= $(patsubst %.h,%.md,$(HEADERS))

#
#  Types which are incomplete in these headers.  TALLOC_CTX is void, and
#  the rest are structs declared but not defined.  Naming them lets the
#  headers parse.  They have no size, and the tool says so rather than
#  guessing if a field ever uses one by value.
#
OPAQUE		:= TALLOC_CTX \
		   DIR \
		   dl_loader_t \
		   fr_da_stack_t \
		   fr_dict_gctx_t \
		   fr_dict_protocol_t \
		   fr_dict_t \
		   fr_hash_table_t \
		   fr_timer_list_t

#
#  Values the tool cannot work out for itself.
#
#  WITH_VERIFY_PTR matches the build struct_sizes was compiled in, and
#  adds two fields to fr_pair_t.
#
#  FR_TLIST_ENTRY and FR_DLIST_ENTRY name a struct holding one list
#  entry, which is laid out the same as the entry itself.
#
#  The last two are #defines from headers other than the one being read:
#  FR_DICT_MAX_TLV_STACK is FR_DICT_TLV_NEST_MAX + 5 from dict.h, and
#  FR_EXT_ALIGNMENT is sizeof(uint64_t) from ext.h.
#
DEFINES		:= WITH_VERIFY_PTR \
		   'FR_TLIST_ENTRY(x)=fr_tlist_t' \
		   'FR_DLIST_ENTRY(x)=fr_dlist_t' \
		   FR_DICT_MAX_TLV_STACK=29 \
		   FR_EXT_ALIGNMENT=8

#
#  stats.h declares a field through a macro which takes no arguments,
#  which -D does not cover.
#
STATS_MACRO	:= 'STATS_HEADER_COMMON=fr_stats_link_t const *def'

ALIGNMENT_FLAGS	:= --sizes $(SIZES) \
		   $(addprefix --opaque=,$(OPAQUE)) \
		   $(addprefix -D,$(DEFINES)) \
		   --macro=$(STATS_MACRO)

#
#  The type mismatch scan.
#
#  vartypes.py reports variables whose declared type is not the type of the
#  value they were given, either by assignment or through a pointer argument.
#  The interesting ones are the aliases, where two names mean the same machine
#  type but promise different things about a negative return, as fr_slen_t and
#  ssize_t do.
#
VARTYPES	:= $(call here,scripts/build/vartypes.py)
VARTYPES_SRC	:= $(call here,src)

#
#  Override either of these on the command line:
#
#	make -f scripts/build/Makefile scan.vartypes VARTYPES_KIND=all
#
VARTYPES_OUT	?= $(call here,build/scan/vartypes.txt)
VARTYPES_KIND	?= alias

.PHONY: all reports clean help scan.vartypes scan.clean

all: reports

reports: $(REPORTS)

#
#  The scan reads every source file in the tree, so naming them all as
#  prerequisites would cost more to work out than the scan costs to run.  The
#  report is rewritten each time it is asked for.
#
#  vartypes.py writes its progress to stderr and the report to stdout, so
#  --quiet keeps the report clean and the summary below comes from the file
#  itself.  A failed run leaves no half written report behind.
#
#  --kind takes more than one value, so the "--" is needed to stop the
#  directory being read as another kind.
#
scan.vartypes:
	@mkdir -p $(dir $(VARTYPES_OUT))
	@$(VARTYPES) --quiet --kind $(VARTYPES_KIND) -- $(VARTYPES_SRC) > $(VARTYPES_OUT) || \
		{ rm -f $(VARTYPES_OUT); exit 1; }
	@echo "VARTYPES $(patsubst ./%,%,$(VARTYPES_OUT)) - $$(tail -1 $(VARTYPES_OUT))"

scan.clean:
	@rm -f $(VARTYPES_OUT)
	@echo "removed the scan reports"

#
#  One rule per header, so that changing a header rewrites only its own
#  report.  A header which declares no structures still gets a file
#  saying so, because a rule has to produce the file it names.
#
#  alignment.py writes nothing when it cannot measure a structure, so a
#  failed run leaves no half-right report behind.  The stale one is
#  removed as well, and make stops.
#
$(REPORTS): $(UTIL)/%.md: $(UTIL)/%.h $(ALIGNMENT) $(SIZES)
	@$(ALIGNMENT) $< --markdown $@ $(ALIGNMENT_FLAGS) || { rm -f $@; exit 1; }
	@echo "ALIGNMENT $(notdir $@)"

#
#  struct_sizes prints the size and alignment of every type the reports
#  need.  The tree's own build only makes it as part of "all", so it is
#  built here directly.  It uses nothing but sizeof and _Alignof, so it
#  needs no libraries.
#
$(SIZES): $(SIZES_SRC)
	@mkdir -p $(dir $@)
	@$(COMPILER) $(CPPFLAGS) $(CFLAGS) $(TALLOC_CFLAGS) $< -o $@
	@echo "CC $(notdir $@)"

clean:
	@rm -f $(REPORTS)
	@echo "removed the generated reports"

help:
	@echo "make -f scripts/build/Makefile               write src/lib/util/*.md"
	@echo "make -f scripts/build/Makefile clean         remove them again"
	@echo "make -f scripts/build/Makefile <name>.md     write one report"
	@echo
	@echo "One report per header in src/lib/util.  A report is rewritten when"
	@echo "its own header changes, or when alignment.py or struct_sizes does."
	@echo
	@echo "make -f scripts/build/Makefile scan.vartypes write $(patsubst ./%,%,$(VARTYPES_OUT))"
	@echo "make -f scripts/build/Makefile scan.clean    remove it again"
	@echo
	@echo "The scan reports variables whose declared type is not the type of"
	@echo "the value they were given.  Set VARTYPES_KIND to choose which"
	@echo "mismatches are reported: alias, signedness, narrowing, unrelated,"
	@echo "or all.  Set VARTYPES_OUT to write somewhere else."
