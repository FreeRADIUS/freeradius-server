#
#	Scripts to format dictionary files.
#
#	$Id$
#

#
#  This should only be run by hand, and then sanity checked by hand!
#
format: $(wildcard dictionary*)
	@for x in $(wildcard dictionary*) ; do \
		./format.pl $$x; \
	done
