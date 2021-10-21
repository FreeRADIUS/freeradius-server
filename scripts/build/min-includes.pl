#!/usr/bin/env perl
######################################################################
#
#  This script find duplicates of #include files, ignoring #ifdef's, etc.
#  from C source files, and (at your command) removes the duplicates.
#
#  It is meant to be run ONLY by FreeRADIUS developers, and has nothing
#  whatsoever to do with RADIUS, FreeRADIUS, or configuring a RADIUS server.
#
######################################################################
#
#  Run as: ./min-includes.pl $(find . -name "*.c" -print)
#		prints out duplicate includes from files.
#
#	   ./min-includes.pl -e $(find . -name "*.c" -print)
#		removes the duplicate includes from each file.
#		Remember to check that it still builds!
#
#  It has to be run from the TOP of the FreeRADIUS build tree,
#  i.e. where the top-level "configure" script is located.
#
######################################################################
#
#  FIXME: we should take -I <path> from the command line.
#
######################################################################
#
#  Copyright (C) 2021 Alan DeKok <aland@freeradius.org>
#
#  $Id$
#
######################################################################

use strict;
use warnings;
use Data::Dumper;

#
#  @todo - use Getopt::Long, and allow -I for includes,
#  which lets us search include directories.
#
our ($opt_d, $opt_e, $opt_i, $opt_r, $opt_x, $opt_X);
use Getopt::Std;
getopts('deirxX');
my $debug = 0;
my $edit = $opt_e;
my $dry_run = $opt_d;
my $edit_includes = $opt_i;
my $reorder = $opt_r;

$debug = 1 if defined $opt_x;
$debug = 2 if defined $opt_X;

if ($edit_includes && $reorder) {
    die "Can't edit and reorder at the same time";
}

my %processed;

my $any_dups = 0;

my %contents;
my %refs;
my %incs;
my %depth;
my %lines;
my %names;
my %requested;
my %reverse;
my %delete_line;
my %transitive;
my %worked;

my @work;

#
#  Find the #include's for one file.
#
#  Builds a hash keyed by filename.
#
#  The contents of the hash are the name of the file being included,
#  and the line number in the source file where that file was
#  included.
#
sub process {
    my $file = shift;
    my $dir = $file;

    $dir =~ s,/[^/]+$,/,;

    $file =~ s,//,/,g;			# canonicalize it

    $depth{$file} = 1;

    print "... $file\n" if $debug > 1;

    open(my $FILE, "<", $file) or die "Failed to open $file: $!\n";

    my $line = 0;
    while (<$FILE>) {
	my $inc;
	my $ref;
	my $content = $_;

        $line++;

	#
	#  Skip anything which isn't an include
	#
        next if (!/^\s*\#\s*include\s+/);

	#
	#  Include a header from this directory.
	#
        if (/^\s*\#\s*include\s+"(.+?)"/) {
	    $inc = $1;
	    $ref = "$dir$1";

        } elsif (/^\s*\#\s*include\s+<(.+?)>/) {
	    $inc = $1;
	    $ref = $1;

	    if ($ref =~ /freeradius/) {
		$ref = "src/$ref";
	    }

        } else {
	    die "Unhandled include at $file line $line\n";
	}

	$ref =~ s,//,/,g;			# canonicalize it

	next if defined $lines{$file}{$inc};	# ignore if we include the same file twice

	$contents{$file}{$line} = $content;		# remember the original content at that line

	$lines{$file}{$inc} = $line;		# FILE includes INC at line number
	$names{$file}{$inc} = $ref;		# FILE includes REF which maps to INCLUDE
	$refs{$file}{$ref} = $line;		# we don't muck with this one
	$incs{$file}{$ref} = $inc;		# we don't muck with this one

	$reverse{$ref}{$file} = $line;		# include REF is included by FILE at LINE
	$transitive{$file}{$ref} = 1;		# FILE points to REF directly

	$depth{$ref} = 1 if ! defined $depth{$ref};

	next if ($ref !~ /^src/);		# only process REF if it's in our source tree

	next if defined $worked{$ref};		# we've already processed the include file REF

	push @work, $ref;			# we need to process this include file REF

	$worked{$ref}++;

#	print "$file includes $ref via $inc at $line\n";
    }

    close $FILE;
}

#
#  Delete specific lines from the files.
#
sub process_edit {
    foreach my $file (keys %delete_line) {
	my $OUTPUT;

	print "$file\n" if $dry_run;

	open(my $FILE, "<", $file) or die "Failed to open $file: $!\n";

	if (!$dry_run) {
	    open($OUTPUT, ">", "$file.tmp") or die "Failed to create $file.tmp: $!\n";
	}

	my $line = 0;
	while (<$FILE>) {
	    $line++;

	    if ($dry_run && defined $delete_line{$file}{$line}) {
		print "\tdelete line $line already referenced in $delete_line{$file}{$line}\n";
	    }

	    # supposed to delete this line, don't print it to the output.
	    next if (defined $delete_line{$file}{$line});

	    if (!$dry_run) {
		print $OUTPUT $_;
	    }
	}

	if (!$dry_run) {
	    close $OUTPUT;
	}

	close $FILE;

	rename "$file.tmp", $file;
    }
}

#
#  Sort the includes by depth
#
#  Note that this doesn't quite work, because of things
#  like value.c, which does:
#
#	#define _VALUE_PRIVATE
#	#include <freeradius-devel/util/value.h>
#	#undef _VALUE_PRIVATE
#
#  So order matters.  We don't really parse the C files, so
#  we don't know that context matters here.
#
sub process_reorder {
    my %sorted;

    #
    #  Loop over the input files, swapping includes around the lines
    #
    foreach my $file (keys %requested) {
	my @lines = sort {$a <=> $b} keys %{$contents{$file}};

	foreach my $ref (sort {$depth{$a} <=> $depth{$b}} keys %{$refs{$file}}) {
	    $sorted{$file}{shift @lines} = $contents{$file}{$refs{$file}{$ref}};
	}
   }

    return;

    foreach my $file (keys %sorted) {
	my $OUTPUT;

	print "$file\n" if $dry_run;

	open(my $FILE, "<", $file) or die "Failed to open $file: $!\n";

	if (!$dry_run) {
	    open($OUTPUT, ">", "$file.tmp") or die "Failed to create $file.tmp: $!\n";
	}

	my $line = 0;
	while (<$FILE>) {
	    $line++;

	    #
	    #  If we have a matching line, print the sorted version
	    #  instead of the contents from the file.
	    #
	    if ($sorted{$file}{$line}) {
		print $OUTPUT $sorted{$file}{$line};
	    } else {
		print $OUTPUT $_;
	    }
	}

	if (!$dry_run) {
	    close $OUTPUT;
	}

	close $FILE;

	rename "$file.tmp", $file;
    }
}


#
#  Read and process the input C files.
#
foreach my $file (@ARGV) {
    $file =~ s,//,/,g;

    $requested{$file}++;
    process($file);
}
#
#  Processing the C files resulted in a set of include files to
#  process.  We need to read those in turn, in order to create a full
#  mapping of which file includes what.
#
foreach my $file (@work) {
    next if ! -e $file;

    process($file);
}

#
#  Get the correct depth for each file.
#
foreach my $file (keys %transitive) {
    my $mydepth = 1;

    foreach my $ref (keys %{$transitive{$file}}) {
	$mydepth = $depth{$ref} + 1 if ($depth{$ref} >= $mydepth);
    }

    $depth{$file} = $mydepth;
}

if ($debug > 1) {
    foreach my $file (sort {$depth{$a} <=> $depth{$b}} keys %depth) {
	print $depth{$file}, "\t", $file, "\n";
    }
}

#
#  We now process transitive references.  i.e. file FOO includes BAR,
#  but BAR also includes BAZ, BAD, etc.  We hoist all of that
#  information.
#
#  Use the "depth" array, and start from 1 (file includes nothing
#  else) to N (file is included -> included -> include N times.  This
#  lets us hoist things gradually
#
#  This loop is sort of O(N^3), but it does a lot of trimming as we
#  process the various files.
#
foreach my $file (sort {$depth{$a} <=> $depth{$b}} keys %depth) {
    next if ($depth{$file} == 1);

    #
    #  Loop over includes for $file.  If the include is not as deep as
    #  we are, then it MUST already have been processed, so we skip it.
    #
    foreach my $inc (keys %{$transitive{$file}}) {
	next if ($depth{$inc} < $depth{$file});

	#
	#  $file includes $inc, so loop over the things which are
	#  included by $inc.
	#
	#  If $file already references the second-include file, then
	#  don't do anything else.
	#
	#  Otherwise mark up $file as including the second-include file.
	#
	foreach my $inc2 (keys %{$transitive{$inc}}) {
	    next if (defined $transitive{$file}{$inc2});

	    $transitive{$file}{$inc2} = $transitive{$inc}{$inc2} + 1;
	}
  }
}

# Loop over each file we're checking
foreach my $file (sort keys %refs) {
    next if ! defined $requested{$file} && ! $edit_includes;

    print $file, "\n" if ! $edit;

    #  walk of the list of include's in this file
    foreach my $ref (sort {$refs{$file}{$a} <=> $refs{$file}{$b}} keys %{$refs{$file}}) {
	# @todo - sort includes in order of increasing depth, so that
	# we have a canonical order!

	#
	#  If we're not editing files, print out what we're going to
	#  do.
	#
	if (!$edit) {
	    if ($delete_line{$file}{$refs{$file}{$ref}}) {
		print "\t[", $refs{$file}{$ref}, "]\t!$incs{$file}{$ref} (from line $refs{$file}{$delete_line{$file}{$refs{$file}{$ref}}}, $delete_line{$file}{$refs{$file}{$ref}})\n";

	    } else {
		print "\t[", $refs{$file}{$ref}, "]\t$incs{$file}{$ref}\n";
	    }
	}

	#  Loop over the includes used by that file, seeing if they're included here.
	foreach my $inc (keys %{$transitive{$ref}}) {

	    # This file doesn't manually include the given reference
	    next if ! defined $refs{$file}{$inc};

	    # If the other include is earlier than this one, then
	    # it's already been handled.  So we ignore it.
	    next if ($refs{$file}{$inc} <= $refs{$file}{$ref});

	    $any_dups++;

	    $delete_line{$file}{$refs{$file}{$inc}} = $ref;

	    print "\t\talready includes $inc, duplicate at line $refs{$file}{$inc}\n" if $debug;
	}
    }
}

#
#  if we're not editing the files, exit with success when there's no duplicates.
#
if (!$edit && !$reorder) {
    exit ($any_dups != 0);
}

process_edit() if $edit;

process_reorder() if $reorder;

exit 0;
