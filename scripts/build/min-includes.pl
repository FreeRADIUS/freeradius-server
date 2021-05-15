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
#  Run as: ./min-includes.pl `find . -name "*.c" -print`
#		prints out duplicate includes from files.
#
#	   ./min-includes.pl +n `find . -name "*.c" -print`
#		removes the duplicate includes from each file.
#		Remember to check that it still builds!
#
#  It has to be run from the TOP of the FreeRADIUS build tree,
#  i.e. where the top-level "configure" script is located.
#
######################################################################
#
#  FIXME: We don't handle include files taken from the current
#  directory...
#
#  FIXME: we should take -I <path> from the command line.
#
######################################################################
#
#  Copyright (C) 2006 Alan DeKok <aland@freeradius.org>
#
#  $Id$
#
######################################################################

use strict;
use warnings;

my %processed;

my $any_dups = 0;
my $debug = 0;

my %refs;
my %include;
my %maps;
my %forward;
my %reverse;
my %duplicate;
my %delete_line;

#
#  Find the #include's for one file.
#
sub process {
    my $file = shift;

    return if ($processed{$file});

    $processed{$file}++;

    open(my $FILE, "<", $file) or die "Failed to open $file: $!\n";

    my $line = 0;
    while (<$FILE>) {
        $line++;

        next if (!/^\s*\#\s*include\s+/);

        if (/^\s*\#\s*include\s+"(.+?)"/) {
            $refs{$file}{$1} = $line;

            # FIXME: local header files?
            # src/foo/bar.c: #include "foo.h"
            #   src/foo/foo.h do stuff..

            $include{$1}++;
        } elsif (/^\s*\#\s*include\s+<(.+?)>/) {
            $refs{$file}{$1} = $line;
            $include{$1}++;
        }
    }

    close $FILE;
}

#
#  Where include files are located.
#
#  FIXME:
#
my @directories = ("src/lib", "src");
my $do_it = 0;

#
#  Horrid.
#
if ($ARGV[0] eq "+n") {
    shift;
    $do_it = 1;
}

#
#  Bootstrap the basic C files.
#
foreach my $file (@ARGV) {
    process($file);
}


#
#  Process the include files referenced from the C files, to find out
#  what they include Note that we create a temporary array, rather
#  than walking over %include, because the process() function adds
#  entries to the %include hash.
#
my @work = sort keys %include;
foreach my $inc (@work) {

    foreach my $dir (@directories) {
        my $path = $dir . "/" . $inc;

        # normalize path
        $path =~ s:/.*?/\.\.::;
        $path =~ s:/.*?/\.\.::;

        next if (! -e $path);
        process($path);
        $forward{$inc} = $path;
        $reverse{$path} = $inc;

        # ignore system include files
        next if ((scalar keys %{$refs{$path}}) == 0);

        #  Remember that X includes Y, and push Y onto the list
        #  of files to scan.
        foreach my $inc2 (sort keys %{$refs{$path}}) {
            $maps{$inc}{$inc2} = 0;
            push @work, $inc2;
        }
    }
}

#
#  Process all of the forward refs, so that we have a complete
#  list of who's referencing who.
#
#  This doesn't find the shortest path from A to B, but it does
#  find one path.
#
foreach my $inc (sort keys %maps) {
    foreach my $inc2 (sort keys %{$maps{$inc}}) {
        foreach my $inc3 (sort keys %{$maps{$inc2}}) {
            # map is already there...
            next if (defined $maps{$inc}{$inc3});

            $maps{$inc}{$inc3} = $maps{$inc2}{$inc3} + 1;
        }
    }
}

#
#  Walk through the files again, looking for includes that are
#  unnecessary.  Note that we process header files, too.
#
foreach my $file (sort keys %refs) {

    # print out some debugging information.
    if ($debug > 0) {
        if (defined $reverse{$file}) {
            print $file, "\t(", $reverse{$file}, ")\n";
        } else {
            print $file, "\n";
        }
    }

    #  walk of the list of include's in this file
    foreach my $ref (sort keys %{$refs{$file}}) {

        #  walk over the include files we include, or included by
        #  files that we include.
        foreach my $inc2 (sort keys %{$maps{$ref}}) {
            #
            #  If we include X, and X includes Y, and we include
            #  Y ourselves *after* X, it's a definite dupe.
            #
            #  Note that this is a *guaranteed* duplicate.
            #
            #  Sometimes order matters, so we can't always delete X if
            #  we include Y after X, and Y includes X
            #
            if (defined $refs{$file}{$inc2} &&
                ($refs{$file}{$inc2} > $refs{$file}{$ref})) {
                $duplicate{$file}{$inc2} = $ref;

                # mark the line to be deleted.
                $delete_line{$file}{$refs{$file}{$inc2}}++;

                $any_dups++;
            }
        }
        print "\t", $ref, "\n" if ($debug > 0);
    }
}

if ($debug > 0) {
    print "------------------------------------\n";
}

#
#  Maybe just print out the dups so that a person can validate them.
#
if (!$do_it) {
    foreach my $file (sort keys %duplicate) {
        print $file, "\n";

        foreach my $inc (sort keys %{$duplicate{$file}}) {
            print "\t[", $refs{$file}{$inc}, "] ", $inc, " (", $duplicate{$file}{$inc}, " at ", $refs{$file}{$duplicate{$file}{$inc}}, ")\n";
        }
    }
} else {
    foreach my $file (sort keys %duplicate) {
        open(my $FILE, "<", $file) or die "Failed to open $file: $!\n";
        open(my $OUTPUT, ">", "$file.tmp") or die "Failed to create $file.tmp: $!\n";

        my $line = 0;
        while (<$FILE>) {
            $line++;

            # supposed to delete this line, don't print it to the output.
            next if (defined $delete_line{$file}{$line});

            print $OUTPUT $_;
        }

        close $OUTPUT;
        close $FILE;

        rename "$file.tmp", $file;
    }

}

#  If we succeeded in re-writing the files, it's OK.
exit 0 if ($do_it);

#  If there are no duplicates, then we're OK.
exit 0 if (!$any_dups);

#  Else there are duplicates, complain.
exit 1
