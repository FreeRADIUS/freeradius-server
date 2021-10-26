#!/usr/bin/env perl
######################################################################
#
#  Copyright (C) 2021 Alan DeKok <aland@freeradius.org>
#
#  $Id$
#
#  Updates log IDs
#
#
######################################################################

use strict;
use warnings;
use Data::Dumper;

my $status = 0;
my $max_id;
my $regex;

sub process {
    my $file = shift;

    open(my $FILE, "<", $file) or die "Failed to open $file: $!\n";
    open(my $OUTPUT, ">", "$file.tmp") or die "Failed to create $file.tmp: $!\n";

    while (<$FILE>) {
	#
	#  Change the various non-ID messages to ID-based messages
	#
	#  Allow "R" variants of the macros, and DEBUG(2,3,4)
	#
	if (s/^(\s*R?(DEBUG|P?ERROR|INFO)[0-9]?)\((\s*0\s*,)?/${1}_ID\(\@/g) {
	    s/_ID\(\@/\($max_id, /;
	    $max_id++;
	}

	print $OUTPUT $_;
    }

    close $FILE;
    close $OUTPUT;

    rename "$file.tmp", $file;
}

sub read_max_id {
    my $file = shift;

    open(my $FILE, "<", $file) or die "Failed opening $file";
    while (<$FILE>) {
	next if /\s*#/;

	/(\d+)/;			# get digits

	$max_id = $1;
	last;
    }

    close $FILE;
}

sub write_max_id {
    my $file = shift;

    open(my $FILE, "<", $file) or die "Failed opening $file";
    open(my $OUTPUT, ">", "$file.tmp") or die "Failed opening $file.tmp";

    while (<$FILE>) {
	if (/\s*#/) {
	    print $OUTPUT $_;
	    next;
	}

	s/(\d+)/$max_id/;
	print $OUTPUT $_;
	last;
    }

    close $FILE;
    close $OUTPUT;

    rename "$file.tmp", $file;
}

read_max_id("scripts/build/max_id.txt");

foreach my $file (@ARGV) {
    $file =~ s,//,/,g;

    next if $file !~ /\.[ch]$/;

    process($file);
}

write_max_id("scripts/build/max_id.txt") if ($status == 0);

exit $status;
