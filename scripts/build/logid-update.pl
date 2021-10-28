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
my %files;
my %lines;
my %messages;

sub process {
    my $file = shift;
    my $text;
    my $id;
    my $line;

    open(my $FILE, "<", $file) or die "Failed to open $file: $!\n";
    open(my $OUTPUT, ">", "$file.tmp") or die "Failed to create $file.tmp: $!\n";

    $line = 0;
    while (<$FILE>) {
	$line++;

	#
	#  Change the various non-ID messages to ID-based messages
	#
	#  Allow "R" variants of the macros, and DEBUG(2,3,4)
	#
	#  Allow DEBUG(0, ...) to mean "please assign an ID".
	#
	if (! s/^(\s*R?(DEBUG|P?ERROR|INFO)[0-9]?)\((\s*\d+\s*,)?/${1}_ID\(\@/g) {
	    print $OUTPUT $_;
	    next;
	}

	#  Remember the number so that later regexes don't nuke it.
	$id = $3;

	#
	#  If there's no number, or it's 0, allocate one.
	#
	if (! defined $id || ($id eq '0,')) {
	    s/_ID\(\@/\($max_id, /;
	    $id = $max_id++;
	} else {
	    #
	    #  Ensure that the numbers are stable.
	    #
	    s/_ID\(\@/\($id/;
	    $id =~ s/,//;
	}

	#
	#  Try to get the actual message.
	#
	my $text = $_;
	$text =~ s/^[^"]+//;
	$text =~ s/",.*/"/;
	$text =~ s/"\).*/"/;
	chop $text;

	#
	#  Remember where everything is.
	#
	$files{$id} = $file;
	$lines{$id} = $line;
	$messages{$id} = $text;

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
