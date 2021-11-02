#!/usr/bin/env perl
######################################################################
#
#  Copyright (C) 2021 Alan DeKok <aland@freeradius.org>
#
#  $Id$
#
#  Updates log IDs
#
#  Log IDs are 64-bit numbers composed of:
#
#   4 bits of type (DEBUG, ERROR, INFO, WARN, etc.)
#   4 bits of log level (e.g. DEBUG vs DEBUG4)
#   4 bit of flags
#     1 bit of "is it for a request or not"
#     1 bit of "is it for a module"  (lets us easily do core vs module filters)
#     2 bits reserved
#
#  16 bits of library (libfreeradius-foo, or rlm_foo)
#   8 bits of "thing within a library"
#  16 bits of globally unique identifier
#
#  totalling 52 bits.  Which leaves 12 bits for future things.
#
#  Having the globally unique identifier means that it's easier
#  to track the various IDs.
#
#  We also need instance IDs, for things like network / worker threads,
#  and trunks, and connections.
#
#
######################################################################

use strict;
use warnings;
use Data::Dumper;

#
#  Ensure that we can read the output of Data::Dumper
#
$Data::Dumper::Purity = 1;

my $status = 0;
my $max_id;
my $regex;
my %files;
my %lines;
my %messages;
my %types;

sub process {
    my $file = shift;
    my $text;
    my $id;
    my $line;
    my $type;

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
	if (! s/^(\s*R?(DEBUG|P?ERROR|INFO|WARN)[0-9]?)\((\s*\d+\s*,)?/${1}_ID\(\@/g) {
	    print $OUTPUT $_;
	    next;
	}

	$type = $2;

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
	#  If we see the same ID twice, it's an error.
	#
	if (defined $files{$id}) {
	    die "ID $id is defined already in $files{$id}:$lines{$id}, and again in $file:$line";
	}

	#
	#  Remember where everything is.
	#
	$files{$id} = $file;
	$lines{$id} = $line;
	$messages{$id} = $text;

	$type =~ s/^P//;	# PERROR -> ERROR
	$types{$id} = $type;	# DEBUG, ERROR, INFO, WARN

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

exit 1 if ($status != 0);

write_max_id("scripts/build/max_id.txt");

exit $status;
