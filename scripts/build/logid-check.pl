#!/usr/bin/env perl
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

my %id2name;
my %name2id;

my %section_id2name;
my %section_name2id;

my $status = 0;

sub process {
    my $file = shift;
    my $name = $file;

    $name =~ s,.*/,,;
    $name =~ s/libfreeradius-//;
    $name =~ s/\.mk//;

    open(my $FILE, "<", $file) or die "Failed to open $file: $!\n";

    my $line = 0;
    while (<$FILE>) {
	next if ! /LOG_ID/;

	if (/^\s*LOG_ID_LIB/) {
	    my @fields = split /\s+/;
	    my $id = $fields[2];

	    if (defined $id2name{$id}) {
		print STDERR "ID $id is defined in both $id2name{$id} and $name\n";
		$status = 1;
		last;
	    }

	    if (defined $name2id{$name}) {
		print STDERR "Library '$name' is defined as two different IDs $name2id{$name} and $id\n";
		$status = 1;
		last;
	    }

	    $id2name{$id} = $name;
	    $name2id{$name} = $id;
	    next;
	}

	if (/DEFINE_LOG_ID_SECTION/) {
	    my @fields = split /,/;

	    my $section = $fields[1];
	    $section =~ s/\s+//g;

	    my $id = $fields[2];
	    $id =~ s/\s+//g;

	    if (defined $section_id2name{$name}{$id}) {
		print STDERR "ID $id is defined in both $section_id2name{$name}{$id} and $name\n";
		$status = 1;
		last;
	    }

	    if (defined $section_name2id{$name}{$section}) {
		print STDERR "Library name $name defines '$section' as two different IDs $section_name2id{$name}{$section} and $id\n";
		$status = 1;
		last;
	    }

	    $section_id2name{$name}{$id} = $section;
	    $section_name2id{$name}{$section} = $id;
	    next;
	}
    }

    close $FILE;
}

foreach my $file (@ARGV) {
    $file =~ s,//,/,g;

    process($file);
}

exit $status;
