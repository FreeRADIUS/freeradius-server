#!/usr/bin/env perl
######################################################################
#
#  Copyright (C) 2021 Network RADIUS SAS (legal@networkradius.com)
#
#  $Id$
#
######################################################################

use strict;
use warnings;
use Data::Dumper;
use File::Basename;

my %id2name;
my %name2id;
my %dir2id;

my %section_id2name;
my %section_name2id;


my $status = 0;
my $max_id = 1;

our ($opt_a, $opt_x);
use Getopt::Std;
getopts('ax');
my $debug = (defined $opt_x);
my $assign = (defined $opt_a);
my %unassigned;

sub process {
    my $file = shift;
    my $FILE;

    # normalize it
    $file =~ s,//,/,g;

    #
    #  Remove the filename to get the directory.
    #
    my $dir = $file;
    $dir =~ s,/[^/]+$,,;

    my $name = $file;

    #
    #  The name of this thing is "server" for libfreeradius-server.mk,
    #  or "rlm_sql" for rlm_sql.mk
    #
    if ($name =~ /libfreeradius/) {
	$name =~ s,.*/,,;
	$name =~ s/libfreeradius-//;
	$name =~ s/\.mk//;

    } elsif ($name =~ /all.mk/) {
	$name =~ s,/all.mk.*$,,;
	$name =~ s,.*/,,;

    } elsif ($name =~ /rlm_[\w_]+.mk/) {
	$name =~ s,.*/,,;
	$name =~ s/\.mk//;

	#
	#  These should arguably be in subdirectories, as with most of
	#  the rest of the code.
	#
	next if ($name =~ /rlm_radius_/);

    } else {
	die "$name is not handled\n";
    }

    #
    #  Prefer ".in" files, so that we edit the ones in source control.
    #
    if (open($FILE, "<$file.in")) {
	$file .= ".in";

    } else {
	open($FILE, "<", $file) or die "Failed to open $file: $!\n";
    }

    my $line = 0;
    my $log_id;

    print "$file\n" if $debug;

    while (<$FILE>) {
	#
	#  if this Makefile is loading other ones, then ignore it.
	#
	if (/SUBMAKEFILES/) {
	    close $FILE;
	    return;
	}

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

	    if (defined $log_id) {
		print STDERR "LOG_ID_LIB is defined twice in $file\n";
		$status = 1;
		last;
	    }

	    $id2name{$id} = $name;
	    $name2id{$name} = $id;
	    $log_id = $id;

	    if (defined $dir2id{$dir}) {
		print STDERR "LOG_ID_LIB is defined two different ways in $dir\n";
		$status = 1;
		last;
	    }

	    print "\tLOG_ID_LIB=$id with name $name\n" if $debug;

	    $dir2id{$dir} = $id;

	    $max_id = $id + 1 if ($id >= $max_id);
	    next;
	}

	if (/DEFINE_LOG_ID_SECTION/) {
	    my @fields = split /,/;

	    my $section = $fields[1];
	    $section =~ s/\s+//g;

	    my $id = $fields[2];
	    $id =~ s/\s+//g;

	    #
	    #  There wasn't a LOG_ID_LIB defined in this file.
	    #  Perhaps it was defined in a parent directory?
	    #
	    if (! defined $log_id) {
		my $parent = $dir;

		$parent =~ s,/[^/]+$,,;

		while ($parent !~ m,src$,) {
		    $parent =~ s,/[^/]+$,,;

		    if (defined $dir2id{$parent}) {
			$log_id = $dir2id{$parent};
			last;
		    }
		}

		# No LOG_ID_LIB defined, we're done.
		if (! defined $log_id) {
		    print STDERR "LOG_ID_LIB is not defined in $file\n";
		    $status = 1;
		    last;
		}
	    }

	    #
	    #  Check for conflicting definitions, is the ID associated with a name?
	    #
	    if (defined $section_id2name{$log_id}{$id}) {
		print STDERR "ID $id is defined in both $section_id2name{$log_id}{$id} and $section\n";
		$status = 1;
		last;
	    }

	    #
	    #  Check for conflicting definitions, is the name associated with an ID?
	    #
	    if (defined $section_name2id{$log_id}{$section}) {
		print STDERR "Library name $name defines '$section' as two different IDs $section_name2id{$log_id}{$section} and $id\n";
		$status = 1;
		last;
	    }

	    print "\t$section=$id\n" if ($debug > 0);

	    #
	    #  Define a hierarchical namespace.
	    #
	    $section_id2name{$log_id}{$id} = $section;
	    $section_name2id{$log_id}{$section} = $id;
	    next;
	}
    }

    if (!$assign) {
	close $FILE;
	return;
    }

    return if defined $log_id;

    print "\tassigned ID $max_id\n" if $debug;

    $unassigned{$file} = $max_id++;
}

foreach my $file (sort @ARGV) {
    next if $file !~ /\.mk/;
    next if $file =~ /tool/;

    process($file);
}

#exit $status if !$status;

#
#  Go through and assign IDs.
#
foreach my $file (sort keys %unassigned) {
    open my $FILE, ">>$file" or die "Failed opening $file: $!\n";
    print $FILE "LOG_ID_LIB\t= $unassigned{$file}\n";
    close $FILE;
}

exit $status;
