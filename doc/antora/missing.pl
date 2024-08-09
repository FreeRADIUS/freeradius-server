#!/usr/bin/env perl

#
#  check for missing files in antora
#
#
#  ./missing.pl $(find . -name "nav.adoc" -print)
#



use strict;
use warnings;
use File::Basename;
use File::Find;

my %used;
my %exists;

while (@ARGV) {
    my $filename = shift;

    my $dir = dirname($filename);

    my @adoc = `find $dir -name "*.adoc" -print`;

    foreach my $name (@adoc) {
	next if $name =~ /nav.adoc/;
	next if $name =~ /partials/;
	chop $name;

	$exists{$name}++;
    }

    open(my $FILE, "<", $filename) or die "Failed to open $filename: $!\n";

    while (<$FILE>) {
	next if !/xref:(.*?).adoc/;
	
	$used{"$dir/pages/$1.adoc"}++

    }

    close $FILE;
}

foreach my $name (sort {$a cmp $b} keys %used) {
	next if -e $name;

	print "REF-NO-FILE: ", $name, "\n";
}

foreach my $name (sort {$a cmp $b} keys %exists) {
	next if defined $used{$name};

	print "FILE-NO-REF: ", $name, "\n";
}

