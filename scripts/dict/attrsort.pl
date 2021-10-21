#!/usr/bin/env perl
#
#  Sort the attributes in a dictionary, and put them into a canonical
#  form.  This will DESTROY any comments!
#
#  Usage: cat dictionary | ./attrsort.pl > new
#
#  This is a bit of a hack.  The main purpose is to be able to quickly
#  "diff" two dictionaries which have significant differences...
#
#  $Id$
#

use strict;
use warnings;

my %attributes;
my %values;
my %name2val;

while (<>) {
    #
    #  Get attribute.
    #
    if (/^ATTRIBUTE\s+([\w-]+)\s+(\w+)\s+(\w+)(.*)/) {
        my $name=$1;
        my $value = $2;
        my $type = $3;
        my $stuff = $4;

        $value =~ tr/[A-F]/[a-f]/; # normal form for hex
        $value =~ tr/X/x/;

        my $index;
        if ($value =~ /^0x/) {
            $index = hex $value;
        } else {
            $index = $value;
        }

        $attributes{$index} = "$name $value $type$stuff";
        $name2val{$name} = $index;
        next;
    }

    #
    #  Values.
    #
    if (/^VALUE\s+([\w-]+)\s+([\w\/,.-]+)\s+(\w+)(.*)/) {
        my $attr = $1;
        my $name = $2;
        my $value = $3;
        my $stuff = '';

        $value =~ tr/[A-F]/[a-f]/; # normal form for hex
        $value =~ tr/X/x/;

        my $index;
        if ($value =~ /^0x/) {
            $index = hex $value;
        } else {
            $index = $value;
        }

        if (!defined $name2val{$attr}) {
            print "# FIXME: FORWARD REF?\nVALUE $attr $name $value$stuff\n";
            next;
        }

        $values{$name2val{$attr}}{$index} = "$attr $name $value$stuff";
        next;
    }
}

#
#  Print out the attributes sorted by number.
#
foreach my $attr_val (sort {$a <=> $b} keys %attributes) {
    print "ATTRIBUTE ", $attributes{$attr_val}, "\n";
}

foreach my $value (sort {$a <=> $b} keys %values) {
    print $value, "\t", $attributes{$value}, "\n";
}

#
#  And again, this time printing out values.
#
foreach my $attr_val (sort {$a <=> $b} keys %attributes) {

    next if (!defined $values{$attr_val});

    foreach my $value (sort {$a <=> $b} keys %{$values{$attr_val}}) {
        print "VALUE ", $values{$attr_val}{$value}, "\n";
    }
}
