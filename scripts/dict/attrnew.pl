#!/usr/bin/env perl
#
#  Print out the ATTRIBUTE's which are defined only once on input,
#  and any VALUE's which are defined for those attributes.  It does NOT
#  print out unique VALUEs for multiple-defined attributes, though.
#
#  Usage: cat dictionary1 dictionary2 | ./attrnew.pl > unique
#
#  This is a bit of a hack.  In order to make it work, you've got to
#  add a "fake" attribute to the end of dictionary1, so that you know
#  which attributes belong to which dictionary...
#
#  $Id$
#

use strict;
use warnings;

my %attributes;
my %values;

my %dup;
my %first_ref;
my %name2val;

my $line = 0;
while (<>) {
    $line++;

    #
    #  Get attribute.
    #
    if (/^ATTRIBUTE\s+([\w-]+)\s+(\w+)\s+(\w+)(.*)/) {
        my $name = $1;
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

        if (defined $attributes{$index}) {
            $dup{$index}++;
        } else {
            $first_ref{$line} = $index;
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
    my $stuff = $4;

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
foreach my $line (sort {$a <=> $b} keys %first_ref) {
    my $attr_val = $first_ref{$line};

    next if (defined $dup{$attr_val});

    print "ATTRIBUTE ", $attributes{$attr_val}, "\n";

    next if (!defined $values{$attr_val});

    foreach my $value (sort {$a <=> $b} keys %{$values{$attr_val}}) {
        print "VALUE ", $values{$attr_val}{$value}, "\n";
    }

}
