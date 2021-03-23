#!/usr/bin/env perl
#
#  Cross-reference RFC attributes.
#
#  $Id$
#

use strict;
use warnings;

my %file;
my %name;

while (@ARGV) {
    my $filename = shift;

    open(my $FILE, "<", $filename) or die "Failed to open $filename: $!\n";

    my @output = ();

    my $begin_vendor = 0;
    my $blank = 0;
    my $vendor;
    my $tabsa;
    my $tabsn;

    while (<$FILE>) {

        #
        #  Clear out trailing whitespace
        #
        s/[ \t]+$//;

        #
        #  And CR's
        #
        s/\r//g;

        #
        #  Suppress multiple blank lines
        #
        if (/^\s+$/) {
            next if ($blank == 1);
            $blank = 1;
            next;
        }
        $blank = 0;

        #
        #  Remember the vendor
        #
        if (/^VENDOR\s+([\w-]+)\s+(\w+)(.*)/) {
            my $name=$1;
            my $len = length $name;
            my $tabs;
            if ($len < 32) {
                my $lenx = 32 - $len;
                $lenx += 7;                # round up
                $lenx /= 8;
                $lenx = int $lenx;
                $tabs = "\t" x $lenx;
            } else {
                $tabs = " ";
            }
            $vendor = $name;
            next;
        }

        #
        #  Remember if we did begin-vendor.
        #
        if (/^BEGIN-VENDOR\s+([\w-]+)/) {
            $begin_vendor = 1;
            if (!defined $vendor) {
                $vendor = $1;
            } elsif ($vendor ne $1) {
                # do something smart
            }

            next;
        }

        #
        #  Get attribute.
        #
        if (/^ATTRIBUTE\s+([\w-]+)\s+(\w+)\s+(\w+)(.*)/) {
            my $name=$1;
            my $len = length $name;
            my $tabs;
            if ($len < 40) {
                my $lenx = 40 - $len;
                $lenx += 7;                # round up
                $lenx /= 8;
                $lenx = int $lenx;
                $tabs = "\t" x $lenx;
                if ($tabs eq "") {
                    $tabs = " ";
                }
            } else {
                $tabs = " ";
            }

            my $value = $2;
            my $type = $3;
            my $stuff = $4;

            if ($begin_vendor == 0) {
                #
                #  FIXME: Catch and print conflicting attributes.
                #
                $file{$value} = $filename;
                $file{$value} =~ s/dictionary\.//;
                $name{$value} = $name . $tabs;
            }

            #
            #  See if it's old format, with the vendor at the end of
            #  the line.  If so, make it the new format.
            #
            if (defined $vendor && $stuff =~ /$vendor/) {
                if ($begin_vendor == 0) {
                    $begin_vendor = 1;
                }
                $stuff =~ s/$vendor//;
                $stuff =~ s/\s+$//;
            }

            next;
        }

        #
        #  Values.
        #
        if (/^VALUE\s+([\w-]+)\s+([\w\/,.-]+)\s+(\w+)(.*)/) {
            my $attr=$1;
            my $len = length $attr;
            if ($len < 32) {
                my $lenx = 32 - $len;
                $lenx += 7;                # round up
                $lenx /= 8;
                $lenx = int $lenx;
                $tabsa = "\t" x $lenx;
                if ($tabsa eq "") {
                    $tabsa = " ";
                    $len += 1;
                } else {
                    $len -= $len % 8;
                    $len += 8 * length $tabsa;
                }
            } else {
                $tabsa = " ";
                $len += 1;
            }

            #
            #  For the code below, we assume that the attribute lengths
            #
            my $lena;
            if ($len < 32) {
                $lena = 0;
            } else {
                $lena = $len - 32;
            }

            my $name = $2;
            $len = length $name;
            if ($len < 24) {
                my $lenx = 24 - $lena - $len;
                $lenx += 7;                # round up
                $lenx /= 8;
                $lenx = int $lenx;
                $tabsn = "\t" x $lenx;
                if ($tabsn eq "") {
                    $tabsn = " ";
                }
            } else {
                $tabsn = " ";
            }

            next;
        }

        #
        #  Remember if we did this.
        #
        if (/^END-VENDOR/) {
            $begin_vendor = 0;
        }

        #
        #  Everything else gets dumped out as-is.
        #
    }

    close $FILE;

}

#
#  Print out the attributes.
#
foreach my $attr (sort {$a <=> $b} keys %file) {
    print $name{$attr}, $attr, "\t", $file{$attr}, "\n";
}

