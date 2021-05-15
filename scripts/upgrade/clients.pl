#!/usr/bin/env perl
#
#  Convert old-style "clients" file to new "clients.conf" format.
#
#  Usage: clients.pl clients [naslist] new-clients.conf
#	The "new-clients.conf" will be created if it does not exist.
#	If it does exist, it will be over-written.
#
#
#	$Id$
#

use strict;
use warnings;

if (($#ARGV < 1) || ($#ARGV > 2)) {
    print "Usage: clients.pl clients [naslist] new-clients.conf\n";
    print "       The \"new-clients.conf\" will be created if it does not exist.\n";
    print "       If it does exist, it will be over-written.\n";
    exit(1);
}

my $naslist;
my %clients;

my $old = shift;
my $new = shift;

if ($new =~ /naslist/) {
    $naslist = $new;
    $new = shift;
}

open(my $OLD, "<", $old) or die "Failed to open $old: $!\n";

while (<$OLD>) {
    next if (/^\s*\#/);
    next if (/^\s*$/);

    @_ = split;

    $clients{$_[0]}{"secret"} = $_[1];
}
close $OLD;

if (defined $naslist) {
    open(my $OLD, "<", $naslist) or die "Failed to open $naslist: $!\n";

    while (<$OLD>) {
        next if (/^\s*\#/);
        next if (/^\s*$/);

        @_ = split;

        if (!defined $clients{$_[0]}) {
            print "WARNING! client $_[0] is defined in naslist, but not in clients!";
            next;
        }

        $clients{$_[0]}{"shortname"} = $_[1];
        $clients{$_[0]}{"nas_type"} = $_[2];
    }

    close $OLD;
}

open(my $NEW, ">", $new) or die "Failed to open $new: $!\n";
foreach my $client (keys %clients) {
    print $NEW "client $client {\n";
    print $NEW "\tsecret = ", $clients{$client}{"secret"}, "\n";
    if (defined $clients{$client}{"shortname"}) {
        print $NEW "\tshortname = ", $clients{$client}{"shortname"}, "\n";
        print $NEW "\tnas_type = ", $clients{$client}{"nas_type"}, "\n";
    }
    print $NEW "}\n";
    print $NEW "\n";
}
close $NEW;
