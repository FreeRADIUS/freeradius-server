#!/usr/bin/env perl
#
#  Convert old-style "clients" file to new "clients.conf" format.
#
#  Usage: clients.pl clients new-clients.conf
#         The "new-clients.conf" will be over-written.
#
#
#	$Id$
#
if ($#ARGV != 1) {
    print "Usage: clients.pl clients new-clients.conf\n";
    print "       The \"new-clients.conf\" will be created if it does not exist.\n";
    print "       If it does exist, it will be over-written.";
    exit(1);
}

$old = shift;
$new = shift;

open OLD, "< $old"or die "Failed to open $old: $!\n";
open NEW, "> $new" or die "Failed to open $new: $!\n";

while (<OLD>) {
    next if (/^\s*\#/);

    split;

    print NEW "client $_[0] {\n";
    print NEW "\tsecret = $_[1]\n";
    print NEW "}\n";
}
