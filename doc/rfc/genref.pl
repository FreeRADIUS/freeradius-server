#!/usr/bin/perl
foreach $file (@ARGV) {
    open FILE, "<$file" || die "Error opening $file: $!\n";

    $ref = $file;
    $ref =~ s/\..*//g;

    while (<FILE>) {
	next if (!/^(\d+\.)+\s+([a-zA-Z]+-)+[a-zA-Z]/);

	chop;
	split;
	print $ref, "\t", $_[1], "\n";
    }

    close FILE;
}
