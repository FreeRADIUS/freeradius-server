#!/usr/bin/env perl
#
#  Format the dictionaries according to a standard scheme.
#
#  Usage: ./format.pl dictionary.foo
#
#  We don't over-write the dictionaries in place, so that the process
#  can be double-checked by hand.
#
#  This is a bit of a hack.
#
#  FIXME: get lengths from variables, rather than hard-coding.
#
######################################################################
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#    Copyright (C) 2010 Network RADIUS SAS (legal@networkradius.com)
#
######################################################################
#
#  $Id$
#

use strict;
use warnings;

sub tabs {
        my $width = shift;
        my $name = shift;
        my $len;
        my $lenx;

        $len = length $name;

        return " " if ($len >= $width);

        $lenx = $width - $len;
        $lenx += 7;                # round up
        $lenx /= 8;
        $lenx = int $lenx;
        return "\t" x $lenx;
}

while (@ARGV) {
    my $filename = shift;

    open(my $FILE, "<", $filename) or die "Failed to open $filename: $!\n";

    my @output = ();

    my $year = 1900 + (localtime)[5];

    #
    #  Print a common header
    #
    push @output, "# -*- text -*-\n";
    push @output, "# Copyright (C) ", $year, " The FreeRADIUS Server project and contributors\n";
    push @output, "# This work is licensed under CC-BY version 4.0 https://creativecommons.org/licenses/by/4.0\n";

    #
    #  Separate the '$' from the "Id", so that git doesn't get excited over it.
    #
    push @output, "# Version \$", "Id: ", "\$\n";

    my $begin_vendor = 0;
    my $blank = 0;
    my $previous = "";
    my $vendor;
    my $tabsa;
    my $tabsn;

    while (<$FILE>) {
        #
        #  Suppress any existing header
        #
        next if (/^# -\*- text/);
        next if (/^# Copyright/);
        next if (/^# This work is licensed/);
        next if (/^# Version \$/);

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
            push @output, "\n";
            next;
        }
        $blank = 0;

        s/\s*$/\n/;

        #
        #  Suppress leading whitespace, so long as it's
        #  not followed by a comment..
        #
        s/^\s*([^#])/$1/;

        #
        #  Not an ATTRIBUTE? Suppress "previous" checks.
        #
        if (!/^ATTRIBUTE/) {
            $previous = "";
        }

        #
        #  Remember the protocol
        #
        if (/^PROTOCOL\s+([-\w]+)\s+(\w+)\s+(.*)/) {
            my $name = $1;
            my $format = $3;
            my $tabs = tabs(16, $name);

            $format = "\t$format" if ($format);

            push @output, "PROTOCOL\t$name$tabs$2$format\n";
            next;
        }

        #
        #  Remember the vendor
        #
        if (/^VENDOR\s+([-\w]+)\s+(\w+)(.*)/) {
            my $name = $1;
            my $tabs = tabs(32, $name);

            push @output, "VENDOR\t\t$name$tabs$2$3\n";
            $vendor = $name;
            next;
        }

        #
        #  Remember if we did BEGIN-VENDOR format=
        #
        if (/^BEGIN-VENDOR\s+([-\w]+)\s+(.+)/) {
	    my $tabs;

            $begin_vendor = 1;
            if (!defined $vendor) {
                $vendor = $1;
            } elsif ($vendor ne $1) {
                # do something smart
            }
	    if ($2) {
		$tabs = tabs(32,$vendor);
	    }

            push @output, "BEGIN-VENDOR\t$vendor$tabs$2\n";
            next;
        }

        #
        #  Or just a plain BEGIN-VENDOR
        #
        if (/^BEGIN-VENDOR\s+([-\w]+)/) {
            $begin_vendor = 1;
            if (!defined $vendor) {
                $vendor = $1;
            } elsif ($vendor ne $1) {
                # do something smart
            }

            push @output, "BEGIN-VENDOR\t$vendor\n";
            next;
        }

        #
        #  Get attribute.
        #
        if (/^ATTRIBUTE\s+([-\w]+)\s+([\w.]+)\s+(\w+)(.*)/) {
            my $name = $1;
            my $tabs = tabs(40, $name);

            my $value = $2;
            my $type = $3;
            my $refs = $4;

            #
            #  The numerical value doesn't start with ".".
            #
            #  If the current attribute is a child of the previous
            #  one, then just print out the child values.
            #
            #  Otherwise, remember this attribute as the new "previous"
	    #
	    #  @todo - these checks get things wrong, so they're commented
	    #  out until we have time to go fix them.
            #
#            if ($value !~ /^\./) {
#                if ($value =~ /^$previous(\..+)$/) {
#                    $value = $1;
#                } else {
#                    $previous = $value;
#                }
#            }

            push @output, "ATTRIBUTE\t$name$tabs$value\t$type$refs\n";
            next;
        }

        #
        #  Get DEFINE.
        #
        if (/^DEFINE\s+([-\w]+)\s+(\w+)(.*)/) {
            my $name = $1;
            my $tabs = tabs(40, $name);

            my $type = $2;
            my $stuff = $3;

            push @output, "DEFINE\t$name$tabs\t$type$stuff\n";
            next;
        }

        #
        #  Get MEMBER
        #
        if (/^MEMBER\s+([-\w]+)\s+(\w+)(.*)/) {
            my $name = $1;
            my $tabs = tabs(40, $name);

            my $type = $2;
            my $stuff = $3;

            push @output, "MEMBER\t\t$name$tabs$type$stuff\n";
            next;
        }

        #
        #  STRUCT name attr value
        #
        if (/^STRUCT\s+([-\w]+)\s+([-\w\/,.]+)\s+(\w+)(.*)/) {
            my $name = $1;
            my $key = $2;

            my $tabs = tabs(32, $name);
            my $tabsv = tabs(24, $key);

            push @output, "STRUCT\t$name$tabs$key$tabsv$3$4\n";
            next;
        }

        #
        #  Get ALIAS
        #
        if (/^ALIAS\s+([-\w]+)\s+(\w+)(.*)/) {
            my $name = $1;
            my $tabs = tabs(40, $name);

            my $ref = $2;
            my $stuff = $3;

            push @output, "ALIAS\t\t$name$tabs$ref$stuff\n";
            next;
        }

        #
        #  VALUE attr name value
        #
        if (/^VALUE\s+([-\w]+)\s+([-\w\/,.]+)\s+(\w+)(.*)/) {
            my $attr = $1;
            my $name = $2;

	    my $tabs = tabs(32, $attr);
	    my $tabsa = tabs(24, $name);

            push @output, "VALUE\t$attr$tabs$name$tabsa$3$4\n";
            next;
        }

        #
        #  Get flags.
        #
        if (/^FLAGS\s+([!\w-]+)\s+(.*)/) {
            my $name = $1;

            push @output, "FLAGS\t$name$2\n";
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
        push @output, $_;
    }

#
#  If we changed the format, print the end vendor, too.
#
    if ($begin_vendor) {
        push @output, "\nEND-VENDOR\t$vendor\n";
    }

    close $FILE;

    open($FILE, ">", $filename) or die "Failed to open $filename: $!\n";
    print $FILE @output;
    close $FILE;
}
