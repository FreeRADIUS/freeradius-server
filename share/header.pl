#!/usr/bin/perl

$begin_vendor = 0;
$blank = 0;

while (@ARGV) {
    $filename = shift;

    open FILE, "<$filename" or die "Failed to open $filename: $!\n";

    @output = ();

    while (<FILE>) {
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
	    $name=$1;

	    $pname = $name;
	    $pname =~ tr/[a-z].-/[A-Z]__/;

	    $vvalue = "FR_VENDOR_$pname";
	    push @output, "#define $vvalue $2\n";
	    push @output, "#define ${vvalue}_H ($2 << 16)\n";
	    $vendor = $pname;
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
	    $name=$1;


	    $value = $2;
	    $type = $3;
	    $stuff = $4;

	    #
	    #  See if it's old format, with the vendor at the end of
	    #  the line.  If so, make it the new format.
	    #
	    if ($stuff =~ /$vendor/) {
		if ($begin_vendor == 0) {
		    $begin_vendor = 1;
		}
		$stuff =~ s/$vendor//;
		$stuff =~ s/\s+$//;
	    }


	    $pname = $name;
	    $pname =~ tr/[a-z].-/[A-Z]__/;

	    next if (defined $attr{$pname});

	    if ($vvalue) {
		push @output, "#define FR_ATTR_$pname (${vvalue}_H | $value)\n";
	    } else {
		push @output, "#define FR_ATTR_$pname ($value)\n";
	    }

	    $attr{$pname}++;

	    next;
	}

	#
	#  Values.
	#
	if (/^VALUE\s+([\w-]+)\s+([\w-\/,.]+)\s+(\w+)(.*)/) {
	    $attr=$1;
	    $name = $2;

	    $pattr = $attr;
	    $pattr =~ tr/[a-z].\/-/[A-Z]___/;

	    # FIXME: check if vendor name is in attribute name.
	    #        if not, add it in.

	    $pname = $name;
	    $pname =~ tr/[a-z].\/,-/[A-Z]____/;

	    push @output, "#define FR_VALUE_${pattr}_${pname} ($3)\n";
	    next;
	}

	#
	#  Remember if we did this.
	#
	if (/^END-VENDOR/) {
	    $begin_vendor = 0;
	    next;
	}

	if (/^\$INCLUDE ([a-z0-9.A-Z_]+)/) {
	    push @output, "#include <freeradius-devel/dict/${1}.h>\n";
	    next;
	}
    }

    close FILE;

    print "/* AUTO-GENERATED HEADER - DO NOT EDIT */\n";
    print @output;
}
