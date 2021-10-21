#!/usr/bin/env perl

use strict;
use warnings;

my %refs;
my $ref;

#
#   Read in the references, and put into an associative array
#
open(my $FILE, '<' ,'refs') || die "Error opening refs: $!\n";
while (<$FILE>) {
    chop;
    @_ = split;

    $refs{$_[1]} = $_[0];
}
close $FILE;

#
#  now loop over the input RFC's.
#
foreach my $file (@ARGV) {
    open (my $FILE, '<', $file) || die "Error opening $file: $!\n";

    my $attribute = "zzzzz";

    # get the current reference
    $ref = $file;
    $ref =~ s/\..*//g;

    open(my $OUTPUT, '>', "$ref.html") || die "Error creating $ref.html: $!\n";

    #
    #  Print out the HTML header
    #
    print $OUTPUT <<EOF;
<!DOCTYPE html>
<html>
<head>
   <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
   <meta name="GENERATOR" content="Perl">
   <title>$ref.html</title>
</head>
<body>
<pre>

EOF

    #  loop over the input file
    while (<$FILE>) {
        # html-ize it
        s/&/&amp;/g;
        s/</&lt;/g;
        s/>/&gt;/g;

        if (/\[Page/) {
            print $OUTPUT "";
            next;
        }

        if (/^RFC \d+/) {
            print $OUTPUT "";
            next;
        }

        chop;

        #
        #  Attribute name header.
        #
        if (/^\d+\./ && !/\d$/) {
            @_ = split;

            if ($refs{$_[1]} && $refs{$_[1]} ne "") {
               $attribute = $_[1];

               print $OUTPUT "<a name=\"$attribute\"><h2>$_</h2></a>\n";

            } else {
               print $OUTPUT "<h2>$_</h2>\n";
               $attribute = "zzzz";
            }
            next;
        }

        #
        #  Mark these up special.
        #
        if ((/^   Description/) ||
            (/^   Type/) ||
            (/^   Length/) ||
            (/^   Value/)) {
            print $OUTPUT "<b>$_</b>\n";
            next;
        }

        # Make the current attribute name bold
        s/$attribute/<b>$attribute<\/b>/g;

        @_ = split;

        #
        #  Re-write the output with links to where-ever
        #
        foreach my $word (@_) {
            $word =~ s/[^-a-zA-Z]//g;

            if ($refs{$word} && $refs{$word} ne "") {
               if ($refs{$word} eq $ref) {
                   s/$word/<a href="#$word">$word<\/a>/g;
               } else {
                   s/$word/<a href="$refs{$word}.html#$word">$word<\/a>/g;
               }
            }
        }

        print $OUTPUT $_, "\n";

    }

    print $OUTPUT "</pre>\n";
    print $OUTPUT "</body>\n";
    print $OUTPUT "</html>\n";
    close $OUTPUT;
    close $FILE;
}

#
#  And finally, create the index.
#
open(my $OUTPUT, '>', "attributes.html") || die "Error creating attributes.html: $!\n";

#
#  Print out the HTML header
#
print $OUTPUT <<EOF;
<!DOCTYPE html>
<html>
<head>
   <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
   <meta name="GENERATOR" content="Perl">
   <title>$ref.html</title>
</head>
<body>

<h2>RADIUS Attribute List</h2>
EOF

my $letter = "@";

foreach my $key (sort keys %refs) {
    if (substr($key,0,1) ne $letter) {
        print $OUTPUT "</ul>\n" if $letter ne "@";
        $letter = substr($key,0,1);
        print $OUTPUT "\n<h3>$letter</h3>\n\n";
        print $OUTPUT "<ul>\n";
    }

    print $OUTPUT "<a href=\"$refs{$key}.html#$key\">$key</a><br>\n";
}

print $OUTPUT "</ul>\n";

print $OUTPUT "</body>\n";
print $OUTPUT "</html>\n";
close $OUTPUT;
