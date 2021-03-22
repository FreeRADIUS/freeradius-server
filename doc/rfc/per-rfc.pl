#!/usr/bin/env perl

#
#   Read in the references, and put into an associative array
#
open FILE, "<refs" || die "Error opening refs: $!\n";
while (<FILE>) {
    chop;
    split;

    $refs{$_[1]} = $_[0];
    $defs{$_[0]}{$_[1]}++;
}
close FILE;

#
#  now loop over the input RFC's.
#
foreach $file (@ARGV) {
    $def=$file;
    $def =~ s/\.txt//;

    $attribute = "zzzzz";

    # get the current reference
    $ref = $file;
    $ref =~ s/\..*//g;
    $rfc = $ref;
    $ref = "attributes-$ref";

    open OUTPUT, ">$ref.html" || die "Error creating $ref.html: $!\n";

    #
    #  Print out the HTML header
    #
    print OUTPUT <<EOF;
<!DOCTYPE HTML PUBLIC "-//w3c//dtd html 4.0 transitional//en">
<html>
<head>
   <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
   <meta name="GENERATOR" content="Perl">
   <title>$rfc Index of Attributes</title>
</head>
<body>
<h1>$rfc Attribute List</h1>
EOF

  $letter = "@";

  foreach $key (sort keys %{$defs{$def}}) {
    if (substr($key,0,1) ne $letter) {
      print OUTPUT "</ul>\n" if ($letter ne "@");
      $letter = substr($key,0,1);
      print OUTPUT "\n<h3>$letter</h3>\n\n";
      print OUTPUT "<ul>\n";
    }

    print OUTPUT "<a href=\"$refs{$key}.html#$key\">$key</a><br />\n";

  }

  print OUTPUT "</ul>\n";
  print OUTPUT "</body>\n";
  close OUTPUT;
}
