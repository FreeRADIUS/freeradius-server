#!/usr/bin/perl
#
#	$Id$
#
use warnings ;
use GDBM_File ;
use Fcntl ;
use Getopt::Long;

my $user = '';
my $divisor = 1;
my $match = '.*';

#
#  This should be fixed...
#
$filename = '';

#
#  Print out only one user,
#
#  Or specifiy printing in hours, minutes, or seconds (default)
#
GetOptions ('user=s'  => \$user,
	    'match=s' => \$match,
	    'file=s'  => \$filename,
	    'hours'   => sub { $divisor = 3600 },
	    'minutes' => sub { $divisor = 60 },
	    'seconds' => sub { $divisor = 1 } );

#
#  For now, this must be specified by hand.
#
if ($filename eq '') {
    die "You MUST specify the DB filename via: --file = <filename>\n";
}

#
#  Open the file.
#
my $db = tie(%hash, 'GDBM_File', $filename, O_RDONLY, 0666) or die "Cannot open$filename: $!\n";

#
#  If given one name, give the seconds
#
if ($user ne '') {
    print $user, "\t\t", int ( unpack('L',$hash{$user}) / $divisor), "\n";

    undef $db;
    untie %hash;
    exit 0;
}

#
#  This may be faster, but unordered.
#while (($key,$val) = each %hash) {
#
foreach $key (sort keys %hash) {
    #
    #  These are special.
    next if ($key eq "DEFAULT1");
    next if ($key eq "DEFAULT2");

    #
    #  Allow user names matching a regex.
    #
    next if ($key !~ /$match/);

    #
    #  Print out the names...
    print $key, "\t\t", int ( unpack('L',$hash{$key}) / $divisor), "\n";
}
undef $db;
untie %hash;
