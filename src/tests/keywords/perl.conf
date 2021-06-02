#
# Test code for use testing xlat functionality of rlm_perl
#

use strict;
use warnings;

use constant {
	L_AUTH         => 2,
	L_INFO         => 3,
	L_ERR          => 4,
	L_WARN         => 5,
	L_PROXY        => 6,
	L_ACCT         => 7,
	L_DBG          => 16,
	L_DBG_WARN     => 17,
	L_DBG_ERR      => 18,
	L_DBG_WARN_REQ => 19,
	L_DBG_ERR_REQ  => 20,
};

# Function to handle xlat
# Just do something simple with all parameters provided and return to the caller
sub xlat {

	radiusd::log(L_DBG, 'From xlat '.join(' ', @_));

	for (my $i = 0; $i <= $#_; $i++) {
		$_[$i] = join('|', split(',', $_[$i]));
	}

	return join('#', @_);
}

# Simple function that returns an integer
sub add {
	my $ret = 0;
	for (my $i = 0; $i <= $#_; $i++) {
		$ret += $_[$i];
	}
	return $ret;
}

# Function which expects the first argument to be an array ref
sub xlatarray{
	return join('|', @{ $_[0] });
}

# Take a scalar and return an array
sub xlatscalar2array {
	return split(/ /, $_[0]);
}

# Take an arbitary number of scalars and retun an array of array refs
sub xlatscalar2arrayref {
	my @array;
	for (my $i = 0; $i <= $#_; $i++) {
		my @subarray = split(/ /, $_[$i]);
		push (@array, \@subarray);
	}
	return @array;
}

# Function which receives an array and returns a hash
sub xlatarray2hash {
	my %hash;
	my $i = 1;
	foreach my $v (@{ $_[0] }) {
		$hash{'V'.$i} = $v;
		$i++;
	}
	return %hash;
}
