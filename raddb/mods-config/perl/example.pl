
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#  Copyright 2002  The FreeRADIUS server project
#  Copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
#

#
# Example code for use with rlm_perl
#
# You can use every module that comes with your perl distribution!
#
# If you are using DBI and do some queries to DB, please be sure to
# use the CLONE function to initialize the DBI connection to DB.
#

use strict;
use warnings;

# use ...
use Data::Dumper;

#
# This the remapping of return values
#
use constant {
	RLM_MODULE_REJECT   => 0, # immediately reject the request
	RLM_MODULE_OK       => 2, # the module is OK, continue
	RLM_MODULE_HANDLED  => 3, # the module handled the request, so stop
	RLM_MODULE_INVALID  => 4, # the module considers the request invalid
	RLM_MODULE_DISALLOW => 5, # reject the request (user is locked out)
	RLM_MODULE_NOTFOUND => 6, # user not found
	RLM_MODULE_NOOP     => 7, # module succeeded without doing anything
	RLM_MODULE_UPDATED  => 8, # OK (pairs modified)
	RLM_MODULE_NUMCODES => 9  # How many return codes there are
};

# Same as src/include/log.h
use constant {
	L_AUTH         => 2,  # Authentication message
	L_INFO         => 3,  # Informational message
	L_ERR          => 4,  # Error message
	L_WARN         => 5,  # Warning
	L_PROXY        => 6,  # Proxy messages
	L_ACCT         => 7,  # Accounting messages
	L_DBG          => 16, # Only displayed when debugging is enabled
	L_DBG_WARN     => 17, # Warning only displayed when debugging is enabled
	L_DBG_ERR      => 18, # Error only displayed when debugging is enabled
	L_DBG_WARN_REQ => 19, # Less severe warning only displayed when debugging is enabled
	L_DBG_ERR_REQ  => 20, # Less severe error only displayed when debugging is enabled
};

#  Global variables can persist across different calls to the module.
#
#
#	{
#	 my %static_global_hash = ();
#
#		sub post_auth {
#		...
#		}
#		...
#	}


# Function to handle recv Access-Request
sub recv_access_request {
	my $p = shift();

	# For debugging purposes only
#	log_request_attributes($p);
	# Here's where your authorization code comes
	# You can call another function from here:
	test_call();

	return RLM_MODULE_OK;
}

# Function to handle authenticate
sub authenticate {
	my $p = shift();

	# For debugging purposes only
#	log_request_attributes($p);

	if ($p->{'request'}{'User-Name'}[0] =~ /^baduser/i) {
		# Reject user and tell him why
		$p->{'reply'}{'Reply-Message'}[0] = "Denied access by rlm_perl function";
		return RLM_MODULE_REJECT;
	} else {
		# Accept user and set some attribute
		if (&freeradius::xlat("%client(group)") eq 'UltraAllInclusive') {
			# User called from NAS with unlim plan set, set higher limits
			$p->{'reply'}{'Vendor-Specific'}{'Cisco'}{'h323-credit-amount'}[0] = "1000000";
		} else {
			$p->{'reply'}{'Vendor-Specific'}{'Cisco'}{'h323-credit-amount'}[0] = "100";
		}
		return RLM_MODULE_OK;
	}
}

# Function to handle recv Accounting
sub recv_accounting {
	my $p = shift();

	# For debugging purposes only
#	log_request_attributes($p);

	return RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {
	my $p = shift();

	# For debugging purposes only
#	log_request_attributes($p);

	# You can call another subroutine from here
	test_call();

	return RLM_MODULE_OK;
}

# Function to handle send sections
sub send {
	my $p = shift();

	# For debugging purposes only
#	log_request_attributes($p);

	return RLM_MODULE_OK;
}

# Function to handle xlat
# Receives arguments presented to the xlat as discrete
# arguments to the function.
# If any of the arguments are lists with multiple values e.g.
# %{User-Name[*]} where there are multiple instances of User-Name
# then these will be passed as references to arrays.
#
# Any return value is presented as the result of the xlat
#
# The function is called in array context so all returned values
# are received, though currently are concatenated before being
# presented as the expansion of the xlat.  This is due to change
# in the future.
#
# Note: Hashes for the attribute lists are not available in
#       xlat evaluation and neither will setting them result
#       in attributes being created.
sub xlat {
	# Loads some external perl and evaluate it
	my ($filename,$a,$b,$c,$d) = @_;
	freeradius::log(L_DBG, "From xlat $filename");
	freeradius::log(L_DBG,"From xlat $a $b $c $d");
	open(my $FH, '<', $filename) or die "open '$filename' $!";
	local($/) = undef;
	my $sub = <$FH>;
	close $FH;
	my $eval = qq{ sub handler{ $sub;} };
	eval $eval;  ## no critic
	eval {main->handler;};
}

# Function to handle detach
sub detach {

}

#
# Some functions that can be called from other functions
#

sub test_call {
	# Some code goes here
}

sub log_attributes {
	my %hash = %{$_[0]};
	my $indent = $_[1];
	for (keys %hash) {
		if (ref $hash{$_} eq 'HASH') {
			freeradius::log(L_DBG, ' 'x$indent . "$_ =>");
			log_attributes($hash{$_}, $indent + 2);
		} elsif (ref $hash{$_} eq 'ARRAY') {
			foreach my $attr (@{$hash{$_}}) {
				if (ref $attr eq 'HASH') {
					freeradius::log(L_DBG, ' 'x$indent . "$_ =>");
					log_attributes($attr, $indent + 2);
				} else {
					freeradius::log(L_DBG, ' 'x$indent . "$_ = $attr");
				}
			}
		}
	}
}

sub log_request_attributes {
	# This shouldn't be done in production environments!
	# This is only meant for debugging!
	my $p = shift();
	freeradius::log(L_DBG, "request:");
	log_attributes(\%{$p->{'request'}}, 2);
}

