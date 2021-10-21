use strict;
use warnings;

# Bring the global hashes into the package scope
our (%RAD_REQUEST, %RAD_REPLY, %RAD_CONFIG, %RAD_STATE);

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


# Function to handle authorize
sub authorize {
	# For debugging purposes only
#	log_request_attributes();

	# Here's where your authorization code comes
	# You can call another function from here:
	test_call();

	return RLM_MODULE_OK;
}

# Function to handle authenticate
sub authenticate {
	# For debugging purposes only
#	log_request_attributes();

	if ($RAD_REQUEST{'User-Name'} =~ /^baduser/i) {
		# Reject user and tell him why
		$RAD_REPLY{'Reply-Message'} = "Denied access by rlm_perl function";
		# For testing return NOTFOUND - returning REJECT immediatly rejects the packet so fails the test
		return RLM_MODULE_NOTFOUND;
	} else {
		# Accept user and set some attribute
		if (&radiusd::xlat("%(client:group)") eq 'UltraAllInclusive') {
			# User called from NAS with unlim plan set, set higher limits
			$RAD_REPLY{'Vendor-Specific.Cisco.h323-credit-amount'} = "1000000";
		} else {
			$RAD_REPLY{'Vendor-Specific.Cisco.h323-credit-amount'} = "100";
		}
		return RLM_MODULE_OK;
	}
}

# Function to handle preacct
sub preacct {
	# For debugging purposes only
#	log_request_attributes();

	return RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {
	# For debugging purposes only
#	log_request_attributes();

	# You can call another subroutine from here
	test_call();

	return RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {
	# For debugging purposes only
#	log_request_attributes();

	return RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {
	# For debugging purposes only
#	log_request_attributes();

	return RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {
	# For debugging purposes only
#	log_request_attributes();

	return RLM_MODULE_OK;
}

# Function to handle xlat
sub xlat {
	# For debugging purposes only
#	log_request_attributes();

	# Loads some external perl and evaluate it
	my ($filename,$a,$b,$c,$d) = @_;
	radiusd::log(L_DBG, "From xlat $filename");
	radiusd::log(L_DBG,"From xlat $a $b $c $d");
	open(my $FH, '<', $filename) or die "open '$filename' $!";
	local($/) = undef;
	my $sub = <$FH>;
	close $FH;
	my $eval = qq{ sub handler{ $sub;} };
	eval $eval; ## no critic
	eval {main->handler;};
}

# Function to handle detach
sub detach {
	# For debugging purposes only
#	log_request_attributes();
}

#
# Some functions that can be called from other functions
#

sub test_call {
	# Some code goes here
}

sub log_request_attributes {
	# This shouldn't be done in production environments!
	# This is only meant for debugging!
	for (keys %RAD_REQUEST) {
		radiusd::log(L_DBG, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}");
	}
}
