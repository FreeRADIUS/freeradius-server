
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

# Bring the global hashes into the package scope
our (%RAD_REQUEST, %RAD_REPLY, %RAD_CHECK, %RAD_STATE, %RAD_PERLCONF);

# This is hash wich hold original request from radius
#my %RAD_REQUEST;
# In this hash you add values that will be returned to NAS.
#my %RAD_REPLY;
#This is for check items
#my %RAD_CHECK;
# This is the session-sate
#my %RAD_STATE;
# This is configuration items from "config" perl module configuration section
#my %RAD_PERLCONF;

# Multi-value attributes are mapped to perl arrayrefs.
#
#  update request {
#    Filter-Id := 'foo'
#    Filter-Id += 'bar'
#  }
#
# This results to the following entry in %RAD_REQUEST:
#
#  $RAD_REQUEST{'Filter-Id'} = [ 'foo', 'bar' ];
#
# Likewise, you can assign an arrayref to return multi-value attributes

#
# This the remapping of return values
#
use constant {
	RLM_MODULE_REJECT   => 0, # immediately reject the request
	RLM_MODULE_OK       => 2, # the module is OK, continue
	RLM_MODULE_HANDLED  => 3, # the module handled the request, so stop
	RLM_MODULE_INVALID  => 4, # the module considers the request invalid
	RLM_MODULE_USERLOCK => 5, # reject the request (user is locked out)
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
#	&log_request_attributes;

	# Here's where your authorization code comes
	# You can call another function from here:
	&test_call;

	return RLM_MODULE_OK;
}

# Function to handle authenticate
sub authenticate {
	# For debugging purposes only
#	&log_request_attributes;

	if ($RAD_REQUEST{'User-Name'} =~ /^baduser/i) {
		# Reject user and tell him why
		$RAD_REPLY{'Reply-Message'} = "Denied access by rlm_perl function";
		return RLM_MODULE_REJECT;
	} else {
		# Accept user and set some attribute
		if (&radiusd::xlat("%{client:group}") eq 'UltraAllInclusive') {
			# User called from NAS with unlim plan set, set higher limits
			$RAD_REPLY{'h323-credit-amount'} = "1000000";
		} else {
			$RAD_REPLY{'h323-credit-amount'} = "100";
		}
		return RLM_MODULE_OK;
	}
}

# Function to handle preacct
sub preacct {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {
	# For debugging purposes only
#	&log_request_attributes;

	# You can call another subroutine from here
	&test_call;

	return RLM_MODULE_OK;
}

# Function to handle checksimul
sub checksimul {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {
	# For debugging purposes only
#	&log_request_attributes;

	return RLM_MODULE_OK;
}

# Function to handle xlat
sub xlat {
	# For debugging purposes only
#	&log_request_attributes;

	# Loads some external perl and evaluate it
	my ($filename,$a,$b,$c,$d) = @_;
	&radiusd::radlog(L_DBG, "From xlat $filename ");
	&radiusd::radlog(L_DBG,"From xlat $a $b $c $d ");
	local *FH;
	open FH, $filename or die "open '$filename' $!";
	local($/) = undef;
	my $sub = <FH>;
	close FH;
	my $eval = qq{ sub handler{ $sub;} };
	eval $eval;
	eval {main->handler;};
}

# Function to handle detach
sub detach {
	# For debugging purposes only
#	&log_request_attributes;
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
		&radiusd::radlog(L_DBG, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}");
	}
}

