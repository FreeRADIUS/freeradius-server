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
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#  
#  Copyright 2002  The FreeRADIUS server project
#  Copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
#  
#
#You can use every module that comes with your perl distribution

use strict;
# use ...
# This is very important ! Without this script will not get the filled hashesh from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK);
use Data::Dumper;

# This is hash wich hold original request from radius
#my %RAD_REQUEST;
# In this hash you add values that will be returned to NAS.
#my %RAD_REPLY;
#This is for check items
#my %RAD_CHECK;

#
# This the remaping of return values 
#
	use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
	use constant	RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
	use constant	RLM_MODULE_OK=>        2;#  /* the module is OK, continue */
	use constant	RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
	use constant	RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
	use constant	RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
	use constant	RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
	use constant	RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
	use constant	RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
	use constant	RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */

sub accounting
{
	for (keys %RAD_REQUEST) {
		# This is for test only 	
		&radiusd::radlog(1, "rlm_perl:: $_ = $RAD_REQUEST{$_} ");
	}

	#
	# You can call another subroutine from here 
	#
	
	&test_call;
	
	#
	# Add something to reply.
	#
	
	return RLM_MODULE_OK;
}

sub test_call
{
	#
	# Some code goes here 
	#
	
}

#
# This is authentication	
#
#
sub authenticate 
{
	# Do something 
	# Authenticate the request !
	# 
	# Return some info to NAS 
	
	$RAD_REPLY{'h323-credit-amount'} = "100";
	
	#...
	#
	
	return RLM_MODULE_OK;
}
sub detach 
{
	        &radiusd::radlog(0,"rlm_perl::Detaching. Reloading. Done.");
}

#
# This is xlate function wich loads some external perl and evaluate it.
#
sub xlat
{
	        
      my ($filename,$a,$b,$c,$d) = @_;
		        
      &radiusd::radlog(1, "From xlat $filename ");
      &radiusd::radlog(1,"From xlat $a $b $c $d ");
      local *FH;
      open FH, $filename or die "open '$filename' $!";
      local($/) = undef;
      my $sub = <FH>;
      close FH;
      my $eval = qq{ sub handler{ $sub;} };
      eval $eval;
      eval {main->handler;};
											        
}
