<?php
require_once('../lib/functions.php');
require_once('../lib/ldap/functions.php');
	if ($config[ldap_write_server])
		$ds = @ldap_connect($config[ldap_write_server]);
	else
		$ds = @ldap_connect($config[ldap_server]);
	if ($ds){
		$r = @da_ldap_bind($ds,$config);
		if ($r){
			list ($givenname,$sn) = preg_split('/ /',$Fcn,2);
			$dn = 'uid=' . $login . ',' . $config[ldap_default_new_entry_suffix];
			$new_user_entry["objectclass"][0]="top";
			$new_user_entry["objectclass"][1]="person";
			$new_user_entry["objectclass"][2]="organizationalPerson";
			$new_user_entry["objectclass"][3]="inetOrgPerson";
			$new_user_entry["objectclass"][4]="radiusprofile";
			$new_user_entry["cn"]="$Fcn";
			$new_user_entry["sn"]="$sn";
			$new_user_entry["givenname"]="$givenname";
			$new_user_entry["mail"]="$Fmail";
			$new_user_entry["telephonenumber"]="$Ftelephonenumber";
			$new_user_entry["homephone"]="$Fhomephone";
			$new_user_entry["mobile"]="$Fmobile";
			$new_user_entry["ou"]="$Fou";
			$new_user_entry["uid"]="$login";
			if (is_file("../lib/crypt/$config[general_encryption_method].php")){
				include("../lib/crypt/$config[general_encryption_method].php");
				$passwd = da_encrypt($passwd);
		$new_user_entry[$attrmap['User-Password']] = '{' . "$config[general_encryption_method]" . '}' . $passwd;
			}
			else{
				echo "<b>Could not open encryption library file.Password will be clear text.</b><br>\n";
				$new_user_entry[$attrmap['User-Password']]="{clear}" . $passwd;
			}

			if ($config[ldap_debug] == 'true'){
				print "<b>DEBUG(LDAP): ldap_add(): DN='$dn'</b><br>\n";
				print "<b>DEBUG(LDAP): ldap_add(): Entry Data:";
				print_r($new_user_entry);
				print "</b><br>\n";
			}
			@ldap_add($ds,$dn,$new_user_entry);

			foreach($show_attrs as $key => $attr){
				if ($attrmap["$key"] == 'none')
					continue;
//
//	if value is the same as the default and the corresponding attribute in ldap does not exist or
//	the value is the same as that in ldap then continue
//
	        		if ( check_defaults($$attrmap["$key"],'',$default_vals["$key"]))
	                		continue;
				if ( $$attrmap["$key"] == '')
					continue;
				unset($mod);
				$mod[$attrmap["$key"]] = $$attrmap["$key"];

				if ($config[ldap_debug] == 'true'){
					print "<b>DEBUG(LDAP): ldap_mod_add(): DN='$dn'</b><br>\n";
					print "<b>DEBUG(LDAP): ldap_mod_add(): Data:";
					print_r($mod);
					print "</b><br>\n";
				}
				@ldap_mod_add($ds,$dn,$mod);
			}
		}
		if (@ldap_error($ds) == 'Success')
			echo "<b>User was added in user database</b><br>\n";
		else
			echo "<b>LDAP ERROR: " . ldap_error($ds) . "</b><br>\n";
		@ldap_close($ds);
	}
?>
