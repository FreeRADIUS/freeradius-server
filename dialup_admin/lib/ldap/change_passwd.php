<?php
require_once('../lib/ldap/functions.php');
	if ($config[ldap_write_server])
		$ds = @ldap_connect($config[ldap_write_server]);
	else
		$ds = @ldap_connect($config[ldap_server]);
	if ($ds){
		$r = @da_ldap_bind($ds,$config);
		if ($r){
			if (is_file("../lib/crypt/$config[general_encryption_method].php")){
				include("../lib/crypt/$config[general_encryption_method].php");
				$passwd = da_encrypt($passwd);
				$passwd = '{' . $config[general_encryption_method] . '}' . $passwd;
				$mod[$attrmap['User-Password']] = $passwd;
				if ($config[ldap_debug] == 'true'){
					print "<b>DEBUG(LDAP): ldap_mod_replace(): DN='$dn'</b><br>\n";
					print "<b>DEBUG(LDAP): ldap_mod_replace(): Data:";
					print_r($mod);
					print "</b><br>\n";
				}
				@ldap_mod_replace($ds,$dn,$mod);
				if (@ldap_error($ds) != 'Success')
					echo "<b>LDAP ERROR: " . ldap_error($ds) . "</b><br>\n";
			}
			else
				echo "<b>Could not open encryption library file.</b><br>\n";
		}
		@ldap_close($ds);
	}
?>
