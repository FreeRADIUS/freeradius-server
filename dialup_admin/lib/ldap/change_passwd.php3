<?php
require_once('../lib/ldap/functions.php3');
	if (!isset($ds))
		$ds = @ldap_connect($config[ldap_server]);
	if ($ds){
		if (!isset($r))
			$r = @da_ldap_bind($ds,$config);
		if ($r){
			if (is_file("../lib/crypt/$config[general_encryption_method].php3")){
				include("../lib/crypt/$config[general_encryption_method].php3");
				$passwd = da_encrypt($passwd);
				$passwd = '{' . $config[general_encryption_method] . '}' . $passwd;
				$mod[$attrmap['User-Password']] = $passwd;
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
