<?php
require_once('../lib/ldap/functions.php3');
	$ds = @ldap_connect($config[ldap_server]);
	if ($ds){
		$r = @da_ldap_bind($ds,$config);
		if ($r){
			if ($Fcn != '' && $Fcn != '-' && $Fcn != $cn)
				$mod['cn'] = $Fcn;
			if ($Fmail != '' && $Fmail != '-' && $Fmail != $mail)
				$mod['mail'] = $Fmail;
			if ($Fou != '' && $Fou != '-' && $Fou != $ou)
				$mod['ou'] = $Fou;
			if ($Ftelephonenumber != '' && $Ftelephonenumber != '-' && $Ftelephonenumber != $telephonenumber)
				$mod['telephonenumber'] = $Ftelephonenumber;
			if ($Fhomephone != '' && $Fhomephone != '-' && $Fhomephone != $homephone)
				$mod['homephone'] = $Fhomephone;
			if ($dn != ''){
				@ldap_mod_replace($ds,$dn,$mod);
				if (@ldap_error($ds) != 'Success')
					echo "<b>LDAP ERROR: " . ldap_error($ds) . "</b><br>\n";
				else
					echo "<b>User personal information updated successfully</b><br>\n";
			}
		}
		@ldap_close($ds);
	}
?>
