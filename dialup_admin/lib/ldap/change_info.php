<?php
require_once('../lib/ldap/functions.php');
	if ($config[ldap_write_server])
		$ds = @ldap_connect($config[ldap_write_server]);
	else
		$ds = @ldap_connect($config[ldap_server]);
	if ($config[general_decode_normal_attributes] == 'yes'){
		$decode_normal = 1;
		if (is_file("../lib/lang/$config[general_prefered_lang]/utf8.php"))
			include_once("../lib/lang/$config[general_prefered_lang]/utf8.php");
		else
			include_once('../lib/lang/default/utf8.php');
		$k = init_encoder();
	}
	if ($ds){
		$r = @da_ldap_bind($ds,$config);
		if ($r){
			if ($Fcn != '' && $Fcn != '-' && $Fcn != $cn){
				list ($givenname,$sn) = preg_split('/ /',$Fcn,2);
				$mod['cn'] = $Fcn;
				$mod['cn'] = ($decode_normal) ? encode_string($mod['cn'],$k) : $mod['cn'];
				$mod['givenname'] = $givenname;
			$mod['givenname'] = ($decode_normal) ? encode_string($mod['givenname'],$k) : $mod['givenname'];
				$mod['sn'] = $sn;
				$mod['sn'] = ($decode_normal) ? encode_string($mod['sn'],$k) : $mod['sn'];

			}
			if ($Fmail != '' && $Fmail != '-' && $Fmail != $mail)
				$mod['mail'] = $Fmail;
			if ($Fou != '' && $Fou != '-' && $Fou != $ou){
				$mod['ou'] = $Fou;
				$mod['ou'] = ($decode_normal) ? encode_string($mod['ou'],$k) : $mod['ou'];
			}
			if ($Ftelephonenumber != '' && $Ftelephonenumber != '-' && $Ftelephonenumber != $telephonenumber)
				$mod['telephonenumber'] = $Ftelephonenumber;
			if ($Fhomephone != '' && $Fhomephone != '-' && $Fhomephone != $homephone)
				$mod['homephone'] = $Fhomephone;
			if ($dn != ''){
			       if ($config[ldap_debug] == 'true'){
					print "<b>DEBUG(LDAP): ldap_mod_replace(): DN='$dn'</b><br>\n";
					print "<b>DEBUG(LDAP): ldap_mod_replace(): Data:";
					print_r($mod);
					print "</b><br>\n";
				}
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
