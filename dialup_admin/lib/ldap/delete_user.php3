<?php
require_once('../lib/ldap/functions.php3');
if (!isset($ds))
	$ds = @ldap_connect($config[ldap_server]);
if ($ds){
	if (!isset($r))
		$r = @da_ldap_bind($ds,$config);
	if ($r){
		@ldap_delete($ds,$dn);
		if (@ldap_error($ds) == 'Success')
			echo "<b>User Deleted successfully</b><br>\n";
		else
			echo "<b>LDAP ERROR: " . ldap_error($ds) . "</b><br>\n";
		@ldap_close($ds);
	}
}
?>
