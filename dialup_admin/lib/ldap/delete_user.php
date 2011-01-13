<?php
require_once('../lib/ldap/functions.php');
if ($config[ldap_write_server])
	$ds = @ldap_connect($config[ldap_write_server]);
else
	$ds = @ldap_connect($config[ldap_server]);
if ($ds){
	$r = @da_ldap_bind($ds,$config);
	if ($r){
		if ($config[ldap_debug] == 'true')
			print "<b>DEBUG(LDAP): Delete Request: DN='$dn'</b><br>\n";
		@ldap_delete($ds,$dn);
		if (@ldap_error($ds) == 'Success')
			echo "<b>User Deleted successfully</b><br>\n";
		else
			echo "<b>LDAP ERROR: " . ldap_error($ds) . "</b><br>\n";
		@ldap_close($ds);
	}
}
?>
