<?php
require_once('../lib/ldap/functions.php3');
$ds=@ldap_connect("$config[ldap_server]");  // must be a valid ldap server!
if ($ds) {
	if (!is_numeric($max))
		$max = 10;
	if ($max > 500)
		$max = 10;
	$r=@da_ldap_bind($ds,$config);
	if ($search_IN == 'name' || $search_IN == 'ou')
		$attr = ($search_IN == 'name') ? 'cn' : 'ou';
	else if ($search_IN == 'radius'){
		require('../lib/ldap/attrmap.php3');
		$attr = $attrmap[$radius_attr];
	}
	if ($config[ldap_debug] == 'true')
		print "<b>DEBUG(LDAP): Search Query: BASE='$config[ldap_base]',FILTER='$attr=*$search*'</b><br>\n";
	$sr=@ldap_search($ds,"$config[ldap_base]", "$attr=*$search*",array('uid'),0,$max);
	if (($info = @ldap_get_entries($ds, $sr))){
		for ($i = 0; $i < $info["count"]; $i++)
			$found_users[] = $info[$i]['uid'][0];
	}
	@ldap_close($ds);
}
else
	echo "<b>Could not connect to the LDAP server</b><br>\n";
?>
