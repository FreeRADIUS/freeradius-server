<?php
require_once('../lib/ldap/functions.php3');
$ds=@ldap_connect("$config[ldap_server]");  // must be a valid ldap server!
if ($ds) {
	$r=@da_ldap_bind($ds,$config);
	if ($search_IN == 'name' || $search_IN == 'ou')
		$attr = ($search_IN == 'name') ? 'cn' : 'ou';
	else if ($search_IN == 'radius'){
		require('../lib/ldap/attrmap.php3');
		$attr = $attrmap[$radius_attr];
	}
	$sr=@ldap_search($ds,"$config[ldap_base]", "$attr=*$search*",array('uid'),0,$max_results);
	if (($info = @ldap_get_entries($ds, $sr))){
		for ($i = 0; $i < $info["count"]; $i++)
			$found_users[] = $info[$i]['uid'][0];
	}
	@ldap_close($ds);
}
else
	echo "<b>Could not connect to the LDAP server</b><br>\n";
?>
