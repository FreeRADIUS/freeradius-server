<?php
function connect2db($config)
{
	$ds=@ldap_connect("$config[ldap_server]");  // must be a valid ldap server!
	if ($ds)
		$r=@ldap_bind($ds,"$config[ldap_binddn]",$config[ldap_bindpw]);
	return $ds;
}

function get_user_info($ds,$user,$config)
{
	if ($ds){
		$sr=@ldap_search($ds,"$config[ldap_base]", "uid=" . $user);
		$info = @ldap_get_entries($ds, $sr);
		$cn = $info[0]["cn"][0];
		if ($cn == '')
			$cn = '-';
		return $cn;
	}
}

function closedb($ds,$config)
{
	if ($ds)
		@ldap_close($ds);
}
?>
