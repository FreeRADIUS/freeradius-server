<?php
function da_ldap_bind($ds,$config)
{
	if ($ds){
		if ($config[ldap_use_http_credentials] == 'yes'){
			global $HTTP_SERVER_VARS;
			$din = $HTTP_SERVER_VARS["PHP_AUTH_USER"];
			$pass = $HTTP_SERVER_VARS["PHP_AUTH_PW"];
		}
		if ($config[ldap_use_http_credentials] != 'yes' ||
			($din == '' && $pass == '')){
			$din = $config[ldap_binddn];
			$pass = $config[ldap_bindpw];
		}	
		if (preg_match('/[\s,]/',$din))		// It looks like a dn
			return @ldap_bind($ds,$din,$pass);
		else{				// It's not a DN. Find a corresponding DN
			$r=@ldap_bind($ds,"$config[ldap_binddn]",$config[ldap_bindpw]);
			if ($r){
				$sr=@ldap_search($ds,"$config[ldap_base]", 'uid=' . $din);
				$info = @ldap_get_entries($ds, $sr);
				$din = $info[0]['dn'];
				if ($din != '')
					return @ldap_bind($ds,$din,$pass);
			}
		}
	}
}

function connect2db($config)
{
	if (!isset($ds))
		$ds=@ldap_connect("$config[ldap_server]");  // must be a valid ldap server!
	if ($ds)
		if (!isset($r))
			$r=@da_ldap_bind($ds,$config);
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
