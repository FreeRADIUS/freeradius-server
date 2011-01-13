<?php
require_once('../lib/xlat.php');

function da_ldap_bind($ds,$config)
{
	if ($ds){
		if ($config[ldap_use_http_credentials] == 'yes'){
			$din = $_SERVER["PHP_AUTH_USER"];
			$pass = $_SERVER["PHP_AUTH_PW"];
			if ($config[ldap_map_to_directory_manager] != '' &&
			$din == $config[ldap_map_to_directory_manager] &&
			$config[ldap_directory_manager] != '')
				$din = $config[ldap_directory_manager];
		}
		if ($config[ldap_use_http_credentials] != 'yes' ||
			($din == '' && $pass == '')){
			$din = $config[ldap_binddn];
			$pass = $config[ldap_bindpw];
		}
		if (preg_match('/[\s,]/',$din)){	// It looks like a dn
			if ($config[ldap_debug] == 'true')
				print "<b>DEBUG(LDAP): Bind Request: DN='$din',PASSWD='$pass'</b><br>\n";
			return @ldap_bind($ds,"$din","$pass");
		}
		else{				// It's not a DN. Find a corresponding DN
			if ($config[ldap_debug] == 'true')
		print "<b>DEBUG(LDAP): Bind Request: DN='$config[ldap_binddn]',PASSWD='$config[ldap_bindpw]'</b><br>\n";
			$r=@ldap_bind($ds,"$config[ldap_binddn]",$config[ldap_bindpw]);
			if ($r){
				$sr=@ldap_search($ds,"$config[ldap_base]", 'uid=' . $din);
				$info = @ldap_get_entries($ds, $sr);
				$din = $info[0]['dn'];
				if ($din != ''){
					if ($config[ldap_debug] == 'true')
						print "<b>DEBUG(LDAP): Bind Request: DN='$din',PASSWD='$pass'</b><br>\n";
					return @ldap_bind($ds,"$din","$pass");
				}
			}
		}
	}
}

function connect2db($config)
{
	$ds=@ldap_connect("$config[ldap_server]");  // must be a valid ldap server!
	if ($ds)
		$r=@da_ldap_bind($ds,$config);
	return $ds;
}

function get_user_info($ds,$user,$config,$decode_normal,$k)
{
	if ($ds){
		$attrs = array('cn');
		if ($config[ldap_userdn] == ''){
			if ($config[ldap_filter] != '')
				$filter = xlat($config[ldap_filter],$login,$config);
			else
				$filter = 'uid=' . $login;
		}
		else
			$filter = xlat($config[ldap_userdn],$login,$config);
		if ($config[ldap_debug] == 'true'){
			if ($config[ldap_userdn] == '')
	print "<b>DEBUG(LDAP): Search Query: BASE='$config[ldap_base]',FILTER='$filter'</b><br>\n";
			else
	print "<b>DEBUG(LDAP): Search Query: BASE='$filter',FILTER='(objectclass=radiusprofile)'</b><br>\n";
		}
		if ($config[ldap_userdn] == '')
			$sr=@ldap_search($ds,"$config[ldap_base]", $filter,$attrs);
		else
			$sr=@ldap_read($ds,$filter, '(objectclass=radiusprofile)',$attrs);
		$info = @ldap_get_entries($ds, $sr);
		$cn = $info[0]["cn"][0];
		if ($cn != '' && $decode_normal == 1)
			$cn = decode_string($cn,$k);
		if ($cn == '')
			$cn = '-';
		return $cn;
	}
}

function get_user_dn($ds,$user,$config)
{
	if ($ds){
		$attrs = array('dn');
		if ($config[ldap_userdn] == ''){
			if ($config[ldap_filter] != '')
				$filter = xlat($config[ldap_filter],$login,$config);
			else
				$filter = 'uid=' . $login;
		}
		else
			$filter = xlat($config[ldap_userdn],$login,$config);
		if ($config[ldap_debug] == 'true'){
			if ($config[ldap_userdn] == '')
	print "<b>DEBUG(LDAP): Search Query: BASE='$config[ldap_base]',FILTER='$filter'</b><br>\n";
			else
	print "<b>DEBUG(LDAP): Search Query: BASE='$filter',FILTER='(objectclass=radiusprofile)'</b><br>\n";
		}
		if ($config[ldap_userdn] == '')
			$sr=@ldap_search($ds,"$config[ldap_base]", $filter,$attrs);
		else
			$sr=@ldap_read($ds,$filter, '(objectclass=radiusprofile)',$attrs);
		$entry = ldap_first_entry($ds, $sr);
		if ($entry)
			$dn = ldap_get_dn($ds,$entry);
		return $dn;
	}
}

function check_user_passwd($dn,$passwd,$config)
{
	$ds=@ldap_connect("$config[ldap_server]");
	if ($ds && $dn != '' && $passwd != ''){
		$r = @ldap_bind($ds,$dn,$passwd);
		if ($r)
			return TRUE;
		else
			return FALSE;
	}
	else
		return FALSE;

	return FALSE;
}

function closedb($ds,$config)
{
	if ($ds)
		@ldap_close($ds);
}
?>
