<?php
# If using sessions set use_session to 1 to also cache the config file
#
$use_session = 0;
if ($use_session){
	// Start session
	@session_start();
}
if (!isset($config)){
	$ARR=file("../conf/admin.conf");
	foreach($ARR as $val) {
		$val=chop($val);
		if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
			continue;
		list($key,$v)=split(":[[:space:]]*",$val,2);
		if (preg_match("/%\{(.+)\}/",$v,$matches)){
			$val=$config[$matches[1]];
			$v=preg_replace("/%\{$matches[1]\}/",$val,$v);
		}
		$config["$key"]="$v";
	}
	if ($use_session)
		session_register('config');
}
if ($use_session == 0 && $config[general_use_session] == 'yes'){
	// Start session
	@session_start();
}
if ($login != '' && $config[general_strip_realms] == 'yes'){
	$realm_del = ($config[general_realm_delimiter] != '') ? $config[general_realm_delimiter] : '@';
	$realm_for = ($config[general_realm_format] != '') ? $config[general_realm_format] : 'suffix';
	$new = explode($realm_del,$login,2);
	if (count($new) == 2)
		$login = ($realm_for == 'suffix') ? $new[0] : $new[1];
}
?>
