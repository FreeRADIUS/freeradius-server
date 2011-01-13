<?php
#
# Things should work even if register_globals is set to off
#

$testVer=intval(str_replace(".", "",'4.1.0'));
$curVer=intval(str_replace(".", "",phpversion()));
if( $curVer >= $testVer )
	import_request_variables('GPC');
# If using sessions set use_session to 1 to also cache the config file
#
$use_session = 0;
unset($config);
unset($nas_list);
if ($use_session){
	// Start session
	@session_start();
	if (isset($_SESSION['config']))
		$config = $_SESSION['config'];
	if (isset($_SESSION['nas_list']))
		$nas_list = $_SESSION['nas_list'];
}
if (!isset($config)){
	$ARR=file("../conf/admin.conf");
	$EXTRA_ARR = array();
	foreach($ARR as $val) {
		$val=chop($val);
		if (preg_match('/^[[:space:]]*#/',$val) || preg_match('/^[[:space:]]*$/',$val))
			continue;
		list($key,$v)=preg_split("/:[[:space:]]*/",$val,2);
		if (preg_match("/%\{(.+)\}/",$v,$matches)){
			$val=$config[$matches[1]];
			$v=preg_replace("/%\{$matches[1]\}/",$val,$v);
		}
		if (preg_match("/^nas(\d+)_(\w+)$/",$key,$matches))
			$nas_list[$matches[1]][$matches[2]] = $v;
		if ($key == 'INCLUDE'){
			if (is_readable($v))
				array_push($EXTRA_ARR,file($v));
			else
				echo "<b>Error: File '$v' does not exist or is not readable</b><br>\n";
		}
		else
			$config["$key"]="$v";
	}
	foreach($EXTRA_ARR as $val1) {
		foreach($val1 as $val){
			$val=chop($val);
			if (preg_match('/^[[:space:]]*#/',$val) || preg_match('/^[[:space:]]*$/',$val))
				continue;
			list($key,$v)=preg_split("/:[[:space:]]*/",$val,2);
			if (preg_match("/%\{(.+)\}/",$v,$matches)){
				$val=$config[$matches[1]];
				$v=preg_replace("/%\{$matches[1]\}/",$val,$v);
			}
			if (preg_match("/^nas(\d+)_(\w+)$/",$key,$matches))
				$nas_list[$matches[1]][$matches[2]] = $v;
			$config["$key"]="$v";
		}
	}
	if ($use_session){
		session_register('config');
		session_register('nas_list');
	}

}
if ($use_session == 0 && $config[general_use_session] == 'yes'){
	// Start session
	@session_start();
	if (isset($nas_list))
		session_register('nas_list');
}
//Make sure we are only passed allowed strings in username
if ($login != '')
	$login = preg_replace("/[^\w\.\/\@\:\-]/",'',$login);

if ($login != '' && $config[general_strip_realms] == 'yes'){
	$realm_del = ($config[general_realm_delimiter] != '') ? $config[general_realm_delimiter] : '@';
	$realm_for = ($config[general_realm_format] != '') ? $config[general_realm_format] : 'suffix';
	$new = explode($realm_del,$login,2);
	if (count($new) == 2)
		$login = ($realm_for == 'suffix') ? $new[0] : $new[1];
}
unset($mappings);
if (isset($_SESSION['mappings']))
	$mappings = $_SESSION['mappings'];
if (!isset($mappings) && $config[general_username_mappings_file] != ''){
	$ARR = file($config[general_username_mappings_file]);
	foreach($ARR as $val){
		$val=chop($val);
		if (preg_match('/^[[:space:]]*#/',$val) || preg_match('/^[[:space:]]*$/',$val))
			continue;
		list($key,$realm,$v)=preg_split("/:[[:space:]]*/",$val,3);
		if ($realm == 'accounting' || $realm == 'userdb' || $realm == 'nasdb' || $realm == 'nasadmin')
			$mappings["$key"][$realm] = $v;
		if ($realm == 'nasdb'){
			$NAS_ARR = array();
			$NAS_ARR = preg_split('/,/',$v);
			foreach ($nas_list as $key => $nas){
				foreach ($NAS_ARR as $nas_check){
					if ($nas_check == $nas[name])
						unset($nas_list[$key]);
				}
			}
		}
	}
	if ($config[general_use_session] == 'yes')
		session_register('mappings');
}

date_default_timezone_set($config[timezone]);

//Include missing.php if needed
if (!function_exists('array_change_key_case'))
	include_once('../lib/missing.php');
@header('Content-type: text/html; charset='.$config[general_charset].';');
?>
