<?php
include_once('../lib/xlat.php');
#Read user_edit attribute map
unset($show_attrs);
if (isset($_SESSION['show_attrs']))
	$show_attrs = $_SESSION['show_attrs'];
if (!isset($show_attrs)){
	$infile = xlat($config[general_user_edit_attrs_file],$login,$config);
	$ARR = file($infile);
	foreach($ARR as $val){
		$val=chop($val);
		if (preg_match('/^[[:space:]]*#/',$val) || preg_match('/^[[:space:]]*$/',$val))
			continue;
		list($key,$v)=preg_split("/\t+/",$val);
		$show_attrs["$key"]=($v != '') ? "$v" : "$key";
	}
	if ($config[general_use_session] == 'yes')
		session_register('show_attrs');
}
unset($acct_attrs);
if (isset($_SESSION['acct_attrs']))
	$acct_attrs = $_SESSION['acct_attrs'];
if (!isset($acct_attrs) && isset($config[general_accounting_attrs_file])){
	$infile = xlat($config[general_accounting_attrs_file],$login,$config);
	$ARR = file($infile);
	foreach ($ARR as $val){
		$val=chop($val);
		if (preg_match('/^[[:space:]]*#/',$val) || preg_match('/^[[:space:]]*$/',$val))
			continue;
		list($num,$desc,$showua,$showuf,$showfl)=preg_split("/\t+/",$val);
		if ($showua == 'yes'){
			$acct_attrs["ua"]["num"]++;
			$acct_attrs["ua"]["$num"]=$desc;
		}
		if ($showuf == 'yes'){
			$acct_attrs["uf"]["num"]++;
			$acct_attrs["uf"]["$num"]=$desc;
		}
		if ($showfl == 'yes'){
			$acct_attrs["fl"]["num"]++;
			$acct_attrs["fl"]["$num"]=$desc;
		}
	}
	if ($config[general_use_session] == 'yes')
		session_register('acct_attrs');
}
?>
