<?php
#Read user_edit attribute map
if (!isset($show_attrs)){
	$ARR = file($config[general_user_edit_attrs_file]);
	foreach($ARR as $val){
		$val=chop($val);
		if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
			continue;
		list($key,$v)=split("\t+",$val);
		$show_attrs["$key"]=($v != '') ? "$v" : "$key";
	}
	if ($config[general_use_session] == 'yes')
		session_register('show_attrs');
}
if (!isset($acct_attrs) && isset($config[general_accounting_attrs_file])){
	$ARR = file($config[general_accounting_attrs_file]);
	foreach ($ARR as $val){
		$val=chop($val);
		if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
			continue;
		list($num,$desc,$showua,$showuf,$showfl)=split("\t+",$val);
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
