<?php
#Read sql attribute map
if (!isset($sql_attrs)){
	$ARR = file($config[general_sql_attrs_file]);
	foreach($ARR as $val){
		$val=chop($val);
		if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
			continue;
		list($key,$desc,$show,$func)=split("\t+",$val);
		$sql_attrs[strtolower($key)][desc] = "$desc";
		$sql_attrs[strtolower($key)][show] = "$show";
		$sql_attrs[strtolower($key)][func] = ($func == "") ? "nothing" : "$func";
	}
	if ($config[general_use_session] == 'yes')
		session_register('sql_attrs');
}
?>
