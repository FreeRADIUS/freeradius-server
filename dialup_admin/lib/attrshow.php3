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
?>
