<?php
#Read user_edit attribute map
$ARR = file($config[general_user_edit_attrs_file]);
foreach($ARR as $val){
	$val=chop($val);
	if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
		continue;
	list($key,$v)=split("\t+",$val);
	$show_attrs["$key"]=($v != '') ? "$v" : "$key";
}
?>
