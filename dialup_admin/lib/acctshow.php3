<?php
#Read sql attribute map
$ARR = file($config[general_sql_attrs_file]);
foreach($ARR as $val){
	$val=chop($val);
	if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
		continue;
	list($key,$desc,$show,$func)=split("\t+",$val);
	$sql_attrs["$key"][desc] = "$desc";
	$sql_attrs["$key"][show] = "$show";
	$sql_attrs["$key"][func] = ($func == "") ? "nothing" : "$func";
}
?>
