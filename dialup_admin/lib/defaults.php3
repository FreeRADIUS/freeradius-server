<?php
$ARR=file("$config[general_default_file]");
foreach($ARR as $val) {
	$val=chop($val);
	if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
		continue;
	list($key,$v)=split(":[[:space:]]*",$val);
	$default_vals["$key"]="$v";
}
if (is_file("../lib/$config[general_lib_type]/defaults.php3"))
        include("../lib/$config[general_lib_type]/defaults.php3");
