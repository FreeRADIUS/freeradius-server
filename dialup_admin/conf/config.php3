<?php
$ARR=file("/usr/local/dialup_admin/conf/admin.conf");
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
?>
