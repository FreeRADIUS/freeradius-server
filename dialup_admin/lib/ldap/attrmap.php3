<?php
#Read ldap attribute map
$ARR = file("$config[general_ldap_attrmap]");
foreach($ARR as $val){
	$val=chop($val);
	if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
		continue;
	list(,$key,$v)=split('[[:space:]]+',$val);
	$v = strtolower($v);
	$attrmap["$key"]=$v;
}
$ARR = file("$config[general_extra_ldap_attrmap]");
foreach($ARR as $val){
	$val=chop($val);
	if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
		continue;
	list(,$key,$v)=split('[[:space:]]+',$val);
	$v = strtolower($v);
	$attrmap["$key"]=$v;
}
?>
