<?php
#Read ldap attribute map
$ARR = file("$config[general_sql_attrmap]");
foreach($ARR as $val){
	$val=chop($val);
	if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
		continue;
	list($type,$key,$v)=split('[[:space:]]+',$val);
	$attrmap["$key"]=$v;
	$attr_type["$key"]=$type;
}
