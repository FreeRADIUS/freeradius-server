<?php
#Read person attribute mapings
$ARR = file($config[general_ldap_person_attrs_file]);
foreach($ARR as $val){
	$val=chop($val);
	if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
		continue;
	list($key,$desc)=split("\t+",$val);
	$person_attrs["$key"] = "$desc";
}
?>
