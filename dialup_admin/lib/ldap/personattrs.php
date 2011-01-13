<?php
#Read person attribute mapings
$ARR = file($config[general_ldap_person_attrs_file]);
foreach($ARR as $val){
	$val=chop($val);
	if (preg_match('/^[[:space:]]*#/',$val) || preg_match('/^[[:space:]]*$/',$val))
		continue;
	list($key,$desc)=preg_split("/\t+/",$val);
	$person_attrs["$key"] = "$desc";
}
?>
