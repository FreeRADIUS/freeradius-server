<?php
#Read sql attribute map
unset($attrmap);
unset($rev_attrmap);
unset($attr_type);
if (isset($_SESSION['attrmap'])){
	#If attrmap is set then the rest will also be set
        $attrmap = $_SESSION['attrmap'];
	$rev_attrmap =$_SESSION['rev_attrmap'];
	$attr_type = $_SESSION['attr_type'];
}
$ARR = file("$config[general_sql_attrmap]");
foreach($ARR as $val){
	$val=chop($val);
	if (ereg('^[[:space:]]*#',$val) || ereg('^[[:space:]]*$',$val))
		continue;
	list($type,$key,$v)=split('[[:space:]]+',$val);
	$attrmap["$key"]=$v;
	$rev_attrmap["$v"] = $key;
	$attr_type["$key"]=$type;
	if ($config[general_use_session] == 'yes'){
		session_register('attrmap');
		session_register('rev_attrmap');
		session_register('attr_type');
	}
}
