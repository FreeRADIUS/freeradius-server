<?php
unset($text_default_vals);
unset($default_vals);
if (isset($_SESSION['text_default_vals']))
	$text_default_vals = $_SESSION['text_default_vals'];
if (!isset($text_default_vals)){
	$ARR=file("$config[general_default_file]");
	foreach($ARR as $val) {
		$val=chop($val);
		if (preg_match('/^[[:space:]]*#/',$val) || preg_match('/^[[:space:]]*$/',$val))
			continue;
		list($key,$v)=preg_split("/:[[:space:]]*/",$val,2);
		$text_default_vals["$key"][0]="$v";
		$text_default_vals["$key"]['count']++;
	}
	if (!isset($text_default_vals))
		$text_default_vals["NOT_EXIST"][0] = '0';
	if ($config[general_use_session] == 'yes')
		session_register('text_default_vals');
}
$default_vals = $text_default_vals;
if (is_file("../lib/$config[general_lib_type]/defaults.php"))
        include("../lib/$config[general_lib_type]/defaults.php");
?>
