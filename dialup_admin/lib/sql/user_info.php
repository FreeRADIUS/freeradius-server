<?php
require('../lib/sql/attrmap.php');
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
if ($config[sql_use_operators] == 'true'){
	$op = ',op';
	$use_op = 1;
}else{
	$op = "";
	$use_op = 0;
}
$user_exists = 'no';

$cn = '-';
$cn_lang = '-';
$address = '-';
$address_lang = '-';
$homeaddress = '-';
$homeaddress_lang = '-';
$fax = '-';
$url = '-';
$ou = '-';
$ou_lang = '-';
$title = '-';
$title_lang = '-';
$telephonenumber = '-';
$homephone = '-';
$mobile = '-';
$mail = '-';
$mailalt = '-';
$user_password_exists = 'no';

unset($item_vals);
unset($tmp);
$link = @da_sql_pconnect($config);
if ($link){
	$res = @da_sql_query($link,$config,
	"SELECT attribute,value $op FROM $config[sql_check_table] WHERE username = '$login';");
	if ($res){
		if (@da_sql_num_rows($res,$config))
			$user_exists = 'yes';
		while(($row = @da_sql_fetch_array($res,$config))){
			$attr = $row[attribute];
			$val = $row[value];
			if ($attr == $config[sql_password_attribute] && $val != '')
				$user_password_exists = 'yes';
			if ($use_op){
				$oper = $row[op];
				$tmp["$attr"][operator][]="$oper";
			}
			$tmp["$attr"][]="$val";
			$tmp["$attr"][count]++;
		}
		$res = @da_sql_query($link,$config,
		"SELECT attribute,value $op FROM $config[sql_reply_table] WHERE username = '$login';");
		if ($res){
			if (@da_sql_num_rows($res,$config))
				$user_exists = 'yes';
			while(($row = @da_sql_fetch_array($res,$config))){
				$attr = $row[attribute];
				$val = $row[value];
				if ($use_op){
					$oper = $row[op];
					$tmp["$attr"][operator][]="$oper";
				}
				$tmp["$attr"][] = "$val";
				$tmp["$attr"][count]++;
			}
			if ($config[sql_use_user_info_table] == 'true'){
				$res = @da_sql_query($link,$config,
				"SELECT * FROM $config[sql_user_info_table] WHERE username = '$login';");
				if ($res){
					if (@da_sql_num_rows($res,$config)){
						$user_exists = 'yes';
						$user_info = 1;
					}
					if (($row = @da_sql_fetch_array($res,$config))){
						$cn = ($row[name] != '') ? $row[name] : '-';
						$telephonenumber = ($row[workphone] != '') ? $row[workphone] : '-';
						$homephone = ($row[homephone] != '') ? $row[homephone] : '-';
						$ou = ($row[department] != '') ? $row[department] : '-';
						$mail = ($row[mail] != '') ? $row[mail] : '-';
						$mobile = ($row[mobile] != '') ? $row[mobile] : '-';
					}
				}
				else
					echo "<b>Database query failed partially: " . da_sql_error($link,$config) . "</b><br>\n";
			}
		}
		else
			echo "<b>Database query failed partially: " . da_sql_error($link,$config) . "</b><br>\n";
		if (isset($tmp)){
			foreach(array_keys($tmp) as $val){
				if ($val == '')
					continue;
				$key = $rev_attrmap["$val"];
				if ($key == ''){
					$key = $val;
					$attrmap["$key"] = $val;
					$attr_type["$key"] = 'replyItem';
					$rev_attrmap["$val"] = $key;
				}
				$item_vals["$key"] = $tmp[$val];
				$item_vals["$key"][count] = $tmp[$val][count];
				if ($use_op)
					$item_vals["$key"][operator] = $tmp[$val][operator];
			}
		}

	}
	else
		echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";
?>
