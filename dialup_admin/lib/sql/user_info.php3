<?php
require('../lib/sql/attrmap.php3');
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
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

unset($item_vals);
unset($tmp);
$link = @da_sql_pconnect($config);
if ($link){
	$res = @da_sql_query($link,$config,
	"SELECT Attribute,Value $op FROM $config[sql_check_table] WHERE UserName = '$login';");
	if ($res){
		if (@da_sql_num_rows($res,$config))
			$user_exists = 'yes';
		while(($row = @da_sql_fetch_array($res,$config))){
			$attr = $row[Attribute];
			$val = $row[Value];
			if ($use_op){
				$oper = $row[op];
				$tmp["$attr"][operator][]="$oper";
			}
			$tmp["$attr"][]="$val";
			$tmp["$attr"][count]++;
		}
		$res = @da_sql_query($link,$config,
		"SELECT Attribute,Value $op FROM $config[sql_reply_table] WHERE UserName = '$login';");
		if ($res){
			if (@da_sql_num_rows($res,$config))
				$user_exists = 'yes';
			while(($row = @da_sql_fetch_array($res,$config))){
				$attr = $row[Attribute];
				$val = $row[Value];
				if ($use_op){
					$oper = $row[op];
					$tmp["$attr"][operator][]="$oper";
				}
				$tmp["$attr"][] = "$val";
				$tmp["$attr"][count]++;
			}
			if ($config[sql_use_user_info_table] == 'true'){
				$res = @da_sql_query($link,$config,
				"SELECT * FROM $config[sql_user_info_table] WHERE UserName = '$login';");
				if ($res){
					if (@da_sql_num_rows($res,$config))
						$user_exists = 'yes';
					if (($row = @da_sql_fetch_array($res,$config))){	
						$cn = ($row[Name] != '') ? $row[Name] : '-';
						$telephonenumber = ($row[WorkPhone] != '') ? $row[WorkPhone] : '-';
						$homephone = ($row[HomePhone] != '') ? $row[HomePhone] : '-';
						$ou = ($row[Department] != '') ? $row[Department] : '-';
						$mail = ($row[Mail] != '') ? $row[Mail] : '-';
						$mobile = ($row[Mobile] != '') ? $row[Mobile] : '-';
					}
				}			
			}
		}
		else
			echo "<b>Database query failed partially</b><br>\n";
		foreach($attrmap as $key => $val){
			if (isset($tmp[$val])){
				$item_vals["$key"] = $tmp[$val];
				$item_vals["$key"][count] = $tmp[$val][count];
				if ($use_op)
					$item_vals["$key"][operator] = $tmp[$val][operator];

			}
		}

	}
	else
		echo "<b>Database query failed</b><br>\n";	
}
else
	echo "<b>Could not connect to database</b><br>\n";
?>
