<?php
require('../lib/sql/attrmap.php3');
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
$user_exists = 'no';
$link = @da_sql_pconnect($config);
if ($link){
	$res = @da_sql_query($link,$config,
	"SELECT Attribute,Value FROM $config[sql_check_table] WHERE UserName = '$login';");
	if ($res){
		if (@da_sql_num_rows($res,$config))
			$user_exists = 'yes';
		while(($row = @da_sql_fetch_array($res,$config))){
			$attr = $row[Attribute];
			$val = $row[Value];
			$tmp["$attr"][]="$val";
			$tmp["$attr"][count]++;
		}
		$res = @da_sql_query($link,$config,
		"SELECT Attribute,Value FROM $config[sql_reply_table] WHERE UserName = '$login';");
		if ($res){
			while(($row = @da_sql_fetch_array($res,$config))){
				$attr = $row[Attribute];
				$val = $row[Value];
				$tmp["$attr"][] = "$val";
				$tmp["$attr"][count]++;
			}
			if ($config[sql_use_user_info_table] == 'true'){
				$res = @da_sql_query($link,$config,
				"SELECT * FROM $config[sql_user_info_table] WHERE UserName = '$login';");
				if ($res){
					if (($row = @da_sql_fetch_array($res,$config))){	
						$cn = ($row[Name]) ? $row[Name] : '-';
						$telephonenumber = ($row[WorkPhone]) ? $row[WorkPhone] : '-';
						$homephone = ($row[HomePhone]) ? $row[HomePhone] : '-';
						$ou = ($row[Department]) ? $row[Department] : '-';
						$mail = ($row[Mail]) ? $row[Mail] : '-';
						$mobile = ($row[Mobile]) ? $row[Mobile] : '-';
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
			}
		}

	}
	else
		echo "<b>Database query failed</b><br>\n";	
}
else
	echo "<b>Could not connect to database</b><br>\n";
?>
