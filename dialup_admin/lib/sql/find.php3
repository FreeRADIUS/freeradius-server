<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}

$link = @da_sql_pconnect($config);
if ($link){
	if (($search_IN == 'name' || $search_IN == 'ou') && $config[sql_use_user_info_table] == 'true'){
		$attr = ($search_IN == 'name') ? 'Name' : 'Department';
		$res = @da_sql_query($link,$config,
		"SELECT UserName FROM $config[sql_user_info_table] WHERE
		$attr LIKE '%$search%';");
		if ($res){
			while(($row = @da_sql_fetch_array($res,$config)))
				$found_users[] = $row[UserName];
		}
		else
			"<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	}
	else if ($search_IN == 'radius' && $radius_attr != ''){
		require("../lib/sql/attrmap.php3");
		$table = ($attr_type[$radius_attr] == 'checkItem') ? $config[sql_check_table] : $config[sql_reply_table];
		$attr = $attrmap[$radius_attr];
		$res = @da_sql_query($link,$config,
		"SELECT UserName FROM $table WHERE Attribute = '$attr' AND Value LIKE '%$search%';");
		if ($res){
			while(($row = @da_sql_fetch_array($res,$config)))
				$found_users[] = $row[UserName];
		}
		else
			"<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	}
}
else
	echo "<b>Could not connect to database</b><br>\n";
?>
