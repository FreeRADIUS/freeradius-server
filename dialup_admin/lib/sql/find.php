<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}

unset($found_users);

$link = @da_sql_pconnect($config);
if ($link){
	$search = da_sql_escape_string($search);
	if (!is_numeric($max))
		$max = 10;
	if ($max > 500)
		$max = 10;
	if (($search_IN == 'name' || $search_IN == 'department' || $search_IN == 'username') &&
			$config[sql_use_user_info_table] == 'true'){
		$res = @da_sql_query($link,$config,
		"SELECT " . da_sql_limit($max,0,$config) . " username FROM $config[sql_user_info_table] WHERE
		lower($search_IN) LIKE '%$search%' " .
		da_sql_limit($max,1,$config) . " " . da_sql_limit($max,2,$config) . " ;");
		if ($res){
			while(($row = @da_sql_fetch_array($res,$config)))
				$found_users[] = $row[username];
		}
		else
			"<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	}
	else if ($search_IN == 'radius' && $radius_attr != ''){
		require("../lib/sql/attrmap.php3");
		if ($attrmap["$radius_attr"] == ''){
			$attrmap["$radius_attr"] = $radius_attr;
			$attr_type["$radius_attr"] = 'replyItem';
		}
		$table = ($attr_type[$radius_attr] == 'checkItem') ? $config[sql_check_table] : $config[sql_reply_table];
		$attr = $attrmap[$radius_attr];
		$attr = da_sql_escape_string($attr);
		$res = @da_sql_query($link,$config,
		"SELECT " . da_sql_limit($max,0,$config) . " username FROM $table WHERE attribute = '$attr'
		AND value LIKE '%$search%' " . da_sql_limit($max,1,$config) . " " . da_sql_limit($max,2,$config) . " ;");
		if ($res){
			while(($row = @da_sql_fetch_array($res,$config)))
				$found_users[] = $row[username];
		}
		else
			"<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	}
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";
?>
