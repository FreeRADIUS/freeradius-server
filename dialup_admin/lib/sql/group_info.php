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
$group_exists = 'no';
$link = @da_sql_pconnect($config);
if ($link){
	if ($login == ''){
		unset($existing_groups);

		$res = @da_sql_query($link,$config,
		"SELECT COUNT(*) as counter,groupname FROM $config[sql_usergroup_table]
		GROUP BY groupname;");
		if ($res){
			while(($row = @da_sql_fetch_array($res,$config))){
				$name = $row[groupname];
				$existing_groups["$name"] = $row[counter];
			}
			if (isset($existing_groups))
				ksort($existing_groups);
		}
		else
			echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	}
	else{
		unset($item_vals);
		unset($tmp);
		unset($group_members);
		unset($existing_groups);

		$res = @da_sql_query($link,$config,
		"SELECT attribute,value $op FROM $config[sql_groupcheck_table] WHERE groupname = '$login';");
		if ($res){
			if (@da_sql_num_rows($res,$config))
				$group_exists = 'yes';
			while(($row = @da_sql_fetch_array($res,$config))){
				$attr = $row[attribute];
				$val = $row[value];
				if ($use_op){
					$oper = $row[op];
					$tmp["$attr"][operator][]="$oper";
				}
				$tmp["$attr"][]="$val";
				$tmp["$attr"][count]++;
			}
			$res = @da_sql_query($link,$config,
			"SELECT attribute,value $op FROM $config[sql_groupreply_table] WHERE groupname = '$login';");
			if ($res){
				if (@da_sql_num_rows($res,$config))
					$group_exists = 'yes';
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
			}
			else
				echo "<b>Database query failed partially: " . da_sql_error($link,$config) . "</b><br>\n";
			$res = @da_sql_query($link,$config,
			"SELECT username FROM $config[sql_usergroup_table] WHERE groupname = '$login' ORDER BY username;");
			if ($res){
				if (@da_sql_num_rows($res,$config))
					$group_exists = 'yes';
				while(($row = @da_sql_fetch_array($res,$config))){
					$member = $row[username];
					$group_members[] = "$member";
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
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";
?>
