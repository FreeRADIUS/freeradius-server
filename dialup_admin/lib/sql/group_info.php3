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
unset($item_vals);
unset($tmp);
unset($group_members);
$link = @da_sql_pconnect($config);
if ($link){
	$res = @da_sql_query($link,$config,
	"SELECT Attribute,Value $op FROM $config[sql_groupcheck_table] WHERE GroupName = '$login';");
	if ($res){
		if (@da_sql_num_rows($res,$config))
			$group_exists = 'yes';
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
		"SELECT Attribute,Value $op FROM $config[sql_groupreply_table] WHERE GroupName = '$login';");
		if ($res){
			if (@da_sql_num_rows($res,$config))
				$group_exists = 'yes';
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
		}
		else
			echo "<b>Database query failed partially: " . da_sql_error($link,$config) . "</b><br>\n";
		$res = @da_sql_query($link,$config,
		"SELECT UserName FROM $config[sql_usergroup_table] WHERE GroupName = '$login' ORDER BY UserName;");
		if ($res){
			if (@da_sql_num_rows($res,$config))
				$group_exists = 'yes';
			while(($row = @da_sql_fetch_array($res,$config))){
				$member = $row[UserName];
				$group_members[] = "$member";
			}
		}	
		else
			echo "<b>Database query failed partially: " . da_sql_error($link,$config) . "</b><br>\n";
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
		echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
}
else
	echo "<b>Could not connect to database</b><br>\n";
?>
