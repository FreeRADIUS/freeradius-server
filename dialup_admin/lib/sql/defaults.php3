<?php
if ($login != ''){
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
	unset($item_vals);
	unset($tmp);
	$link = @da_sql_pconnect($config);
	if ($link){
		$res = @da_sql_query($link,$config,
		"SELECT GroupName FROM $config[sql_usergroup_table] WHERE UserName = '$login';");
		if ($res){
			while(($row = @da_sql_fetch_array($res,$config)))
				$member_groups[] = $row[GroupName];
		}
		if (isset($member_groups)){
			foreach ($member_groups as $group){
				$res = @da_sql_query($link,$config,
				"SELECT Attribute,Value $op FROM $config[sql_groupcheck_table]
				WHERE GroupName = '$group';");
				if ($res){
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
					"SELECT Attribute,Value $op FROM $config[sql_groupreply_table]
					WHERE GroupName = '$group';");
					if ($res){
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
				}
				else
					echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
				foreach($attrmap as $key => $val){
					if (isset($tmp[$val])){
						if ($use_op)
							$default_vals["$key"][operator] = $tmp["$val"][operator];
						if ($tmp[$val][0] != '')
							$default_vals["$key"] = $tmp["$val"];
					}
				}
			}
		}
	}
	else
		echo "<b>Could not connect to database</b><br>\n";
}
?>
