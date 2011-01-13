<?php
require('../lib/sql/attrmap.php');
if ($login != '' && $user_type != 'group'){
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
	$overwrite_defaults = 1;
	$stop = 0;
	$times = 0;
	do{
		unset($item_vals);
		unset($member_groups);
		unset($tmp);
		$times++;
		$link = @da_sql_pconnect($config);
		if ($link){
			$res = @da_sql_query($link,$config,
			"SELECT groupname FROM $config[sql_usergroup_table] WHERE username = '$login';");
			if ($res){
				while(($row = @da_sql_fetch_array($res,$config))){
					$group = $row[groupname];
					$member_groups[$group] = $group;
				}
				if (isset($member_groups))
					ksort($member_groups);
			}
			if (isset($member_groups)){
				$in = '(';
				foreach ($member_groups as $group)
					$in .= "'$group',";
				$in = substr($in,0,-1);
				$in .= ')';
				$res = @da_sql_query($link,$config,
				"SELECT attribute,value $op FROM $config[sql_groupcheck_table]
				WHERE groupname IN $in;");
				if ($res){
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
					"SELECT attribute,value $op FROM $config[sql_groupreply_table]
					WHERE groupname IN $in;");
					if ($res){
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
				}
				else
					echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
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
						if (!isset($default_vals["$key"]) || $overwrite_defaults){
							if ($use_op)
								$default_vals["$key"][operator] = $tmp["$val"][operator];
							if ($tmp[$val][0] != '')
								$default_vals["$key"] = $tmp["$val"];
						}
					}
				}
			}
			if ($times == 1){
				if ($config[sql_default_user_profile] == '')
					$stop = 1;
				else{
					$saved_login = $login;
					$saved_member_groups = $member_groups;
					$login = $config[sql_default_user_profile];
					$overwrite_defaults = 0;
				}
			}
			if ($times == 2){
				$login = $saved_login;
				$member_groups = $saved_member_groups;
				$stop = 1;
			}
		}
		else
			echo "<b>Could not connect to SQL database</b><br>\n";
	}while($stop == 0);
}
else{
	if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php"))
		include_once("../lib/sql/drivers/$config[sql_type]/functions.php");
	else{
		echo "<b>Could not include SQL library</b><br>\n";
		exit();
	}
	unset($member_groups);
	$link = @da_sql_pconnect($config);
	if ($link){
		$res = @da_sql_query($link,$config,
		"SELECT DISTINCT groupname FROM $config[sql_usergroup_table];");
		if ($res){
			while(($row = @da_sql_fetch_array($res,$config)))
				$member_groups[] = $row[groupname];
		}
		else
			echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	}
	else
		echo "<b>Could not connect to SQL database</b><br>\n";
}
?>
