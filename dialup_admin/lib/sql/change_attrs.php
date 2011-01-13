<?php
require_once('../lib/functions.php');
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php"))
        include_once("../lib/sql/drivers/$config[sql_type]/functions.php");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
if ($config[sql_use_operators] == 'true'){
	$use_ops=1;
	$text1 = 'AND op =';
	$text2 = ',op';
}
$link = @da_sql_pconnect($config);
if ($link){
	foreach($show_attrs as $key => $desc){
		if ($attrmap["$key"] == 'none')
			continue;
		if ($attrmap["$key"] == ''){
			$attrmap["$key"] = $key;
			$attr_type["key"] = 'replyItem';
			$rev_attrmap["$key"] = $key;
		}
		$i = 0;
		$j = -1;
		$name = $attrmap["$key"] . $i;

		while(isset($$name)){
			$val=$$name;
			$val = da_sql_escape_string($val);
			$op_name = $name . '_op';
			$i++;
			$j++;
			$name = $attrmap["$key"] . $i;

			$sql_attr=$attrmap["$key"];
			$query_key = ($user_type == 'group') ? 'groupname' : 'username';
			if ($attr_type["$key"] == 'checkItem'){
				$table = ($user_type == 'group') ? $config[sql_groupcheck_table] : $config[sql_check_table];
				$type = 1;
			}
			else if ($attr_type["$key"] == 'replyItem'){
				$table = ($user_type == 'group') ? $config[sql_groupreply_table] : $config[sql_reply_table];
				$type = 2;
			}
			if ($use_ops){
				$op_val = $$op_name;
				if ($op_val != ''){
					$op_val = da_sql_escape_string($op_val);
					if (check_operator($op_val,$type) == -1){
						echo "<b>Invalid operator ($op_val) for attribute $key</b><br>\n";
						continue;
					}
					$op_val2 = ",'$op_val'";
				}
			}
			$sql_attr = da_sql_escape_string($sql_attr);
			$val = da_sql_escape_string($val);
	// if we have operators, the operator has changed and the corresponding value exists then update
			if ($use_ops && isset($item_vals["$key"][operator][$j]) &&
				$op_val != $item_vals["$key"][operator][$j] ){
				$res = @da_sql_query($link,$config,
				"UPDATE $table SET op = '$op_val' WHERE $query_key = '$login'
				AND attribute = '$sql_attr' AND value = '$val';");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Operator change failed for attribute $key: " . da_sql_error($link,$config) . "</b><br>\n";
			}

	// 	if value is the same as that in the sql database do nothing
			if ($val == $item_vals["$key"][$j])
				continue;
	//	if value is null or equals the default value and corresponding value exists then delete
			else if ((check_defaults($val,$op_val,$default_vals["$key"]) || $val == '') && isset($item_vals["$key"][$j])){
				$res = @da_sql_query($link,$config,
				"DELETE FROM $table WHERE $query_key = '$login' AND attribute = '$sql_attr';");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Delete failed for attribute $key: " . da_sql_error($link,$config) . "</b><br>\n";
			}
	//	if value is null or equals the default value then don't add it
			else if ($val == '' || check_defaults($val,$op_val,$default_vals["$key"]))
				continue;
	//	if value differs from the sql value then update
			else{
				if (isset($item_vals["$key"][$j])){
					$old_val = $item_vals["$key"][$j];
					$old_val = da_sql_escape_string($old_val);
					$res = @da_sql_query($link,$config,
					"UPDATE $table SET value = '$val' WHERE $query_key = '$login' AND
					attribute = '$sql_attr' AND value = '$old_val';");
				}
				else
					$res = @da_sql_query($link,$config,
					"INSERT INTO $table ($query_key,attribute,value $text2)
					VALUES ('$login','$sql_attr','$val' $op_val2);");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Change failed for attribute $key: " . da_sql_error($link,$config) . "</b><br>\n";
			}
		}
	}
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";
