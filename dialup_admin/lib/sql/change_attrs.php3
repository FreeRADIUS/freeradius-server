<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
        include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
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
		$i = 0;
		$j = -1;
		$name = $attrmap["$key"] . $i;

		while(isset($$name)){
			$val=$$name;
			$op_name = $name . '_op';
			$op_val = $$op_name;
			if ($op_val != ''){
				$op_val1 = "'$op_val'";
				$op_val2 = ",'$op_val'";
			}
			$i++;
			$j++;
			$name = $attrmap["$key"] . $i;

			$sql_attr=$attrmap["$key"];
			if ($attr_type["$key"] == 'checkItem')
				$table = $config[sql_check_table];
			else if ($attr_type["$key"] == 'replyItem')
				$table = $config[sql_reply_table];
	// if we have operators the operator has changed and the corresponding value exists then update
			if ($use_ops && isset($item_vals["$key"][operator][$j]) &&
				$op_val != $item_vals["$key"][operator][$j] ){
				$res = @da_sql_query($link,$config,
				"UPDATE $table SET op = '$op_val' WHERE UserName = '$login'
				AND Attribute = '$sql_attr' AND Value = '$val';");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Operator change failed for attribute $key</b><br>\n";
			}

	// 	if value is the same as that in the sql database do nothing
			if ($val == $item_vals["$key"][$j])
				continue;
	//	if value is null and corresponding value exists then delete
			else if (($val == $default_vals["$key"] || $val == '') && isset($item_vals["$key"][$j])){
				$res = @da_sql_query($link,$config,
				"DELETE FROM $table WHERE UserName = '$login' AND Attribute = '$sql_attr';");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Delete failed for attribute $key</b><br>\n";
			}
	//	if value is null then don't add it 
			else if ($val == '')
				continue;
	//	if value differs from the sql value then update
			else{
				if (isset($item_vals["$key"][$j])){
					$old_val = $item_vals["$key"][$j];
					$res = @da_sql_query($link,$config,
					"UPDATE $table SET Value = '$val' WHERE UserName = '$login' AND
					Attribute = '$sql_attr' AND Value = '$old_val';");
				}
				else
					$res = @da_sql_query($link,$config,
					"INSERT INTO $table (UserName,Attribute,Value $text2)
					VALUES ('$login','$sql_attr','$val' $op_val2);");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Change failed for attribute $key</b><br>\n";	
			}
		}
	}
}
else
	echo "<b>Could not connect to database</b><br>\n";
