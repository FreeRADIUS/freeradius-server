<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
        include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
$link = @da_sql_pconnect($config);
if ($link){
	foreach($show_attrs as $key => $desc){
		if ($attrmap["$key"] == 'none')
			continue;
		$i = $j = 0;
		$name = $attrmap["$key"] . $i;

		while(isset($$name)){
			$val=$$name;
			$i++;
			$name = $attrmap["$key"] . $i;

			$sql_attr=$attrmap["$key"];
			if ($attr_type["$key"] == 'checkItem')
				$table = $config[sql_check_table];
			else if ($attr_type["$key"] == 'replyItem')
				$table = $config[sql_reply_table];
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
				if (isset($item_vals["$key"][$j]))
					$res = @da_sql_query($link,$config,
					"UPDATE $table SET Value = '$val' WHERE UserName = '$login' AND
					Attribute = '$sql_attr';");
				else
					$res = @da_sql_query($link,$config,
					"INSERT INTO $table (UserName,Attribute,Value)
					VALUES ('$login','$sql_attr','$val');");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Change failed for attribute $key</b><br>\n";	
			}
			$j++;
		}
	}
}
else
	echo "<b>Could not connect to database</b><br>\n";
