<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
include_once('../lib/functions.php');
if ($config[sql_use_operators] == 'true'){
	include("../lib/operators.php");
	$text = ',op';
	$passwd_op = ",':='";
}
$da_abort=0;
$op_val2 = '';
$link = @da_sql_pconnect($config);
if ($link){
	if (is_file("../lib/crypt/$config[general_encryption_method].php")){
		include("../lib/crypt/$config[general_encryption_method].php");
		$passwd = da_encrypt($passwd);
		$passwd = da_sql_escape_string($passwd);
		$res = @da_sql_query($link,$config,
		"INSERT INTO $config[sql_check_table] (attribute,value,username $text)
		VALUES ('$config[sql_password_attribute]','$passwd','$login' $passwd_op);");
		if (!$res || !@da_sql_affected_rows($link,$res,$config)){
			echo "<b>Unable to add user $login: " . da_sql_error($link,$config) . "</b><br>\n";
			$da_abort=1;
		}
		if ($config[sql_use_user_info_table] == 'true' && !$da_abort){
			$res = @da_sql_query($link,$config,
			"SELECT username FROM $config[sql_user_info_table] WHERE
			username = '$login';");
			if ($res){
				if (!@da_sql_num_rows($res,$config)){
					$Fcn = da_sql_escape_string($Fcn);
					$Fmail = da_sql_escape_string($Fmail);
					$Fou = da_sql_escape_string($Fou);
					$Fhomephone = da_sql_escape_string($Fhomephone);
					$Fworkphone = da_sql_escape_string($Fworkphone);
					$Fmobile = da_sql_escape_string($Fmobile);
					$res = @da_sql_query($link,$config,
					"INSERT INTO $config[sql_user_info_table]
					(username,name,mail,department,homephone,workphone,mobile) VALUES
					('$login','$Fcn','$Fmail','$Fou','$Fhomephone','$Ftelephonenumber','$Fmobile');");
					if (!$res || !@da_sql_affected_rows($link,$res,$config))
						echo "<b>Could not add user information in user info table: " . da_sql_error($link,$config) . "</b><br>\n";
				}
				else
					echo "<b>User already exists in user info table.</b><br>\n";
			}
			else
				echo "<b>Could not add user information in user info table: " . da_sql_error($link,$config) . "</b><br>\n";
		}
		if ($Fgroup != ''){
			$Fgroup = da_sql_escape_string($Fgroup);
			$res = @da_sql_query($link,$config,
			"SELECT username FROM $config[sql_usergroup_table]
			WHERE username = '$login' AND groupname = '$Fgroup';");
			if ($res){
				if (!@da_sql_num_rows($res,$config)){
					$res = @da_sql_query($link,$config,
					"INSERT INTO $config[sql_usergroup_table]
					(username,groupname) VALUES ('$login','$Fgroup');");
					if (!$res || !@da_sql_affected_rows($link,$res,$config))
						echo "<b>Could not add user to group $Fgroup. SQL Error</b><br>\n";
				}
				else
					echo "<b>User already is a member of group $Fgroup</b><br>\n";
			}
			else
				echo "<b>Could not add user to group $Fgroup: " . da_sql_error($link,$config) . "</b><br>\n";
		}
		if (!$da_abort){
			if ($Fgroup != '')
				require('../lib/defaults.php');
			foreach($show_attrs as $key => $attr){
				if ($attrmap["$key"] == 'none')
					continue;
				if ($attrmap["$key"] == ''){
					$attrmap["$key"] = $key;
					$attr_type["$key"] = 'replyItem';
					$rev_attrmap["$key"] = $key;
				}
				if ($attr_type["$key"] == 'checkItem'){
					$table = "$config[sql_check_table]";
					$type = 1;
				}
				else if ($attr_type["$key"] == 'replyItem'){
					$table = "$config[sql_reply_table]";
					$type = 2;
				}
				$val = $$attrmap["$key"];
				$val = da_sql_escape_string($val);
				$op_name = $attrmap["$key"] . '_op';
				$op_val = $$op_name;
				if ($op_val != ''){
					$op_val = da_sql_escape_string($op_val);
					if (check_operator($op_val,$type) == -1){
						echo "<b>Invalid operator ($op_val) for attribute $key</b><br>\n";
						coninue;
					}
					$op_val2 = ",'$op_val'";
				}
				if ($val == '' || check_defaults($val,$op_val,$default_vals["$key"]))
					continue;
				$res = @da_sql_query($link,$config,
				"INSERT INTO $table (attribute,value,username $text)
				VALUES ('$attrmap[$key]','$val','$login' $op_val2);");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Query failed for attribute $key: " . da_sql_error($link,$config) . "</b><br>\n";
			}
		}
		echo "<b>User created successfully</b><br>\n";
	}
	else
		echo "<b>Could not open encryption library file</b><br>\n";
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";
?>
