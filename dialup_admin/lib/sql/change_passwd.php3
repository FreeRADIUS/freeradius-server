<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
if ($config[sql_use_operator] == 'true'){
	$text1 = ',op';
	$text2  = ",':='";
	$text3 = "AND op = ':='";
}
$link = @da_sql_pconnect($config);
if ($link){
	if (is_file("../lib/crypt/$config[general_encryption_method].php3")){
		include("../lib/crypt/$config[general_encryption_method].php3");
		$passwd = da_encrypt($passwd);
		$res = @da_sql_query($link,$config,
			"SELECT Value FROM $config[sql_check_table] WHERE UserName = '$login'
			AND Attribute = '$config[sql_password_attribute]';");
		if ($res){
			$row = @da_sql_fetch_array($res,$config);
			if ($row){
				$res = @da_sql_query($link,$config,
				"UPDATE $config[sql_check_table] SET Value = '$passwd' $text3 WHERE
				Attribute = '$config[sql_password_attribute]' AND UserName = '$login';");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Error while changing password</b><br>\n";	
			}
			else{
				$res = @da_sql_query($link,$config,
					"INSERT INTO $config[sql_check_table] (Attribute,Value,UserName $text1)
					VALUES ('$config[sql_password_attribute]','$passwd','$login' $text2);");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Error while changing password</b><br>\n";
			}
		}
		else
			echo "<b>Error while executing query</b><br>\n";
	}
	else
		echo "<b>Could not open encryption library file</b><br>\n";
}
else
	echo "<b>Could not connect to database</b><br>\n";
?>
