<?php
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}
if ($config[sql_use_operators] == 'true'){
	$text1 = ',op';
	$text2  = ",':='";
	$text3 = ", op = ':='";
}
else{
	$text1 = '';
	$text2 = '';
	$text3 = '';
}
$link = @da_sql_pconnect($config);
if ($link){
	if (is_file("../lib/crypt/$config[general_encryption_method].php")){
		include("../lib/crypt/$config[general_encryption_method].php");
		$passwd = da_encrypt($passwd);
		$passwd = da_sql_escape_string($passwd);
		$res = @da_sql_query($link,$config,
			"SELECT value FROM $config[sql_check_table] WHERE username = '$login'
			AND attribute = '$config[sql_password_attribute]';");
		if ($res){
			$row = @da_sql_fetch_array($res,$config);
			if ($row){
				$res = @da_sql_query($link,$config,
				"UPDATE $config[sql_check_table] SET value = '$passwd' $text3 WHERE
				attribute = '$config[sql_password_attribute]' AND username = '$login';");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Error while changing password: " . da_sql_error($link,$config) . "</b><br>\n";
			}
			else{
				$res = @da_sql_query($link,$config,
					"INSERT INTO $config[sql_check_table] (attribute,value,username $text1)
					VALUES ('$config[sql_password_attribute]','$passwd','$login' $text2);");
				if (!$res || !@da_sql_affected_rows($link,$res,$config))
					echo "<b>Error while changing password: " . da_sql_error($link,$config) . "</b><br>\n";
			}
		}
		else
			echo "<b>Error while executing query: " . da_sql_error($link,$config) . "</b><br>\n";
	}
	else
		echo "<b>Could not open encryption library file</b><br>\n";
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";
?>
