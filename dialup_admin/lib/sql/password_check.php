<?php
require('password.php');
if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php");
else{
	echo "<b>Could not include SQL library</b><br>\n";
	exit();
}

if ($action == 'checkpass'){
	$link = @da_sql_pconnect($config);
	if ($link){
		$res = @da_sql_query($link,$config,
			"SELECT attribute,value FROM $config[sql_check_table] WHERE username = '$login'
			AND attribute = '$config[sql_password_attribute]';");
		if ($res){
			$row = @da_sql_fetch_array($res,$config);
			if (is_file("../lib/crypt/$config[general_encryption_method].php")){
				include("../lib/crypt/$config[general_encryption_method].php");
				$enc_passwd = $row[value];
				$passwd = da_encrypt($passwd,$enc_passwd);
				if ($passwd == $enc_passwd)
					$msg = '<font color=blue><b>YES It is that</b></font>';
				else
					$msg = '<font color=red><b>NO It is wrong</b></font>';
			}
			else
				echo "<b>Could not open encryption library file</b><br>\n";
		}
	}
	echo "<tr><td colspan=3 align=center>$msg</td></tr>\n";
}
?>
</form>
