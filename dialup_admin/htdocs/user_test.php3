<?php
require('../conf/config.php3');
if (is_file("../lib/$config[general_lib_type]/user_info.php3"))
	include("../lib/$config[general_lib_type]/user_info.php3");

if ($login == 'da_server_test'){
	$login = $config[general_test_account_login];
	$test_login=1;
}

echo <<<EOM
<html>
<head>
<title>test user $login ($cn)</title>
<link rel="stylesheet" href="style.css">
</head>
<body bgcolor="#80a040" background="images/greenlines1.gif" link="black" alink="black">
<center>
<table border=0 width=550 cellpadding=0 cellspacing=0>
<tr valign=top>
<td align=center><img src="images/title2.gif"></td>
</tr>
</table>

<table border=0 width=400 cellpadding=0 cellspacing=2>
EOM;

if (!$test_login)
	include("../html/user_toolbar.html.php3");

print <<<EOM
</table>

<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
EOM;

if ($test_login){
	print <<<EOM
	<font color="white">Radius Server Test Page</font>&nbsp;
EOM;
}else{
	print <<<EOM
	<font color="white">User $login Test Page</font>&nbsp;
EOM;
}
?>
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>

<?php
if ($test_user == 1){
	if ($server == '')
		$server = $config[general_radius_server];
	if ($port == 0)
		$port = $config[general_radius_server_port];
	$tmp_file = tempnam("$config[general_tmp_dir]",'DA');
	$req=file($config[general_auth_request_file]);
	$comm = $config[general_radclient_bin] . " $server:$port" . ' auth ' . $config[general_radius_server_secret] 
		. ' >' . $tmp_file;
	$fp = popen("$comm","w");
	if ($fp){
		foreach ($req as $val){
			fwrite($fp,$val);
		}
		if ($test_login){
			$test=1;
			fwrite($fp, "User-Name = \"$config[general_test_account_login]\"\n");
			fwrite($fp, "Password = \"$config[general_test_account_password]\"\n");
			pclose($fp);
		}
		else{
			fwrite($fp, "User-Name = \"$login\"\n");
			if ($auth_proto == 'pap')
				fwrite($fp, "Password = \"$passwd\"\n");
			else if ($auth_proto == 'chap')
				fwrite($fp, "CHAP-Password = \"$passwd\"\n");
			pclose($fp);
		}
		$reply = file($tmp_file);
		unlink($tmp_file);
		if (ereg('code 2', $reply[0]))
			$msg = "<b>Authentication was <font color=green>successful</font>";
		else if (ereg('code 3',$reply[0]))
			$msg = "<b>Authentication <font color=red>failed</font>";
		else if (ereg('no response from server', $reply[0]))
			$msg = "<b><font color=red>No response from server</font>";
		else if (ereg('Connection refused',$reply[0]))
			$msg = "<b><font color=red>Connection was refused</font>";
		if ($test_login)
			$msg .= "</b><i> (test user $login)</i><br>\n";
		else
			$msg .= "</b><br>\n";
		array_shift($reply);
		if (count($reply)){
			$msg .= "<br><b>Server response:</b><br>\n";
			foreach ($reply as $val){
				$msg .= "<i>$val</i><br>\n";
			}
		}
		if ($test_login){
			print <<<EOM
$msg
<br>
</td></tr>
</table>
</tr>
</table>
</body>
</html>
EOM;
			exit();
		}

	}
}
?>
   <form method=post>
      <input type=hidden name=login value=<?php print $login ?>>
      <input type=hidden name=test_user value="0">
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
<tr>
<td align=right bgcolor="#d0ddb0">
User Password
</td>
<td>
<input type=password name=passwd value="" size=25>
</td>
</tr>
<tr>
<td align=right bgcolor="#d0ddb0">
Radius Server
</td>
<td>
<input type=text name=server value="<?php print $config[general_radius_server] ?>" size=25>
</td>
</tr>
<tr>
<td align=right bgcolor="#d0ddb0">
Radius Server Port
</td>
<td>
<input type=text name=port value="<?php print $config[general_radius_server_port] ?>" size=25>
</td>
</tr>
<tr>
<td align=right bgcolor="#d0ddb0">
Authentication Protocol
</td>
<td>
<select name="auth_proto" editable>
<option selected value="pap">PAP
<option value="chap">CHAP
</select>
</td>
</tr>

	</table>
<br>
<input type=submit class=button value="Run Test" OnClick="this.form.test_user.value=1">
</form>
<?php
if ($test_user == 1){
	echo <<<EOM
<br>
$msg
EOM;
}
?>
	</td></tr>
</table>
</tr>
</table>
</body>
</html>
