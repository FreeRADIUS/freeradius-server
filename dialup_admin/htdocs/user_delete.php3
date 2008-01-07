<?php
require('../conf/config.php3');
if ($type != 'group')
	if (is_file("../lib/$config[general_lib_type]/user_info.php3"))
		include("../lib/$config[general_lib_type]/user_info.php3");
else
	if (is_file("../lib/$config[general_lib_type]/group_info.php3"))
		include("../lib/$config[general_lib_type]/group_info.php3");

$whatis = ($user_type == 'group') ? 'group' : 'user';
$whatisL = ($user_type == 'group') ? 'Group' : 'User';

echo <<<EOM
<html>
<head>
EOM;

if ($user_type != 'group')
	echo "<title>delete user $login ($cn)</title>\n";
else
	echo "<title>delete group $login</title>\n";

echo <<<EOM
<meta http-equiv="Content-Type" content="text/html; charset=$config[general_charset]">
<link rel="stylesheet" href="style.css">
</head>
<body>
<center>
<table border=0 width=550 cellpadding=0 cellspacing=0>
<tr valign=top>
<td align=center><img src="images/title2.gif"></td>
</tr>
</table>

<table border=0 width=400 cellpadding=0 cellspacing=2>
EOM;

if ($user_type != 'group')
	include("../html/user_toolbar.html.php3");
else
	include("../html/group_toolbar.html.php3");

print <<<EOM
</table>

<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">$whatisL $login Deletion</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
EOM;

if ($delete_user == 1){
	if ($user_type != 'group'){
		if (is_file("../lib/$config[general_lib_type]/delete_user.php3"))
			include("../lib/$config[general_lib_type]/delete_user.php3");
	}
	else{
		if (is_file("../lib/$config[general_lib_type]/delete_group.php3"))
			include("../lib/$config[general_lib_type]/delete_group.php3");
	}
	echo <<<EOM
</td></tr>
</table>
</tr>
</table>
</body>
</html>
EOM;
	exit();
}
?>
   <form method=post>
      <input type=hidden name=login value="<?php print $login ?>">
      <input type=hidden name=delete_user value="0">
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
<tr>
<td align=center>
Are you sure you want to delete <?php echo "$whatis $login"; ?> ?
</td>
</tr>
	</table>
<br>
<input type=submit class=button value="Yes Delete" OnClick="this.form.delete_user.value=1">
</form>
</td></tr>
</table>
</tr>
</table>
</body>
</html>
