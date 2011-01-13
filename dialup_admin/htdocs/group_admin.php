<?php
require('../conf/config.php');
if ($show == 1 && isset($del_members)){
        header("Location: user_admin.php?login=$del_members[0]");
        exit;
}
if ($config[general_lib_type] != 'sql'){
	echo <<<EOM
<title>Group Administration Page</title>
<meta http-equiv="Content-Type" content="text/html; charset=$config[general_charset]">
<link rel="stylesheet" href="style.css">
</head>
<body>
<center>
<b>This page is only available if you are using sql as general library type</b>
</body>
</html>
EOM;
	exit();
}

unset($group_members);
if (is_file("../lib/$config[general_lib_type]/group_info.php")){
	include("../lib/$config[general_lib_type]/group_info.php");
	if ($group_exists == 'no'){
		echo <<<EOM
<title>Group Administration Page</title>
<meta http-equiv="Content-Type" content="text/html; charset=$config[general_charset]">
<link rel="stylesheet" href="style.css">
</head>
<body>
<center>
<form action="group_admin.php" method=get>
<b>Group Name&nbsp;&nbsp;</b>
<input type="text" size=10 name="login" value="$login">
<b>&nbsp;&nbsp;does not exist</b><br>
<input type=submit class=button value="Show Group">
</body>
</html>
EOM;
                exit();
        }
}
?>

<html>
<head>
<title>Group Administration Page</title>
<meta http-equiv="Content-Type" content="text/html; charset=<?php echo $config[general_charset]?>">
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

<?php
include("../html/group_toolbar.html.php");
?>

</table>
<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Group <?php echo $login ?> Administration</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>

<?php
if ($do_changes == 1){
	if (is_file("../lib/$config[general_lib_type]/group_admin.php"))
		include("../lib/$config[general_lib_type]/group_admin.php");
	if (is_file("../lib/$config[general_lib_type]/group_info.php"))
		include("../lib/$config[general_lib_type]/group_info.php");
}
?>


   <form method=post>
      <input type=hidden name=login value="<?php echo $login ?>">
      <input type=hidden name=do_changes value=0>
      <input type=hidden name=show value=0>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
<tr>
<td align=right bgcolor="#d0ddb0">
Group Members (Check to Delete)
</td>
<td>
<select name=del_members[] multiple size=5>
<?php
foreach ($group_members as $member){
	echo "<option value=\"$member\">$member\n";
}
?>
</select>
</td>
</tr>
<tr>
<td align=right bgcolor="#d0ddb0">
New Group Member(s)<br>Separate group members<br> by whitespace or newline
</td>
<td>
<textarea name=new_members cols="15" wrap="PHYSICAL" rows=5></textarea>
</td>
</tr>
	</table>
<br>
<input type=submit class=button value="Commit Changes" OnClick="this.form.do_changes.value=1">
<br><br>
<input type=submit class=button value="Administer selected user" OnClick="this.form.show.value=1">
</form>
</td></tr>
</table>
</tr>
</table>
</body>
</html>
