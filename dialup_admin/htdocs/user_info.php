<?php
require('../conf/config.php');
?>

<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=<?php echo $config[general_charset]?>">
<title>Personal information page</title>
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
include("../html/user_toolbar.html.php");
?>
</table>

<?php
if ($change == 1){
	if (is_file("../lib/$config[general_lib_type]/user_info.php"))
		include("../lib/$config[general_lib_type]/user_info.php");
	if (is_file("../lib/$config[general_lib_type]/change_info.php"))
		include("../lib/$config[general_lib_type]/change_info.php");
}

if (is_file("../lib/$config[general_lib_type]/user_info.php"))
	include("../lib/$config[general_lib_type]/user_info.php");
?>

<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Personal information for <?php echo "$login ($cn)"?></font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>

   <form method=post>
      <input type=hidden name=login value="<?php echo $login?>">
      <input type=hidden name=change value="0">
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
<?php
	echo <<<EOM
	<tr>
		<td align=right bgcolor="#d0ddb0">
		Name (First Name Surname)
		</td><td>
		<input type=text name="Fcn" value="$cn" size=35>
		</td>
	</tr>
	<tr>
		<td align=right bgcolor="#d0ddb0">
		Mail
		</td><td>
		<input type=text name="Fmail" value="$mail" size=35>
		</td>
	</tr>
	<tr>
		<td align=right bgcolor="#d0ddb0">
		Department
		</td><td>
		<input type=text name="Fou" value="$ou" size=35>
		</td>
	</tr>
	<tr>
		<td align=right bgcolor="#d0ddb0">
		Home Phone
		</td><td>
		<input type=text name="Fhomephone" value="$homephone" size=35>
		</td>
	</tr>
	<tr>
		<td align=right bgcolor="#d0ddb0">
		Work Phone
		</td><td>
		<input type=text name="Ftelephonenumber" value="$telephonenumber" size=35>
		</td>
	</tr>
	<tr>
		<td align=right bgcolor="#d0ddb0">
		Mobile Phone
		</td><td>
		<input type=text name="Fmobile" value="$mobile" size=35>
		</td>
	</tr>
EOM;
?>
	</table>
<br>
<input type=submit class=button value="Change" OnClick="this.form.change.value=1">
</form>
	</td></tr>
</table>
</tr>
</table>
</body>
</html>
