<?php
require('../conf/config.php');
if ($show == 1){
	header("Location: user_admin.php?login=$login");
	exit;
}
require('../lib/attrshow.php');
require('../lib/defaults.php');

if ($config[general_lib_type] == 'sql' && $config[sql_use_operators] == 'true'){
	$colspan=2;
	$show_ops=1;
}else{
	$show_ops = 0;
	$colspan=1;
}

?>

<html>
<head>
<title>New user creation page</title>
<meta http-equiv="Content-Type" content="text/html; charset=<?php echo $config[general_charset]?>">
<link rel="stylesheet" href="style.css">
</head>
<body>

<?php
include("password_generator.jsc");
?>

<center>
<table border=0 width=550 cellpadding=0 cellspacing=0>
<tr valign=top>
<td align=center><img src="images/title2.gif"></td>
</tr>
</table>

<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">User Preferences for new user</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>

<?php
if ($create == 1){
	if (is_file("../lib/$config[general_lib_type]/user_info.php"))
		include("../lib/$config[general_lib_type]/user_info.php");
	if ($user_exists != "no"){
		echo <<<EOM
<b>The username <i>$login</i> already exists in the user database</b>
EOM;
	}
	else{
		if (is_file("../lib/$config[general_lib_type]/create_user.php"))
			include("../lib/$config[general_lib_type]/create_user.php");
		require("../lib/defaults.php");
		if (is_file("../lib/$config[general_lib_type]/user_info.php"))
			include("../lib/$config[general_lib_type]/user_info.php");
	}
}
?>
   <form method=post>
      <input type=hidden name=create value="0">
      <input type=hidden name=show value="0">
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
<?php
	echo <<<EOM
	<tr>
		<td align=right colspan=$colspan bgcolor="#d0ddb0">
		Username
		</td><td>
		<input type=text name="login" value="$login" size=35>
		</td>
	</tr>
	<tr>
		<td align=right colspan=$colspan bgcolor="#d0ddb0">
		Password
		</td><td>
		<input type=text name="passwd" size=35>
		</td>
	</tr>
EOM;
	if ($config[general_lib_type] == 'sql'){
		if (isset($member_groups))
			$selected[$member_groups[0]] = 'selected';
		echo <<<EOM
	<tr>
		<td align=right colspan=$colspan bgcolor="#d0ddb0">
		Group
		</td><td>
		<select name="Fgroup">
EOM;
		foreach ($member_groups as $group)
			echo "<option value=\"$group\" $selected[$group]>$group\n";

		echo <<<EOM
		</select>
		</td>
	</tr>
EOM;
	}
	if ($config[general_lib_type] == 'ldap' ||
	($config[general_lib_type] == 'sql' && $config[sql_use_user_info_table] == 'true')){
		echo <<<EOM
	<tr>
		<td align=right colspan=$colspan bgcolor="#d0ddb0">
		Name (First Name Surname)
		</td><td>
		<input type=text name="Fcn" value="$cn" size=35>
		</td>
	</tr>
	<tr>
		<td align=right colspan=$colspan bgcolor="#d0ddb0">
		Mail
		</td><td>
		<input type=text name="Fmail" value="$mail" size=35>
		</td>
	</tr>
	<tr>
		<td align=right colspan=$colspan bgcolor="#d0ddb0">
		Department
		</td><td>
		<input type=text name="Fou" value="$ou" size=35>
		</td>
	</tr>
	<tr>
		<td align=right colspan=$colspan bgcolor="#d0ddb0">
		Home Phone
		</td><td>
		<input type=text name="Fhomephone" value="$homephone" size=35>
		</td>
	</tr>
	<tr>
		<td align=right colspan=$colspan bgcolor="#d0ddb0">
		Work Phone
		</td><td>
		<input type=text name="Ftelephonenumber" value="$telephonenumber" size=35>
		</td>
	</tr>
	<tr>
		<td align=right colspan=$colspan bgcolor="#d0ddb0">
		Mobile Phone
		</td><td>
		<input type=text name="Fmobile" value="$mobile" size=35>
		</td>
	</tr>
EOM;
	}
	foreach($show_attrs as $key => $desc){
		$name = $attrmap["$key"];
		if ($name == 'none')
			continue;
		$oper_name = $name . '_op';
		$val = ($item_vals["$key"][0] != "") ? $item_vals["$key"][0] : $default_vals["$key"][0];
		print <<<EOM
<tr>
<td align=right bgcolor="#d0ddb0">
$desc
</td>
EOM;

		if ($show_ops)
			print <<<EOM
<td>
<select name=$oper_name>
<option selected value="=">=
<option value=":=">:=
<option value="+=">+=
<option value="==">==
<option value="!=">!=
<option value=">">&gt;
<option value=">=">&gt;=
<option value="<">&lt;
<option value="<=">&lt;=
<option value="=~">=~
<option value="!~">!~

</select>
</td>
EOM;

		print <<<EOM
<td>
<input type=text name="$name" value="$val" size=35>
</td>
</tr>
EOM;
	}
?>
	</table>
<br>
<input type=submit class=button value="Create" OnClick="this.form.create.value=1">
<br><br>
<input type=submit class=button value="Show User" OnClick="this.form.show.value=1">
<br><br>
<input type="button" class=button value="Auto/Password" OnClick="generatepassword(this.form.passwd,8);">
</form>
	</td></tr>
</table>
</tr>
</table>
</body>
</html>
