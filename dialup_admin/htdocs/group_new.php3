<?php
require('../conf/config.php3');
if ($show == 1){
	header("Location: group_admin.php3?login=$login");
	exit;
}

if ($config[general_lib_type] != 'sql'){
	echo <<<EOM
<title>New group creation page</title>
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

require('../lib/attrshow.php3');
require('../lib/defaults.php3');
require("../lib/$config[general_lib_type]/group_info.php3");

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
<title>New group creation page</title>
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

<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Preferences for new group</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>

<?php
if (is_file("../lib/$config[general_lib_type]/group_info.php3"))
	include("../lib/$config[general_lib_type]/group_info.php3");
if ($create == 1){
	if ($group_exists != "no"){
		echo <<<EOM
<b>The group <i>$login</i> already exists in the group database</b>
EOM;
	}
	else{
		if (is_file("../lib/$config[general_lib_type]/create_group.php3"))
			include("../lib/$config[general_lib_type]/create_group.php3");
		if (is_file("../lib/$config[general_lib_type]/group_info.php3"))
			include("../lib/$config[general_lib_type]/group_info.php3");
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
		Available Groups
		</td><td>
EOM;
		if (!isset($existing_groups))
			echo "<b>No groups available</b>\n";
		else{
			echo "<select name=\"existing_groups\">\n";
			foreach ($existing_groups as $group => $count)
				echo "<option value=\"$group\">$group\n";
			echo "</select>\n";
		}
	echo <<<EOM
		</td>
	</tr>
	<tr>
		<td align=right colspan=$colspan bgcolor="#d0ddb0">
		Group name
		</td><td>
		<input type=text name="login" value="$login" size=35>
		</td>
	</tr>
	<tr>
		<td align=right colspan=$colspan bgcolor="#d0ddb0">
		First member(s)<br>Separate group members<br> by whitespace or newline
		</td><td>
		<textarea name=members cols="15" wrap="PHYSICAL" rows=5></textarea>
		</td>
	</tr>

EOM;
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
<input type=submit class=button value="Show Group" OnClick="this.form.show.value=1">
</form>
	</td></tr>
</table>
</tr>
</table>
</body>
</html>
