<?php
require('../conf/config.php3');
require('../lib/attrshow.php3');
require('../lib/defaults.php3');
if (is_file("../lib/$config[general_lib_type]/user_info.php3"))
	include("../lib/$config[general_lib_type]/user_info.php3");
if ($config[general_lib_type] == 'sql' && $config[sql_use_operators] == 'true'){
	$colspan=2;
	$show_ops = 1;
	include("../lib/operators.php3");
}
else{
	$show_ops = 0;
	$colspan=1;
}


echo <<<EOM
<html>
<head>
<title>subscription configuration for $login ($cn)</title>
<link rel="stylesheet" href="style.css">
</head>
<body bgcolor="#80a040" background="images/greenlines1.gif" link="black" alink="black">
EOM;

include("password_generator.jsc");

echo <<<EOM
<center>
<table border=0 width=550 cellpadding=0 cellspacing=0>
<tr valign=top>
<td align=center><img src="images/title2.gif"></td>
</tr>
</table>

<table border=0 width=400 cellpadding=0 cellspacing=2>
EOM;

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
	<font color="white">User Preferences for $login ($cn)</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
EOM;
   
if ($change == 1){
	if (is_file("../lib/$config[general_lib_type]/change_attrs.php3"))
		include("../lib/$config[general_lib_type]/change_attrs.php3");
	if ($passwd != '' && is_file("../lib/$config[general_lib_type]/change_passwd.php3"))
		include("../lib/$config[general_lib_type]/change_passwd.php3");
	if (is_file("../lib/$config[general_lib_type]/user_info.php3"))
		include("../lib/$config[general_lib_type]/user_info.php3");
}
else if ($badusers == 1){
	if (is_file("../lib/add_badusers.php3"))
		include("../lib/add_badusers.php3");
}
	
?>
   <form method=post>
      <input type=hidden name=login value=<?php print $login ?>>
      <input type=hidden name=change value="0">
      <input type=hidden name=add value="0">
      <input type=hidden name=badusers value="0">
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
<tr>
<td align=right colspan=<?php print $colspan ?> bgcolor="#d0ddb0">
User Password (changes only)
</td>
<td>
<input type=password name=passwd value="" size=40>
</td>
</tr>
<?php
	foreach($show_attrs as $key => $desc){
		$name = $attrmap["$key"];
		if ($name == 'none')
			continue;
		unset($vals);
		unset($selected);
		unset($ops);
		if ($item_vals["$key"][count]){
			for($i=0;$i<$item_vals["$key"][count];$i++){
				$vals[] = $item_vals["$key"][$i];
				$ops[] = $item_vals["$key"][operator][$i];
			}
		}
		else{
			$vals[] = $default_vals["$key"];
			$ops[] = '=';
		}
		if ($add && $name == $add_attr){
			array_push($vals, $default_vals["$key"]);
			array_push($ops, '=');
		}

		$i = 0;
		foreach($vals as $val){
			$name1 = $name . $i;
			$oper_name = $name1 . '_op';
			$oper = $ops[$i];
			$selected[$oper] = 'selected';
			$i++;
			print <<<EOM
<tr>
<td align=right bgcolor="#d0ddb0">
EOM;
			if ($i == 1)
				echo "$desc\n";
			else
				echo "$desc ($i)\n";
			print <<<EOM
</td>
EOM;
			if ($show_ops)
				print <<<EOM
<td>
<select name=$oper_name>
<option $selected[$op_eq] value="=">=
<option $selected[$op_set] value=":=">:=
<option $selected[$op_add] value="+=">+=
<option $selected[$op_eq2] value="==">==
<option $selected[$op_ne] value="!=">!=
<option $selected[$op_gt] value=">">&gt;
<option $selected[$op_ge] value=">=">&gt;=
<option $selected[$op_lt] value="<">&lt;
<option $selected[$op_le] value="<=">&lt;=
<option $selected[$op_regeq] value="=~">=~
<option $selected[$op_regne] value="!~">!~
</select>
</td>
EOM;

			print <<<EOM
<td>
<input type=text name="$name1" value="$val" size=40>
</td>
</tr>
EOM;
		}
	}
?>
<tr>
<td align=right colspan=<?php print $colspan ?> bgcolor="#d0ddb0">
Add Attribute
</td>
<td>
<select name="add_attr" OnChange="this.form.add.value=1;this.form.submit()">
<?php
foreach ($show_attrs as $key => $desc){
	$name = $attrmap["$key"];
	print <<<EOM
<option value="$name">$desc
EOM;
}
?>
</select>
</td>
</tr>
	</table>
<br>
<input type=submit class=button value=Change OnClick="this.form.change.value=1">
<br><br>
<input type=submit class=button value="Add to Badusers" OnClick="this.form.badusers.value=1">
<br><br>
<input type="button" class=button value="Auto/Password" OnClick="generatepassword(this.form.passwd,8);">
</form>
	</td></tr>
</table>
</tr>
</table>
</body>
</html>
