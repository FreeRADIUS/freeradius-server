<?php
require('../conf/config.php3');

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo <<<EOM
<title>NAS Administration Page</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<center>
<b>Could not include SQL library functions. Aborting</b>
</body>
</html>
EOM;
	exit();
}
if ($config[general_restrict_nasadmin_access] == 'yes'){
	$auth_user = $_SERVER["PHP_AUTH_USER"];
	if ($auth_user == '' || $mappings[$auth_user][nasadmin] != 'yes'){
		echo <<<EOM
<title>NAS Administration Page</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<center>
<b>Access is not allowed to this username.</b>
</body>
</html>
EOM;
		exit();
	}
}


if ($clear_fields == 1 || ($do_it == 0 && $select_nas == 0))
	$selected_nas = $readonly = '';
else
	$readonly = 'readonly';

$link = @da_sql_pconnect($config);
if ($link){
	if ($do_it == 1){
		$selected_nas = da_sql_escape_string($selected_nas);
		switch ($action) {
			case 'check_nas':
				require_once('../lib/functions.php3');
				if (!check_ip($selected_nas) && $selected_nas == gethostbyname($selected_nas))
					$msg = "<b>The NAS name <font color=red>is not</font> valid</b><br>\n";
				else
					$msg = "<b>The NAS name <font color=green>is</font> valid</b><br>\n";
				break;
			case 'del_nas':
				$res = @da_sql_query($link,$config,
				"DELETE FROM $config[sql_nas_table] WHERE nasname = '$selected_nas';");
				if ($res){
					$msg = "<b>NAS '$selected_nas' was deleted successfully</b><br>\n";
					$selected_nas = '';
				}
				else
		$msg = "<b>Error deleting NAS '$selected_nas' " . da_sql_error($link,$config) . "</b><br>\n";
				break;
			case 'add_nas':
				if ($nasname == '' || $nassecret == '' || $nasshortname == '')
					$msg = "<b>Error. Required fields are not set</b><br>\n";
				else{
					$nasshortname = da_sql_escape_string($nasshortname);
					$nastype = da_sql_escape_string($nastype);
					$nasportnum = da_sql_escape_string($nasportnum);
					$nassecret = da_sql_escape_string($nassecret);
					$nascommunity = da_sql_escape_string($nascommunity);
					$nasdescription = da_sql_escape_string($nasdescription);
					$nasname = da_sql_escape_string($nasname);

					$res = @da_sql_query($link,$config,
					"INSERT INTO $config[sql_nas_table]
					(nasname,shortname,type,ports,secret,community,description)
					VALUES ('$nasname','$nasshortname', '$nastype','$nasportnum',
					'$nassecret','$nascommunity','$nasdescription');");
					if ($res){
						$msg = "<b>NAS '$nasname' was added successfully</b><br>\n";
						$selected_nas = $nasname;
					}
					else
			$msg = "<b>Error adding NAS '$nasname' " . da_sql_error($link,$config) . "</b><br>\n";
				}
				break;
			case 'change_nas':
				if ($nassecret == '' || $nasshortname == '')
					$msg = "<b>Error. Required fields are not set</b><br>\n";
				else{
					$nasshortname = da_sql_escape_string($nasshortname);
					$nastype = da_sql_escape_string($nastype);
					$nasportnum = da_sql_escape_string($nasportnum);
					$nassecret = da_sql_escape_string($nassecret);
					$nascommunity = da_sql_escape_string($nascommunity);
					$nasdescription = da_sql_escape_string($nasdescription);
					$nasname = da_sql_escape_string($nasname);

					$res = @da_sql_query($link,$config,
					"UPDATE $config[sql_nas_table] SET
					shortname = '$nasshortname',
					type = '$nastype',
					ports = '$nasportnum',
					secret = '$nassecret',
					community = '$nascommunity',
					description = '$nasdescription' WHERE nasname = '$nasname';");
					if ($res)
						$msg = "<b>NAS '$nasname' was updated successfully</b><br>\n";
					else
			$msg = "<b>Error updating NAS '$selected_nas' " . da_sql_error($link,$config) . "</b><br>\n";
				}
				break;
		}
	}
	$search = @da_sql_query($link,$config,
	"SELECT * FROM $config[sql_nas_table] ORDER BY nasname;");
	if ($search){
		$num = 0;
		unset($my_nas_list);
		while($row = @da_sql_fetch_array($search,$config)){
			$my_nas_name = $row['nasname'];
			if ($my_nas_name != ''){
				$num++;
				$my_nas_list[$my_nas_name]['name'] = $my_nas_name;
				$my_nas_list[$my_nas_name]['shortname'] = $row['shortname'];
				$my_nas_list[$my_nas_name]['type'] = $row['type'];
				if ($clear_fields == 0 && $selected_nas == $my_nas_name){
					$selected[$my_nas_name] = 'selected';
					$selected[$my_nas_list[$my_nas_name]['type']] = 'selected';
				}
				$my_nas_list[$my_nas_name]['ports'] = $row['ports'];
				$my_nas_list[$my_nas_name]['secret'] = $row['secret'];
				$my_nas_list[$my_nas_name]['community'] = $row['community'];
				$my_nas_list[$my_nas_name]['description'] = $row['description'];
			}
		}
	}
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";


?>

<html>
<head>
<title>NAS Administration Page</title>
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

</table>
<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">NAS Administration</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>

   <form method=post>
      <input type=hidden name=do_it value=0>
      <input type=hidden name=clear_fields value=0>
      <input type=hidden name=select_nas value=0>
<?php echo $msg?>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
<tr>
<td align=right bgcolor="#d0ddb0">
NAS List
</td>
<td>
<select name=selected_nas size=5 OnChange="this.form.select_nas.value=1;this.form.submit()">
<?php
foreach ($my_nas_list as $member){
	$name = $member[name];
	echo "<option $selected[$name] value=\"$name\">$name\n";
}
?>
</select>
</td>
</tr>
<?php
$array = $my_nas_list[$selected_nas];
echo <<<EOM
<tr>
<td align=right bgcolor="#d0ddb0">
NAS Name
</td>
<td>
<input type=text name=nasname size=40 value="$array[name]" $readonly>
</td></tr>
<tr>
<td align=right bgcolor="#d0ddb0">
NAS Short Name
</td>
<td>
<input type=text name=nasshortname size=40 value="$array[shortname]">
</td></tr>
<tr>
<td align=right bgcolor="#d0ddb0">
NAS Type
</td>
<td>
<select name=nastype size=1>
<option $selected[cisco] value="cisco">cisco
<option $selected[computone] value="computone">computone
<option $selected[livingston] value="livingston">livingston
<option $selected[max40xx] value="max40xx">max40xx
<option $selected[multitech] value="multitech">multitech
<option $selected[netserver] value="netserver">netserver
<option $selected[pathras] value="pathras">pathras
<option $selected[patton] value="patton">patton
<option $selected[portslave] value="portslave">portslave
<option $selected[tc] value="tc">tc
<option $selected[usrhiper] value="usrhiper">usrhiper
<option $selected[other] value="other">other
</select>
</td></tr>
<tr>
<td align=right bgcolor="#d0ddb0">
NAS Ports Number
</td>
<td>
<input type=text name=nasportnum size=40 value="$array[ports]">
</td></tr>
<tr>
<td align=right bgcolor="#d0ddb0">
NAS Secret
</td>
<td>
<input type=text name=nassecret size=40 value="$array[secret]">
</td></tr>
<tr>
<td align=right bgcolor="#d0ddb0">
NAS SNMP community
</td>
<td>
<input type=text name=nascommunity size=40 value="$array[community]">
</td></tr>
<tr>
<td align=right bgcolor="#d0ddb0">
NAS Description
</td>
<td>
<input type=text name=nasdescription size=40 value="$array[description]">
</td></tr>
EOM;
?>
	</table>
<br>
<select name=action size=1>
<?php
if ($clear_fields == 1 || ($do_it == 0 && $select_nas == 0))
	echo "<option value=\"add_nas\">Add NAS\n";
if ($clear_fields == 0)
	echo <<<EOM
<option value="change_nas">Change NAS Info
<option value="del_nas">Delete Selected NAS
<option value="check_nas">Check NAS validity
EOM;
?>
</select>
<input type=submit class=button value="Perform Action" OnClick="this.form.do_it.value=1">
<br><br>
<input type=submit class=button value="Clear Fields" OnClick="this.form.clear_fields.value=1">
</form>
</td></tr>
</table>
</tr>
</table>
</body>
</html>
