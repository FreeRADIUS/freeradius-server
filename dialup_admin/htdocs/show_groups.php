<?php
require('../conf/config.php');
?>
<html>
<?php

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php");
else{
	echo <<<EOM
<title>User Groups</title>
<meta http-equiv="Content-Type" content="text/html; charset=$config[general_charset]">
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
if ($config[general_lib_type] != 'sql'){
	echo <<<EOM
<title>User Groups</title>
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
?>
<head>
<title>User Groups</title>
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

<br><br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=55%></td>
<td bgcolor="black" width=45%>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">User Groups</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
<font size=-2>Only groups with members are shown</font><p>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
	<tr bgcolor="#d0ddb0">
	<th>#</th><th>group</th><th># of members</th>
	</tr>

<?php
unset($login);
$num = 0;
include_once("../lib/$config[general_lib_type]/group_info.php");
if (isset($existing_groups)){
	foreach ($existing_groups as $group => $num_members){
		$num++;
		$Group = urlencode($group);
		echo <<<EOM
		<tr align=center>
			<td>$num</td>
			<td><a href="group_admin.php?login=$Group" title="Edit group $group">$group</a></td>
			<td>$num_members</td>
		</tr>
EOM;
	}
}
else
	echo "<b>Could not find any groups</b><br>\n";
?>
	</table>
</table>
</tr>
</table>
</body>
</html>
