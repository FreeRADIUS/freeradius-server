<html>
<head>
<title>Help page</title>
<link rel="stylesheet" href="../style.css">
</head>
<body bgcolor="#80a040" background="../images/greenlines1.gif" link="black" alink="black">
<center>
<table border=0 width=550 cellpadding=0 cellspacing=0>
<tr valign=top>
<td align=center><img src="../images/title2.gif"></td>
</tr>
</table>

<table border=0 width=400 cellpadding=0 cellspacing=2></table>

<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=540></td>
<td bgcolor="black" width=400>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th><font color="white">dialup_admin help page</font>&nbsp;</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
<br>

<b>Please choose which file you wish to read:</b><br><br>
<form name="readhelp" method=post>
<select name=help_file>
<?php
$selected[$help_file] = 'selected';

echo <<<EOM
<option $selected[readme] value="readme">README File
<option $selected[howto] value="howto">HOWTO File
<option $selected[faq] value="faq">FAQ File
EOM;
?>
</select>
<br><br>
<input type=submit class=button value="Read File">
</form>

<pre>
<?php
$in_file = '';
if ($help_file == 'readme')
	$in_file = '../../README';
else if ($help_file == 'howto')
	$in_file = '../../doc/HOWTO';
else if ($help_file == 'faq')
	$in_file = '../../doc/FAQ';
if ($in_file != '')
	readfile("$in_file");
?>
</pre>
<br>
</td></tr>
</table>
</tr>
</table>
</body>
</html>
