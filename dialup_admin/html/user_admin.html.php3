<?php

echo <<<EOM
<title>user information for $cn</title>
<meta http-equiv="Content-Type" content="text/html; charset=$config[general_charset]">
</head>
<body>
<link rel="stylesheet" href="style.css">
EOM;
if ($logged_now)
	print <<<EOM
<script Language="JavaScript">
<!--
	var start;
	var our_time;

	function startcounter()
	{
		var start_date = new Date();
		start = start_date.getTime();
		our_time = $lastlog_session_time_jvs;
		showcounter();
	}

	function showcounter ()
	{
		var now_date = new Date();
		var diff = now_date.getTime() - start + our_time;

		var hours = parseInt(diff / 3600000);
		if(isNaN(hours)) hours = 0;

		var minutes = parseInt((diff % 3600000) / 60000);
		if(isNaN(minutes)) minutes = 0;

		var seconds = parseInt(((diff % 3600000) % 60000) / 1000);
		if(isNaN(seconds)) seconds = 0;

		var timeValue = " " ;
		timeValue += ((hours < 10) ? "0" : "") + hours;
		timeValue += ((minutes < 10) ? ":0" : ":") + minutes;
		timeValue += ((seconds < 10) ? ":0" : ":") + seconds;

		document.online.status.value = timeValue;
		setTimeout("showcounter()", 1000);
	}
	//-->
</script>
EOM;

print <<<EOM
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
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=250>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Connection Status for $login ($cn)</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>

EOM;
if ($logged_now){
	print <<<EOM
	<form name="online" onSubmit="return(false);">
	<tr><td align=center bgcolor="#d0ddb0">
	User is <b>online</b> since
	</td><td>
	$lastlog_time
	</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">
	Connection Duration
	</td><td>
	<input type="text" name="status" size=10 value="$lastlog_session_time">
	</form>
	</td></tr>
EOM;
	require('../html/user_admin_userinfo.html.php3');

}else if ($not_known)  print <<<EOM
	<tr><td align=center bgcolor="#d0ddb0">
	This user has <b>never</b> connected
	</td><td>-
	</td></tr>
EOM;
else{
	print <<<EOM
	<tr><td align=center bgcolor="#d0ddb0">
	User is <b>not online</b> now<br>
	</td><td>-
	</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">
	Last Connection Time
	</td><td>
	$lastlog_time
	</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">
	Online Time
	</td><td>
	$lastlog_session_time
	</td></tr>
EOM;
	require('../html/user_admin_userinfo.html.php3');
}

print <<<EOM
	<tr><td align=center bgcolor="#d0ddb0">
	Allowed Session
	</td><td>
	$msg
	</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">
	Usefull User Description
	</td><td>
	$descr
	</td></tr>
	</table>
	</table>
</table>

EOM;

if (is_file("../lib/$config[general_lib_type]/password_check.php3"))
	include("../lib/$config[general_lib_type]/password_check.php3");

echo <<<EOM
<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=250>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Subscription Analysis</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
	<tr><td align=center bgcolor="#d0ddb0">-</td><td align=center bgcolor="#d0ddb0"><b>monthly</b></td><td align=center bgcolor="#d0ddb0"><b>weekly</b></td><td align=center bgcolor="#d0ddb0"><b>daily</b></td><td align=center bgcolor="#d0ddb0"><b>per session</b></td></tr>
	<tr><td align=center bgcolor="#d0ddb0"><b>limit</b></td><td>$monthly_limit</td><td>$weekly_limit</td><td>$daily_limit</td><td>$session_limit</td></tr>
	<tr><td align=center bgcolor="#d0ddb0"><b>used</b></td><td>$monthly_used</td><td>$weekly_used</td><td>$daily_used</td><td>$lastlog_session_time</td></tr>
	</table>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" va
lign=top>
	<tr><td align=center bgcolor="#d0ddb0"><b>day</b></td><td align=center bgcolor="#d0ddb0"><b>daily limit</b></td><td align=center bgcolor="#d0ddb0"><b>used</b></td><tr>
	<tr><td align=center bgcolor="#d0ddb0">sunday</td><td>$daily_limit</td><td>$used[0]</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">monday</td><td>$daily_limit</td><td>$used[1]</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">tuesday</td><td>$daily_limit</td><td>$used[2]</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">wednesday</td><td>$daily_limit</td><td>$used[3]</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">thursday</td><td>$daily_limit</td><td>$used[4]</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">friday</td><td>$daily_limit</td><td>$used[5]</td></tr>
	<tr><td align=center bgcolor="#d0ddb0">saturday</td><td>$daily_limit</td><td>$used[6]</td></tr>
	</table></table>
</table>
<br>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Account Status For The Last 7 Days</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
	<tr><td align=center bgcolor="#d0ddb0">Connections</td><td>
	<b><font color="darkblue">$tot_conns</font></b></td></tr>
	<tr><td align=center bgcolor="#d0ddb0">Online time</td><td>
	<b><font color="darkblue">$tot_time</td></tr></td></tr>
	<tr><td align=center bgcolor="#d0ddb0">Failed Logins</td><td>
	<b><font color="darkblue">$tot_badlogins</td></tr></td></tr>
	<tr><td align=center bgcolor="#d0ddb0">Upload</td><td>
	$tot_input</td></tr></td></tr>
	<tr><td align=center bgcolor="#d0ddb0">Download</td><td>
	$tot_output</td></tr></td></tr>
	<tr><td align=center bgcolor="#d0ddb0">Average Time</td><td>
	$avg_time</td></tr></td></tr>
	<tr><td align=center bgcolor="#d0ddb0">Average Upload</td><td>
	$avg_input</td></tr></td></tr>
	<tr><td align=center bgcolor="#d0ddb0">Average Download</td><td>
	$avg_output</td></tr></td></tr>
	</table>
	</table>
</table>
<br>
EOM;

if ($user_info){
	echo <<<EOM
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=250>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Personal Information</font>
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>name</b>
	</td>
	<td>
	$cn
	</td>
	</tr>
EOM;
	if ($config[general_prefered_lang] != 'en'){
		echo <<<EOM
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>name ($config[general_prefered_lang_name])</b>
	</td>
	<td>
	$cn_lang
	</td>
	</tr>
EOM;
	}
	echo <<<EOM
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>department</b>
	</td>
	<td>
	$ou
	</td>
	</tr>
EOM;
	if ($config[general_prefered_lang] != 'en'){
		echo <<<EOM
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>department ($config[general_prefered_lang_name])</b>
	</td>
	<td>
	$ou_lang
	</td>
	</tr>
EOM;
	}
	echo <<<EOM
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>title</b>
	</td>
	<td>
	$title
	</td>
	</tr>
EOM;
	if ($config[general_prefered_lang] != 'en'){
		echo <<<EOM
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>title ($config[general_prefered_lang_name])</b>
	</td>
	<td>
	$title_lang
	</td>
	</tr>
EOM;
	}
	echo <<<EOM
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>address</b>
	</td>
	<td>
	$address
	</td>
	</tr>
EOM;
	if ($config[general_prefered_lang] != 'en'){
		echo <<<EOM
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>address ($config[general_prefered_lang_name])</b>
	</td>
	<td>
	$address_lang
	</td>
	</tr>
EOM;
	}
	echo <<<EOM
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>home address</b>
	</td>
	<td>
	$homeaddress
	</td>
	</tr>
EOM;
	if ($config[general_prefered_lang] != 'en'){
		echo <<<EOM
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>home address ($config[general_prefered_lang_name])</b>
	</td>
	<td>
	$homeaddress_lang
	</td>
	</tr>
EOM;
	}
	echo <<<EOM
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>phone</b>
	</td>
	<td>
	$telephonenumber
	</td>
	</tr>
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>home phone</b>
	</td>
	<td>
	$homephone
	</td>
	</tr>
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>mobile</b>
	</td>
	<td>
	$mobile
	</td>
	</tr>
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>fax</b>
	</td>
	<td>
	$fax
	</td>
	</tr>
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>home page</b>
	</td>
	<td>
	<a href="$url" target=userpage onclick=window.open("$url","userpage","width=1000,height=550,toolbar=no,scrollbars=yes,resizable=yes") title="Go to user's homepage">$url</a>
	</td>
	</tr>
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>e-mail</b>
	</td>
	<td>
	<a href="mailto: $mail" title="Send E-Mail">$mail</a>
	</td>
	</tr>
	<tr>
	<td align=center bgcolor="#d0ddb0">
	<b>e-mail alias</b>
	</td>
	<td>
	<a href="mailto: $mailalt" title="Send E-Mail">$mailalt</a>
	</td>
	</tr>
	</table>
	</table>
</table>

EOM;
}
?>
	<tr>	<td colspan=3 height=1></td></tr>
	<tr>	<td colspan=3>
	</table>
<?php
if ($logged_now)
	print <<<EOM
<script Language="JavaScript">
	startcounter();
</script>
EOM;
?>

</body>
</html>
