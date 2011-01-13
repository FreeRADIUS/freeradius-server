<html>
<head>
<title>Login-Time Creation Page</title>
<meta http-equiv="Content-Type" content="text/html; charset=<?php echo $config[general_charset]?>">
<link rel="stylesheet" href="style.css">
</head>
<body>
<?php

function check_day($day){
	switch($day){
		case 'Mo':
		case 'Tu':
		case 'We':
		case 'Th':
		case 'Th':
		case 'Fr':
		case 'Sa':
		case 'Su':
		case 'Al':
		case 'Any':
		case 'Wk':
			return 1;
			break;
		default:
			return 0;
			break;
	}
}

$mapping = array(
	'Mo' => 'Monday',
	'Tu' => 'Tuesday',
	'We' => 'Wednesday',
	'Th' => 'Thursday',
	'Fr' => 'Friday',
	'Sa' => 'Saturday',
	'Su' => 'Sunday',
	'Al' => 'All Days',
	'Any' => 'All Days',
	'Wk' => 'Weekdays');

$rules = array();

if ($add == 1){
	if ($use == 'double' && $start_day != $stop_day){
		$new = $start_day;
		if ($stop_day != '')
			$new .= "-$stop_day";
		if ($Dstart_time != '' && $Dstop_time != '')
			$new .= "$Dstart_time-$Dstop_time";
	}
	else if ($use == 'one'){
		$new = $day;
		if ($Mstart_time != '' && $Mstop_time != '')
			$new .= "$Mstart_time-$Mstop_time";
	}
	if ($new != ''){
		if ($rulestr == '')
			$rulestr = $new;
		else
			$rulestr .= ",$new";
	}
}
$Mstart_time = $Mstop_time = $Dstart_time = $Dstop_time = '';


if ($rulestr != ''){
	$rulestr = str_replace('"','',$rulestr);
	$rules1 = preg_split('/[,|]/',$rulestr);
}

if ($rules1){
	foreach ($rules1 as $rule){
		if ($delete1 == 1 && $sel_rule == $rule)
			continue;
		$matches = array();
		if (preg_match('/^\w{2,3}$/',$rule)){
			if (!check_day($rule)){
				$err_msg .= "<b>Rule '$rule' is invalid</b><br>\n";
				continue;
			}
			if ($sel_rule == $rule || $sel_rule == ''){
				$checked[one] = 'checked';
				$selected_more[$rule] = 'selected';
			}
			$msg = $mapping[$rule];
		}
		else if (preg_match('/^(\w{2,3})(\d{4})-(\d{4})$/',$rule,$matches)){
			if (!check_day($matches[1])){
				$err_msg .= "<b>Rule '$rule' is invalid</b><br>\n";
				continue;
			}
			if ($sel_rule == $rule || $sel_rule == ''){
				$checked[one] = 'checked';
				$selected_more[$matches[1]] = 'selected';
				$Mstart_time = $matches[2];
				$Mstop_time = $matches[3];
			}
			$msg = $mapping[$matches[1]] . " $matches[2] - $matches[3]";
		}
		else if (preg_match('/^(\w{2,3})-(\w{2,3})$/',$rule,$matches)){
			if (!check_day($matches[1]) || !check_day($matches[2])){
				$err_msg .= "<b>Rule '$rule' is invalid</b><br>\n";
				continue;
			}
			if ($sel_rule == $rule || $sel_rule == ''){
				$checked[double] = 'checked';
				$selected_start[$matches[1]] = 'selected';
				$selected_stop[$matches[2]] = 'selected';
			}
			$msg = $mapping[$matches[1]] . " - " . $mapping[$matches[2]];
		}
		else if (preg_match('/^(\w{2,3})-(\w{2,3})(\d{4})-(\d{4})$/',$rule,$matches)){
			if (!check_day($matches[1]) || !check_day($matches[2])){
				$err_msg .= "<b>Rule '$rule' is invalid</b><br>\n";
				continue;
			}
			if ($sel_rule == $rule || $sel_rule == ''){
				$checked[double] = 'checked';
				$selected_start[$matches[1]] = 'selected';
				$selected_stop[$matches[2]] = 'selected';
				$Dstart_time = $matches[3];
				$Dstop_time = $matches[4];
			}
			$msg = $mapping[$matches[1]] . " - " . $mapping[$matches[2]] . " $matches[3] - $matches[4]";
		}
		else{
			$err_msg .= "<b>Rule $rule is invalid</b><br>\n";
			continue;
		}
		array_push($rules,$rule);
		$rule_msgs[$rule] = $msg;
	}
}
if ($sel_rule != '')
	$selected_rule[$sel_rule] = 'selected';
else
	$Mstart_time = $Mstop_time = $Dstart_time = $Dstop_time = '';

$rulestr = '';
foreach ($rules as $rule){
	if ($rulestr == '')
		$rulestr = "$rule";
	else
		$rulestr .= ",$rule";
}
if ($update == 1 && $val != '')
	echo <<<EOM
<script language="JavaScript1.1" type="text/javascript">
window.opener.document.edituser.$val.value = "\"$rulestr\"";
window.close();
</script>
EOM;

if ($checked[double] == '' && $checked[one] == '')
	$checked[double] = 'checked';

?>
<center>
<table border=0 width=540 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=340></td>
<td bgcolor="black" width=400>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th><font color="white">Login-Time Create Page</font>&nbsp;</th></tr>
	</table>
</td></tr>
<form name=ruleform method=post action="login_time_create.php3">
<input type=hidden name=add value="0">
<input type=hidden name=delete1 value="0">
<input type=hidden name=update value="0">
<input type=hidden name=val value="<?php echo $val?>">
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td align=center>
<table width=90%>
<tr>
<td>&nbsp;</td>
<td><b>Start Day</b></td>
<td><b>Stop Day</b></td>
<td align=center><b>Time (HHMM)</b></td>
</tr>
<tr>

<?php
	echo <<<EOM
<td><input type=radio name=use value=double $checked[double]>&nbsp;<b>Range</b></td>
<td><select name=start_day OnClick="this.form.use[0].checked=true;this.form.Mstart_time.value='';this.form.Mstop_time.value=''">
<option value="Mo" $selected_start[Mo]>Monday
<option value="Tu" $selected_start[Tu]>Tuesday
<option value="We" $selected_start[We]>Wednesday
<option value="Th" $selected_start[Th]>Thursday
<option value="Fr" $selected_start[Fr]>Friday
<option value="Sa" $selected_start[Sa]>Saturday
<option value="Su" $selected_start[Su]>Sunday
</select></td>
<td><select name=stop_day OnClick="this.form.use[0].checked=true;this.form.Mstart_time.value='';this.form.Mstop_time.value=''">
<option value="Mo" $selected_stop[Mo]>Monday
<option value="Tu" $selected_stop[Tu]>Tuesday
<option value="We" $selected_stop[We]>Wednesday
<option value="Th" $selected_stop[Th]>Thursday
<option value="Fr" $selected_stop[Fr]>Friday
<option value="Sa" $selected_stop[Sa]>Saturday
<option value="Su" $selected_stop[Su]>Sunday
</select></td>
<td align=right><input type=text name=Dstart_time size=4 value="$Dstart_time" OnClick="this.form.use[0].checked=true;this.form.Mstart_time.value='';this.form.Mstop_time.value=''">
&nbsp;-&nbsp;
<input type=text name=Dstop_time size=4 value="$Dstop_time" OnClick="this.form.use[0].checked=true;this.form.Mstart_time.value='';this.form.Mstop_time.value=''"></td>
</tr>
<tr>
<td><input type=radio name=use value=one $checked[one]>&nbsp;<b>Specific</b></td>
<td><select name=day OnClick="this.form.use[1].checked=true;this.form.Dstart_time.value='';this.form.Dstop_time.value=''">
<option value="Mo" $selected_more[Mo]>Monday
<option value="Tu" $selected_more[Tu]>Tuesday
<option value="We" $selected_more[We]>Wednesday
<option value="Th" $selected_more[Th]>Thursday
<option value="Fr" $selected_more[Fr]>Friday
<option value="Sa" $selected_more[Sa]>Saturday
<option value="Su" $selected_more[Su]>Sunday
<option value="Wk" $selected_more[Wk]>Weekdays
<option value="Al" $selected_more[Al]>All Days
</select></td>
<td colspan=2 align=right><input type=text name=Mstart_time size=4 value="$Mstart_time" OnClick="this.form.use[1].checked=true;this.form.Dstart_time.value='';this.form.Dstop_time.value=''">
&nbsp;-&nbsp;
<input type=text name=Mstop_time size=4 value="$Mstop_time" OnClick="this.form.use[1].checked=true;this.form.Dstart_time.value='';this.form.Dstop_time.value=''"></td>
</tr>
EOM;
?>

<tr><td>&nbsp;</td></tr>
<tr><td colspan=5 align=center>
<input type=submit class=button value=" + " OnClick="this.form.add.value=1">
&nbsp;&nbsp;&nbsp;
<input type=submit class=button value=" - " OnClick="this.form.delete1.value=1">
</td></tr>
<tr><td colspan=5 align=center>
<br>
<b>Rule Set</b>
</td></tr>
<tr><td colspan=5 align=center>
<?php
if (!empty($rules)){
	echo "<select name=\"sel_rule\" size=5 multi OnChange=\"this.form.submit()\">\n";
	foreach ($rules as $rule)
		echo "<option value=\"$rule\" $selected_rule[$rule]>$rule_msgs[$rule]\n";
	echo "</select>\n";
}
else
	echo "<i>No rules available</i><br>\n";
?>
</td></tr>
<tr><td colspan=5 align=center><?php echo $err_msg ?></td></tr>
<tr><td>&nbsp;</td></tr>
<tr><td colspan=5 align=center><b>Rule string (<a href="help/login_time_help.html" target=lt_help onclick=window.open("login_time_help.html","lt_help","width=600,height=370,toolbar=no,scrollbars=no,resizable=yes") title="Login-Time Help Page"><font color="blue">UUCP Format</font></a>)</b></td></tr>
<tr><td colspan=5 align=center>
<input type=text name=rulestr value="<?php echo $rulestr ?>" size=40 OnChange="this.form.submit()">
</td></tr>
<tr><td>&nbsp;</td></tr>
<tr><td colspan=5 align=center>
<input type=submit class=button value="Update Attribute in User Edit page" OnClick="this.form.update.value=1">
</td></tr>
</table>
<?php
if ($rulestr == '' && $first == 'yes')
	echo <<<EOM
<script language="JavaScript1.1" type="text/javascript">
window.document.ruleform.rulestr.value=window.opener.document.edituser.$val.value;
window.document.ruleform.submit();
</script>
EOM;
?>
</form>
</td></tr>
<tr><td align=center>
<a href="javascript:window.close();"><b>Close Window</b></a>
</td></tr>
</center>
</table>
</tr>
</table>
</body>
</html>
