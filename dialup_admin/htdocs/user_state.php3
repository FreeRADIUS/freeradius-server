<?php
require('../conf/config.php3');
require('../lib/functions.php3');
require('../lib/defaults.php3');
if (is_file("../lib/$config[general_lib_type]/user_info.php3"))
	include("../lib/$config[general_lib_type]/user_info.php3");

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else
	exit();

$vars = array( 'Dialup-Access' => 'TRUE','Dialup-Lock-Msg' => '-',
		'Max-Weekly-Session' => 0,'Max-Daily-Session' => 0);
foreach($vars as $key => $val){
	$val = ($item_vals["$key"][0] != "") ? $item_vals["$key"][0] : $default_vals["$key"];
	$vars["$key"]=$val;
}
$vars['Dialup-Access'] = ($vars['Dialup-Access'] == 'FALSE') ? 'inactive' : 'active';
$vars['Max-Daily-Session'] = time2strclock($vars['Max-Daily-Session']);
$vars['Max-Weekly-Session'] = time2strclock($vars['Max-Weekly-Session']);

$now = time();
$week = $now - date('w') * 86400;
$now_str = date("$config[sql_date_format]",$now + 86400);
$week_str = date("$config[sql_date_format]",$week);
$today = date("$config[sql_date_format]",$now);

$link = @da_sql_pconnect($config);
if ($link){
	$search = @da_sql_query($link,$config,
	"SELECT COUNT(*), sum(AcctSessionTime) FROM $config[sql_accounting_table] WHERE
	UserName = '$login' AND AcctStopTime >= '$week_str' AND
	AcctStopTime <= '$now_str';");
	if ($search){
		$row = @da_sql_fetch_array($search,$config);
		$weekly_used = time2strclock($row['sum(AcctSessionTime)']);
		$weekly_conns = $row['COUNT(*)'];
	}
	$search = @da_sql_query($link,$config,
	"SELECT COUNT(*),sum(AcctSessionTime) FROM $config[sql_accounting_table] WHERE
	UserName = '$login' AND AcctStopTime LIKE '$today%';");
	if ($search){
		$row = @da_sql_fetch_array($search,$config);
		$daily_used = time2strclock($row['sum(AcctSessionTime)']);
		$daily_conns = $row['COUNT(*)'];
	}
}


foreach($vars as $val){
	echo "$val\n";
}
echo "$weekly_used\n$weekly_conns\n$daily_used\n$daily_conns";
?>
