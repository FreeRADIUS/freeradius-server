<?php
require('../conf/config.php3');
?>
<html>
<head>
<title>account analysis</title>
<link rel="stylesheet" href="style.css">
</head>
<body bgcolor="#80a040" background="images/greenlines1.gif" link="black" alink="black">
<center>

<?php
require('../lib/functions.php3');

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
else{
	echo <<<EOM
<b>Could not include SQL library functions. Aborting</b>
</body>
</html>
EOM;
	exit();
}


$date = strftime('%A, %e %B %Y, %T %Z');
$now = time();
if ($before == '')
	$before = date($config[sql_date_format], $now + 86400);
$after = ($after != '') ? "$after" : date($config[sql_date_format], $now - 604800 );

$after_time = date2time($after);
$before_time = date2time($before);
$days[0] = $after;
$counter = $after_time + 86400;
$i = 1;
while($counter < $before_time){
	$days[$i++] = date($config[sql_date_format],$counter);	
	$counter += 86400;
}
$days[$i] = $before;
$num_days = $i;

$column1 = ($column1 != '') ? "$column1" : 'sessions';
$column2 = ($column2 != '') ? "$column2" : 'usage';
$column3 = ($column3 != '') ? "$column3" : 'download';
$column[1] = "$column1";
$column[2] = "$column2";
$column[3] = "$column3";
$selected1["$column1"] = 'selected';
$selected2["$column2"] = 'selected';
$selected3["$column3"] = 'selected';

$message['sessions'] = 'sessions';
$message['usage'] = 'total usage time';
$message['upload'] = 'uploads';
$message['download'] = 'downloads';
$sql_val['usage'] = 'AcctSessionTime';
$sql_val['upload'] = 'AcctInputOctets';
$sql_val['download'] = 'AcctOutputOctets';
$fun['sessions'] = nothing;
$fun['usage'] = time2strclock;
$fun['upload'] = bytes2str;
$fun['download'] = bytes2str;
$sql_val['user'] = ($login == '') ? "WHERE UserName LIKE '%'" : "WHERE UserName = '$login'";
for ($j = 1; $j <= 3; $j++){
	$tmp = "{$sql_val[$column[$j]]}";
	$res[$j] = ($tmp == "") ? 'COUNT(RadAcctId)' : "sum($tmp)";
}
$i = 1;
$servers[all] = 'all';
while(1){
	$nas = 'nas' . $i;
	$ip = $nas . '_ip';
	$name = $nas . '_name';
	if ($config[$ip] == '')
		break;
	$name = $config[$name];
	$servers[$name] = $config[$ip];
	$i++;
}
if ($server != 'all')
	$s = "AND NASIPAddress = '$server'";

$link = @da_sql_pconnect($config);
if ($link){
	for ($i = $num_days;$i > -1; $i--){
		$day = "$days[$i]";
		$search = @da_sql_query($link,$config,
		"SELECT $res[1],$res[2],$res[3] FROM $config[sql_accounting_table]
		$sql_val[user] AND AcctStopTime >= '$day 00:00:00' 
		AND AcctStopTime <= '$day 23:59:59' $s;");
		if ($search){
			$row = @da_sql_fetch_array($search,$config);
			$data[$day][1] = $row["$res[1]"];
			$data[sum][1] += $row["$res[1]"];
			$num[1] = ($data[$day][1]) ? $num[1] + 1 : $num[1];
			$data[$day][2] = $row["$res[2]"];
			$data[sum][2] += $row["$res[2]"];
			$num[2] = ($data[$day][2]) ? $num[2] + 1 : $num[2];
			$data[$day][3] = $row["$res[3]"];
			$data[sum][3] += $row["$res[3]"];
			$num[3] = ($data[$day][3]) ? $num[3] + 1 : $num[3];
		}
		else
			echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
	}
}
else
	echo "<b>Could not connect to SQL database</b><br>\n";

$num[1] = ($num[1]) ? $num[1] : 1;
$num[2] = ($num[2]) ? $num[2] : 1;
$num[3] = ($num[3]) ? $num[3] : 1;

$data['avg'][1] = ceil($data['sum'][1] / $num[1]);
$data['avg'][2] = ceil($data['sum'][2] / $num[2]);
$data['avg'][3] = ceil($data['sum'][3] / $num[3]);

$data['avg'][1] = $fun[$column[1]]($data['avg'][1]);
$data['avg'][2] = $fun[$column[2]]($data['avg'][2]);
$data['avg'][3] = $fun[$column[3]]($data['avg'][3]);

$data['sum'][1] = $fun[$column[1]]($data['sum'][1]);
$data['sum'][2] = $fun[$column[2]]($data['sum'][2]);
$data['sum'][3] = $fun[$column[3]]($data['sum'][3]);

for ($i = 0; $i <= $num_days; $i++){
	$day = "$days[$i]";
	$max[1] = ($max[1] > $data[$day][1] ) ? $max[1] : $data[$day][1];
	$max[2] = ($max[2] > $data[$day][2] ) ? $max[2] : $data[$day][2];
	$max[3] = ($max[3] > $data[$day][3] ) ? $max[3] : $data[$day][3];

}
for ($i = 0; $i <= $num_days; $i++){
	$day = "$days[$i]";
	for ($j = 1; $j <= 3; $j++){
		$tmp = $data[$day][$j];
		if (!$max[$j])
			$p = $w = $c = 0;
		else{
			$p = floor(100 * ($tmp / $max[$j]));
			$w = floor(70 * ($tmp / $max[$j]));
			$c = hexdec('f0e9e2') - (258 * $p);
			$c = dechex($c);
		}
		if (!$w)
			$w++;
		$perc[$day][$j] = $p . "%";
		$width[$day][$j] = $w;
		$color[$day][$j] = $c;
	}

	$data[$day][1] = $fun[$column[1]]($data[$day][1]);
	$data[$day][2] = $fun[$column[2]]($data[$day][2]);
	$data[$day][3] = $fun[$column[3]]($data[$day][3]);
}

$data[max][1] = $fun[$column[1]]($max[1]);
$data[max][2] = $fun[$column[2]]($max[2]);
$data[max][3] = $fun[$column[3]]($max[3]);

require('../html/stats.html.php3');
?>
