<?php
function time2str($time)
{
	$time = floor($time);
	if (!$time)
		return "0 seconds";
	$d = $time/86400;
	$d = floor($d);
	if ($d){
		$str .= "$d days, ";
		$time = $time % 86400;
	}
	$h = $time/3600;
	$h = floor($h);
	if ($h){
		$str .= "$h hours, ";
		$time = $time % 3600;
	}
	$m = $time/60;
	$m = floor($m);
	if ($m){
		$str .= "$m minutes, ";
		$time = $time % 60;
	}
	if ($time)
		$str .= "$time seconds, ";
	$str = ereg_replace(', $','',$str);

	return $str;
}

function time2strclock($time)
{
	$time = floor($time);
	if (!$time)
		return "00:00:00";

	$str["hour"] = $str["min"] = $str["sec"] = "00";
	$h = $time/3600;
	$h = floor($h);
	if ($h){
		if ($h < 10)
			$h = "0" . $h;
		$str["hour"] = "$h";
		$time = $time % 3600;
	}
	$m = $time/60;
	$m = floor($m);
	if ($m){
		if ($m < 10)
			$m = "0" . $m;
		$str["min"] = "$m";
		$time = $time % 60;
	}
	if ($time){
		if ($time < 10)
			$time = "0" . $time;
	}
	else
		$time = "00";
	$str["sec"] = "$time";
	$ret = "$str[hour]:$str[min]:$str[sec]";

	return $ret;
}

function date2timediv($date)
{
	list($day,$time)=explode(' ',$date);
	$day = explode('-',$day);
	$time = explode(':',$time);
	$timest = mktime($time[0],$time[1],$time[2],$day[1],$day[2],$day[0]);
	$now = time();
	return ($now - $timest);
}

function date2time($date)
{
	list($day,$time)=explode(' ',$date);
	$day = explode('-',$day);
	$time = explode(':',$time);
	$timest = mktime($time[0],$time[1],$time[2],$day[1],$day[2],$day[0]);
	return $timest;
}

function bytes2str($bytes)
{
	$bytes=floor($bytes);
	if ($bytes > 536870912)
		$str = sprintf("%5.2f GBs", $bytes/1073741824);
	if ($bytes > 524288)
		$str = sprintf("%5.2f MBs", $bytes/1048576);
	else
		$str = sprintf("%5.2f KBs", $bytes/1024);

	return $str;
}

function nothing($ret)
{
	return $ret;
}
function check_defaults($val,$op,$def)
{
	for($i=0;$i<$def[count];$i++){
		if ($val == $def[$i] && ($op == '' || $op == $def[operator][$i]))
			return 1;
	}

	return 0;
}
?>
