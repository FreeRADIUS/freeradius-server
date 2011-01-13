<?php

require('../conf/config.php');
require('../lib/functions.php');
require('../lib/sql/functions.php');
require('../lib/acctshow.php');

if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php"))
	include_once("../lib/sql/drivers/$config[sql_type]/functions.php");
else{
	echo <<<EOM
<html>
<head>
<title>Accounting Report Generator</title>
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

$operators=array( '=','<', '>', '<=', '>=', '!=', 'regexp', 'like', 'not like' );
if ($config[sql_type] == 'pg'){
	$operators=array( '=','<', '>', '<=', '>=', '~', 'like', '~*', '~~*', '<<=' );
}

$link = @da_sql_pconnect ($config) or die('cannot connect to sql databse');
$fields = @da_sql_list_fields($config[sql_accounting_table],$link,$config);
$no_fields = @da_sql_num_fields($fields,$config);

unset($items);

for($i=0;$i<$no_fields;$i++){
	$key = strtolower(@da_sql_field_name($fields,$i,$config));
	$val = $sql_attrs[$key][desc];
	if ($val == '')
		continue;
	$show = $sql_attrs[$key][show];
	$selected[$key] = ($show == 'yes') ? 'selected' : '';
	$items[$key] = "$val";
}
asort($items);

class Qi {
	var $name;
	var $item;
	var $_item;
	var $operator;
	var $type;
	var $typestr;
	var $value;
	function Qi($name,$item,$operator) {
				$this->name=$name;
				$this->item=$item;
				$this->operator=$operator;
	}

	function show() {	global $operators;
				global $items;
		$nam = $this->item;
			echo <<<EOM
	<tr><td align=left>
	<i>$items[$nam]</i>
	<input type=hidden name="item_of_$this->name" value="$this->item">
	</td><td align=left>
	<select name=operator_of_$this->name>
EOM;
		foreach($operators as $operator){
			if($this->operator == $operator)
				$selected=" selected ";
			else
				$selected='';
			print("<option value=\"$operator\" $selected>$operator</option>\n");
		 }
	echo <<<EOM
	</select>
	</td><td align=left>
	<input name="value_of_$this->name" type=text value="$this->value">
	</td><td align=left>
	<input type=hidden name="delete_$this->name" value=0>
	<input type=submit class=button size=5 value=del onclick="this.form.delete_$this->name.value=1">
	</td></tr>
EOM;
	}

	function get($designator) {  	global ${"item_of_$designator"};
			global ${"value_of_$designator"};
			global ${"operator_of_$designator"};
			if(${"item_of_$designator"}){
				$this->value= ${"value_of_$designator"};
				$this->operator=${"operator_of_$designator"};
				$this->item=${"item_of_$designator"};
			}
		}
	function query(){
		global $operators;
		global $items;
		return $items[$this->item]."  $this->operator  '$this->value'";
	}
}

?>
<html>
<head>
<title>Accounting Report Generator</title>
<meta http-equiv="Content-Type" content="text/html; charset=<?php echo $config[general_charset]?>">
<link rel="stylesheet" href="style.css">
</head>
<body>

<?php
if(!$queryflag) {
	echo <<<EOM
<form method=post>
<table border=0 width=740 cellpadding=1 cellspacing=1>
<tr>
<td>
<b>Show the following attributes:</b><br>
<select name="accounting_show_attrs[]" size=5 multiple>
EOM;
foreach($items as $key => $val)
	echo <<<EOM
<option $selected[$key] value="$key">$val</option>
EOM;

echo <<<EOM
</select>
<br><br>
<b>Order by:</b><br>
<select name="order_by">
EOM;

foreach($items as $key => $val)
	if ($val == 'username')
		echo <<<EOM
	<option selected value="$key">$val</option>
EOM;
	else
	echo <<<EOM
<option value="$key">$val</option>
EOM;

echo <<<EOM
</select>
<br><br>
<b>Max results returned:</b><br>
<input name=maxresults value=$config[sql_row_limit] size=5>
</td>
<td valign=top>
<input type=hidden name=add value=0>
<table border=0 width=340 cellpadding=1 cellspacing=1>
<tr><td>
<b>Selection criteria:</b>
</td></tr>
<tr><td>
<select name=item_name onchange="this.form.add.value=1;this.form.submit()">
<option>--Attribute--</option>
EOM;

foreach($items as $key => $val)
	print("<option value=\"$key\">$val</option>");

echo <<<EOM
</select>
</td></tr>
EOM;

$number=1;
$offset=0;
while (${"item_of_w$number"}) {
	if(${"delete_w$number"}==1) {$offset=1;$number++;}
		else {
		$designator=$number-$offset;
		${"w$designator"} = new Qi("w$designator","","");
		${"w$designator"}->get("w$number");
		${"w$designator"}->show();
		$number++;
		}
	}
if($add==1) {
	${"w$number"} = new Qi("w$number","$item_name","$operators[0]");
	${"w$number"}->show();
	}
echo <<<EOM
</table>
</td>
<tr>
<td>
<input type=hidden name=queryflag value=0>
<br><input type=submit class=button onclick="this.form.queryflag.value=1">
</td>
</tr>
</table>
</form>
</body>
</html>
EOM;

}

if ($queryflag == 1){
$i = 1;
while (${"item_of_w$i"}){
	$op_found = 0;
	foreach ($operators as $operator){
		if (${"operator_of_w$i"} == $operator){
			$op_found = 1;
			break;
		}
	}
	if (!$op_found)
		die("Operator passed is not valid. Exiting abnormaly.");
	${"item_of_w$i"} = preg_replace('/\s/','',${"item_of_w$i"});
	${"value_of_w$i"} = da_sql_escape_string(${"value_of_w$i"});
	$where .= ($i == 1) ? ' WHERE ' . ${"item_of_w$i"} . ' ' . ${"operator_of_w$i"} . " '" . ${"value_of_w$i"} . "'" :
				' AND ' . ${"item_of_w$i"} . ' ' . ${"operator_of_w$i"} . " '" . ${"value_of_w$i"} . "'" ;
	$i++;
}

$order = ($order_by != '') ? "$order_by" : 'username';

if (preg_match("/[\s;]/",$order))
	die("ORDER BY pattern is illegal. Exiting abnornally.");

if (!is_numeric($maxresults))
	die("Max Results is not in numeric form. Exiting abnormally.");

unset($query_view);
foreach ($accounting_show_attrs as $val)
	$query_view .= $val . ',';
$query_view = preg_replace('/,$/','',$query_view);
unset($sql_extra_query);
if ($config[sql_accounting_extra_query] != '')
	$sql_extra_query = xlat($config[sql_accounting_extra_query],$login,$config);
	$sql_extra_query = da_sql_escape_string($sql_extra_query);
$query="SELECT " . da_sql_limit($maxresults,0,$config) . " $query_view FROM $config[sql_accounting_table]
	$where $sql_extra_query " . da_sql_limit($maxresults,1,$config) .
	" ORDER BY $order " . da_sql_limit($maxresults,2,$config) . ";";

echo <<<EOM
<html>
<head>
<link rel="stylesheet" href="style.css">
</head>
<body>
<br>
<table border=0 width=940 cellpadding=1 cellspacing=1>
<tr valign=top>
<td width=740></td>
<td bgcolor="black" width=200>
	<table border=0 width=100% cellpadding=2 cellspacing=0>
	<tr bgcolor="#907030" align=right valign=top><th>
	<font color="white">Accounting Report Generator</font>&nbsp;
	</th></tr>
	</table>
</td></tr>
<tr bgcolor="black" valign=top><td colspan=2>
	<table border=0 width=100% cellpadding=12 cellspacing=0 bgcolor="#ffffd0" valign=top>
	<tr><td>
<p>
	<table border=1 bordercolordark=#ffffe0 bordercolorlight=#000000 width=100% cellpadding=2 cellspacing=0 bgcolor="#ffffe0" valign=top>
	<tr bgcolor="#d0ddb0">
	</tr>
EOM;
foreach($accounting_show_attrs as $val){
	$desc = $sql_attrs[$val][desc];
	echo "<th>$desc</th>\n";
}
echo "</tr>\n";

	$search = @da_sql_query($link,$config,$query);
	if ($search){
		while( $row = @da_sql_fetch_array($search,$config) ){
			$num++;
			echo "<tr align=center>\n";
			foreach($accounting_show_attrs as $val){
				$info = $row[$val];
				if ($info == '')
					$info = '-';
				$info = $sql_attrs[$val][func]($info);
				if ($val == 'username'){
					$Info = urlencode($info);
					$info = "<a href=\"user_admin.php?login=$Info\" title=\"Edit user $info\">$info<a/>";
				}
				echo <<<EOM
			<td>$info</td>
EOM;
			}
			echo "</tr>\n";
		}
	}
	else
		echo "<b>Database query failed: " . da_sql_error($link,$config) . "</b><br>\n";
echo <<<EOM
	</table>
	</td></tr>
	</table>
</td></tr>
</table>
</body>
</html>
EOM;
}
?>
