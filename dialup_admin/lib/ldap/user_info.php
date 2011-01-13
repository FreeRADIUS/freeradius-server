<?php
require('../lib/ldap/attrmap.php');
require_once('../lib/ldap/functions.php');
if (is_file("../lib/lang/$config[general_prefered_lang]/utf8.php"))
	include_once("../lib/lang/$config[general_prefered_lang]/utf8.php");
else
	include_once('../lib/lang/default/utf8.php');

$cn = '-';
$cn_lang = '-';
$address = '-';
$address_lang = '-';
$homeaddress = '-';
$homeaddress_lang = '-';
$fax = '-';
$url = '-';
$ou = '-';
$ou_lang = '-';
$title = '-';
$title_lang = '-';
$telephonenumber = '-';
$homephone = '-';
$mobile = '-';
$mail = '-';
$mailalt = '-';
$dn = '';
$user_exists = 'no';
unset($item_vals);

if ($config[general_decode_normal_attributes] == 'yes')
	$decode_normal = 1;

$ds=@ldap_connect("$config[ldap_server]");  // must be a valid ldap server!
if ($ds) {
	$r=@da_ldap_bind($ds,$config);
	if ($config[ldap_userdn] == ''){
		if ($config[ldap_filter] != '')
			$filter = xlat($config[ldap_filter],$login,$config);
		else
			$filter = 'uid=' . $login;
	}
	else
		$filter = xlat($config[ldap_userdn],$login,$config);
	if ($config[ldap_debug] == 'true'){
		if ($config[ldap_userdn] == '')
			print "<b>DEBUG(LDAP): Search Query: BASE='$config[ldap_base]',FILTER='$filter'</b><br>\n";
		else
			print "<b>DEBUG(LDAP): Search Query: BASE='$filter',FILTER='(objectclass=radiusprofile)'</b><br>\n";
	}
	if ($config[ldap_userdn] == '')
		$sr=@ldap_search($ds,"$config[ldap_base]", $filter);
	else
		$sr=@ldap_read($ds,$filter, '(objectclass=radiusprofile)');
	$info = @ldap_get_entries($ds, $sr);
	$dn = $info[0]['dn'];
	if ($dn == '')
		$user_exists = 'no';
	else{
		$user_exists = 'yes';
		$user_info = 1;
		$k = init_decoder();
		$cn = ($info[0]['cn'][0]) ? $info[0]['cn'][0] : '-';
		if ($decode_normal)
			$cn = decode_string($cn,$k);
		$cn_lang = $info[0]["cn;lang-$config[general_prefered_lang]"][0];
		$cn_lang = decode_string("$cn_lang", $k);
		$cn_lang = ($cn_lang) ? $cn_lang : '-';
		$telephonenumber = ($info[0]['telephonenumber'][0]) ? $info[0]['telephonenumber'][0] : '-';
		$homephone = ($info[0]['homephone'][0]) ? $info[0]['homephone'][0] : '-';
		$address = ($info[0]['postaladdress'][0]) ? $info[0]['postaladdress'][0] : '-';
		if ($decode_normal)
			$address = decode_string($address,$k);
		$address_lang = $info[0]["postaladdress;lang-$config[general_prefered_lang]"][0];
		$address_lang = decode_string("$address_lang",$k);
		$address_lang = ($address_lang) ? $address_lang : '-';
		$homeaddress = ($info[0]['homepostaladdress'][0]) ? $info[0]['homepostaladdress'][0] : '-';
		$homeaddress_lang = $info[0]["homepostaladdress;lang-$config[general_prefered_lang]"][0];
		$homeaddress_lang = decode_string("$homeaddress_lang", $k);
		$homeaddress_lang = ($homeaddress_lang) ? $homeaddress_lang : '-';
		$mobile = ($info[0]['mobile'][0]) ? $info[0]['mobile'][0] : '-';
		$fax = ($info[0]['facsimiletelephonenumber'][0]) ? $info[0]['facsimiletelephonenumber'][0] : '-';
		$url = ($info[0]['labeleduri'][0]) ? $info[0]['labeleduri'][0] : '-';
		$ou = $info[0]['ou'][0];
		if ($decode_normal)
			$ou = decode_string($ou,$k);
		$ou_lang = $info[0]["ou;lang-$config[general_prefered_lang]"][0];
		$ou_lang = decode_string("$ou_lang", $k);
		$ou_lang = ($ou_lang) ? $ou_lang : '-';
		$mail = ($info[0]['mail'][0]) ? $info[0]['mail'][0] : '-';
		$title = ($info[0]['title'][0]) ? $info[0]['title'][0] : '-';
		if ($decode_normal)
			$title = decode_string($title,$k);
		$title_lang = $info[0]["title;lang-$config[general_prefered_lang]"][0];
		$title_lang = decode_string("$title_lang", $k);
		$title_lang = ($title_lang) ? $title_lang : '-';
		$mailalt = ($info[0]['mailalternateaddress'][0]) ? $info[0]['mailalternateaddress'][0] : '-';
		$user_password_exists = ($info[0]['userpassword'][0] != '') ? 'yes' : 'no';
		foreach($attrmap as $key => $val){
			$item_vals["$key"] = $info[0]["$val"];
		}
	}
	@ldap_close($ds);
}
else
	echo "<b>Could not connect to the LDAP server</b><br>\n";
?>
