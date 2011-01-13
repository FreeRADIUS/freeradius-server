<?php
function xlat($filter,$login,$config)
{
	$string = $filter;
	if ($filter != ''){
		$string = preg_replace('/%u/',$login,$string);
		$string = preg_replace('/%U/',$_SERVER["PHP_AUTH_USER"],$string);
		$string = preg_replace('/%ma/',$mappings[$http_user][accounting],$string);
		$string = preg_replace('/%mu/',$mappings[$http_user][userdb],$string);
		$string = preg_replace('/%mn/',$mappings[$http_user][nasdb],$string);
		$string = preg_replace('/%mN/',$mappings[$http_user][nasadmin],$string);
	}

	return $string;
}
?>
