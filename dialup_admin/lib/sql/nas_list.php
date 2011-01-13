<?php
require('../conf/config.php3');
require_once('../lib/functions.php3');

unset($da_name_cache);
if (isset($_SESSION['da_name_cache']))
	$da_name_cache = $_SESSION['da_name_cache'];
if ($config[sql_nas_table] != ''){

	if (is_file("../lib/sql/drivers/$config[sql_type]/functions.php3"))
		include_once("../lib/sql/drivers/$config[sql_type]/functions.php3");
	else{
		echo "<b>Could not include SQL library</b><br>\n";
		exit();
	}
	$link = @da_sql_pconnect($config);
	if ($link){
		$auth_user = $_SERVER["PHP_AUTH_USER"];
		$extra = '';
		if (isset($mappings[$auth_user][nasdb])){
			$NAS_ARR = array();
			$NAS_ARR = preg_split('/,/',$mappings[$auth_user][nasdb]);
			$extra = 'WHERE nasname IN (';
			foreach ($NAS_ARR as $nas)
				$extra .= "'$nasname',";
			unset($NAS_ARR);
			$extra = rtrim($extra,",");
			$extra .= ')';
		}
		$search = @da_sql_query($link,$config,
		"SELECT * FROM $config[sql_nas_table] $extra;");
		if ($search){
			while($row = @da_sql_fetch_array($search,$config)){
				$num = 0;
				$my_nas_name = $row['nasname'];
				if ($my_nas_name != ''){
					$nas_list[$my_nas_name]['name'] = $my_nas_name;
                                	$nas_server = $da_name_cache[$my_nas_name];
                                	if (!isset($nas_server)){
						if (!check_ip($my_nas_name))
	                                        	$nas_server = @gethostbyname($my_nas_name);
						else
							$nas_server = $my_nas_name;
                                        	if (!isset($da_name_cache) && $config[general_use_session] == 'yes'){
                                                	$da_name_cache[$my_nas_name] = $nas_server;
                                                	session_register('da_name_cache');
                                        	}
                                	}
					if ($nas_server != $my_nas_name || check_ip($nas_server))
						$nas_list[$my_nas_name]['ip'] = $nas_server;
					$nas_list[$my_nas_name]['port_num'] = $row['ports'];
					$nas_list[$my_nas_name]['community'] = $row['community'];
					$nas_list[$my_nas_name]['model'] = $row['description'];
				}
			}
		}
	}
	else
		echo "<b>Could not connect to SQL database</b><br>\n";
}

?>
