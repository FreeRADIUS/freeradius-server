<?php
function da_encrypt()
{
	$numargs=func_num_args();
	$passwd=func_get_arg(0);
	if ($numargs == 2){
		$salt=func_get_arg(1);
		return crypt($passwd,$salt);
	}
        return crypt($passwd);
}
?>
