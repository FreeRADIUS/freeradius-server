function array_change_key_case($input,$case)
{
	$NEW_ARR = array();
	foreach ($input as $val => $key){
		if ($case == CASE_UPPER)
			$K = strtoupper($key);
		else if ($case == CASE_LOWER)
			$K = strtolower($key);
		$NEW_ARR[$K] = $val;
	}

	return $NEW_ARR;
}
