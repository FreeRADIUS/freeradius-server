fr_stats_link_t const fr_stats_link_radius_acc_serv = {
	.name = "fr_stats_radius_acc_serv_t",
	.root_p = &attr_acc_serv,
	.mib = "1.3.6.1.2.1.67.2.1.1",
	.size = sizeof(fr_stats_radius_acc_serv_t),
	.num_elements = 13,
	.entry = {
		{
			.da_p = &attr_acc_serv_ident,
			.type = FR_TYPE_STRING,
			.offset = offsetof(fr_stats_radius_acc_serv_t, ident),
			.size = 0,
		},
		{
			.da_p = &attr_acc_serv_up_time,
			.type = FR_TYPE_TIME_DELTA,
			.offset = offsetof(fr_stats_radius_acc_serv_t, up_time),
			.size = 4,
		},
		{
			.da_p = &attr_acc_serv_reset_time,
			.type = FR_TYPE_TIME_DELTA,
			.offset = offsetof(fr_stats_radius_acc_serv_t, reset_time),
			.size = 4,
		},
		{
			.da_p = &attr_acc_serv_config_reset,
			.type = FR_TYPE_UINT32,
			.offset = offsetof(fr_stats_radius_acc_serv_t, config_reset),
			.size = 4,
		},
		{
			.da_p = &attr_acc_serv_total_access_requests,
			.type = FR_TYPE_UINT32,
			.offset = offsetof(fr_stats_radius_acc_serv_t, total_access_requests),
			.size = 4,
		},
		{
			.da_p = &attr_acc_serv_total_invalid_requests,
			.type = FR_TYPE_UINT32,
			.offset = offsetof(fr_stats_radius_acc_serv_t, total_invalid_requests),
			.size = 4,
		},
		{
			.da_p = &attr_acc_serv_total_dup_requests,
			.type = FR_TYPE_UINT32,
			.offset = offsetof(fr_stats_radius_acc_serv_t, total_dup_requests),
			.size = 4,
		},
		{
			.da_p = &attr_acc_serv_total_responses,
			.type = FR_TYPE_UINT32,
			.offset = offsetof(fr_stats_radius_acc_serv_t, total_responses),
			.size = 4,
		},
		{
			.da_p = &attr_acc_serv_total_malformed_access_requests,
			.type = FR_TYPE_UINT32,
			.offset = offsetof(fr_stats_radius_acc_serv_t, total_malformed_access_requests),
			.size = 4,
		},
		{
			.da_p = &attr_acc_serv_total_bad_authenticators,
			.type = FR_TYPE_UINT32,
			.offset = offsetof(fr_stats_radius_acc_serv_t, total_bad_authenticators),
			.size = 4,
		},
		{
			.da_p = &attr_acc_serv_total_packets_dropped,
			.type = FR_TYPE_UINT32,
			.offset = offsetof(fr_stats_radius_acc_serv_t, total_packets_dropped),
			.size = 4,
		},
		{
			.da_p = &attr_acc_serv_total_no_records,
			.type = FR_TYPE_UINT32,
			.offset = offsetof(fr_stats_radius_acc_serv_t, total_no_records),
			.size = 4,
		},
		{
			.da_p = &attr_acc_serv_total_unknown_types,
			.type = FR_TYPE_UINT32,
			.offset = offsetof(fr_stats_radius_acc_serv_t, total_unknown_types),
			.size = 4,
		},
	},
};

