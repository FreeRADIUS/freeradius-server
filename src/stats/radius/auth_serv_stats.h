/*
 *	radiusAuthServ
 */
typedef struct {
	char	*ident;
	fr_time_delta_t	up_time;
	fr_time_delta_t	reset_time;
	uint32_t	config_reset;
	uint32_t	total_access_requests;
	uint32_t	total_invalid_requests;
	uint32_t	total_dup_access_requests;
	uint32_t	total_access_accepts;
	uint32_t	total_access_rejects;
	uint32_t	total_access_challenges;
	uint32_t	total_malformed_access_requests;
	uint32_t	total_bad_authenticators;
	uint32_t	total_packets_dropped;
	uint32_t	total_unknown_types;
} fr_stats_radius_auth_serv_t;

/*
 * fr_stats_radius_auth_serv_instance_t
 */
FR_STATS_TYPEDEF(radius_auth_serv);

extern fr_stats_link_t const fr_stats_link_radius_auth_serv;

