typedef struct proto_cron_tab_s proto_cron_crontab_t;

typedef struct {
	unsigned int	min;
	unsigned int	max;

	bool		wildcard;
	size_t		offset;

	uint64_t	fields;
} cron_tab_t;

