/*
 *	Yep, this struct is too big, using fixed length strings
 *	is evil. But it makes things easier - for now.
 */
typedef struct conf {
	char			realm[128];
	char			radwtmp[128];
	char			radutmp[128];
	char			acctdir[128];
	char			acctdir2[128];
	char			authproxy[128];
	char			acctproxy[128];
	char			striprealm[128];
	struct conf		*next;
} CONF;

