#ifndef DETAIL_H
#define DETAIL_H
/*
 *	detail.h	Routines to handle detail files.
 *
 * Version:	$Id$
 *
 */

RCSIDH(detail_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef enum detail_state_t {
	STATE_UNOPENED = 0,
	STATE_UNLOCKED,
	STATE_HEADER,
	STATE_READING,
	STATE_QUEUED,
	STATE_RUNNING,
	STATE_NO_REPLY,
	STATE_REPLIED
} detail_state_t;

/*
 *	Allow people to revert to the old behavior if desired.
 *	Also, use the old code if we don't have threads.
 *	FIXME: delete the old (crappy) code, and enable the new
 *	code to work without threads.  One thing at a time...
 */
#ifndef WITHOUT_DETAIL_THREAD
#  ifdef HAVE_PTHREAD_H
#    define WITH_DETAIL_THREAD (1)
#  endif
#endif

typedef struct listen_detail_t {
	fr_event_t	*ev;	/* has to be first entry (ugh) */
	char const 	*name;			//!< Identifier used in log messages
	int		delay_time;
	char const	*filename;
	char const	*filename_work;
	VALUE_PAIR	*vps;
	int		work_fd;

#ifdef WITH_DETAIL_THREAD
	int		master_pipe[2];
	int		child_pipe[2];
	pthread_t	pthread_id;
#endif

	FILE		*fp;
	off_t		offset;
	detail_state_t 	state;
	time_t		timestamp;
	time_t		running;
	fr_ipaddr_t	client_ip;

	off_t		last_offset;
	off_t		timestamp_offset;
	bool		done_entry;		//!< Are we done reading this entry?
	bool		track;			//!< Do we track progress through the file?

	uint32_t	load_factor; /* 1..100 */
	uint32_t	poll_interval;
	uint32_t	retry_interval;

	int		signal;
	int		packets;
	int		tries;
	bool		one_shot;
	int		outstanding;
	int		has_rtt;
	int		srtt;
	int		rttvar;
	uint32_t	counter;
	struct timeval  last_packet;
	RADCLIENT	detail_client;
} listen_detail_t;

int detail_recv(rad_listen_t *listener);
int detail_send(rad_listen_t *listener, REQUEST *request);
void detail_free(rad_listen_t *this);
int detail_print(rad_listen_t const *this, char *buffer, size_t bufsize);
int detail_encode(UNUSED rad_listen_t *this, UNUSED REQUEST *request);
int detail_decode(UNUSED rad_listen_t *this, UNUSED REQUEST *request);
int detail_parse(CONF_SECTION *cs, rad_listen_t *this);

#ifdef __cplusplus
}
#endif

#endif /* DETAIL_H */
