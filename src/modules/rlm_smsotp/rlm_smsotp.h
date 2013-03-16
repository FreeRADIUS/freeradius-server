#define SMSOTP_SOCKET "/var/run/smsotp_socket"
#define SMSOTP_CHALLENGEMESSAGE "Enter Mobile PIN"
#define SMSOTP_AUTHTYPE "smsotp-reply"

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */

typedef struct smsotp_fd_t {
  pthread_mutex_t	mutex;
  const char		*path;	/* allows diff instances to use diff sockets */
  int			fd;
  struct smsotp_fd_t	*next;
} smsotp_fd_t;

typedef struct rlm_smsotp_t {
	char *smsotp_socket;
	char *smsotp_challengemessage;
	char *smsotp_authtype;
} rlm_smsotp_t;

static void _smsotp_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *, const char *);
static void _smsotp_pthread_mutex_lock(pthread_mutex_t *, const char *);
static int _smsotp_pthread_mutex_trylock(pthread_mutex_t *, const char *);
static void _smsotp_pthread_mutex_unlock(pthread_mutex_t *, const char *);

#define smsotp_pthread_mutex_init(a, b) _smsotp_pthread_mutex_init((a), (b), __func__)
#define smsotp_pthread_mutex_lock(a) _smsotp_pthread_mutex_lock((a), __func__)
#define smsotp_pthread_mutex_trylock(a) _smsotp_pthread_mutex_trylock((a), __func__)
#define smsotp_pthread_mutex_unlock(a) _smsotp_pthread_mutex_unlock((a), __func__)
