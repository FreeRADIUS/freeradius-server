#ifndef _REQUEST_LIST_H
#define _REQUEST_LIST_H
/*
 * request_list.h	Hide the handling of the REQUEST list from
 *			the main server.
 *
 * Version:	$Id$
 *
 */

/*
 *  We keep the incoming requests in an array, indexed by ID.
 *
 *  Each array element contains a linked list of active requests,
 *  a count of the number of requests, and a time at which the first
 *  request in the list must be serviced.
 */
typedef struct REQUEST_LIST {
	REQUEST		*first_request;
	REQUEST		*last_request;
	int		request_count;
	time_t		last_cleaned_list;
} REQUEST_LIST;

extern REQUEST_LIST	request_list[256];

extern int rl_init(void);
extern void rl_delete(REQUEST *request);
extern void rl_add(REQUEST *request);
extern REQUEST *rl_find(REQUEST *request);
extern REQUEST *rl_find_proxy(REQUEST *request);
extern REQUEST *rl_next(REQUEST *request);

#define RL_WALK_CONTINUE (0)
#define RL_WALK_STOP     (-1)

typedef int (*RL_WALK_FUNC)(REQUEST *, void *);

extern int rl_walk(RL_WALK_FUNC walker, void *data);

#endif /* _REQUEST_LIST_H */
