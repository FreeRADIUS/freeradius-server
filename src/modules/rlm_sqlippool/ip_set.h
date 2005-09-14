#ifndef IP_SET_H
#define IP_SET_H

/***************************************************************************
*  ip_set.h                      lm_sqlippool - FreeRADIUS SQL Module      *
*                                                                          *
*      Record a set of IP numbers                                          *
*                                                                          *
*                                                      Andrew Vignaux      *
***************************************************************************/

/*
 * Store the IP ranges in host order
 */
typedef struct ip_range {
	uint32_t h_start;
	uint32_t h_finish;
} ip_range;

typedef struct ip_set {
	int length;
	int allocated;
	ip_range * ranges;
} ip_set;

void ip_set_initialize(ip_set * ips);
void ip_set_free(ip_set * ips);
int ip_set_add(ip_set * ips, uint32_t ip);
int ip_set_test(ip_set * ips, uint32_t ip);

#endif /* IP_SET_H */
