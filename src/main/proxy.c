/*
 * proxy.c	Proxy stuff.
 *
 * Version:	$Id$
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<ctype.h>
#include	<string.h>
#include	<time.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	<assert.h>

#include	"radiusd.h"


static uint32_t	proxy_id = 1;

static REQUEST	*proxy_requests = NULL;

#ifdef WITH_OLD_PROXY
static int allowed [] = {
	PW_SERVICE_TYPE,
	PW_FRAMED_PROTOCOL,
	PW_FILTER_ID,
	PW_FRAMED_MTU,
	PW_FRAMED_COMPRESSION,
	PW_LOGIN_SERVICE,
	PW_REPLY_MESSAGE,
	PW_SESSION_TIMEOUT,
	PW_IDLE_TIMEOUT,
	PW_PORT_LIMIT,
	0,
};

static int trusted_allowed [] = {
	PW_SERVICE_TYPE,
	PW_FRAMED_PROTOCOL,
	PW_FILTER_ID,
	PW_FRAMED_MTU,
	PW_FRAMED_COMPRESSION,
	PW_FRAMED_IP_ADDRESS,
	PW_FRAMED_IP_NETMASK,
	PW_FRAMED_ROUTING,
	PW_FRAMED_ROUTE,
	PW_LOGIN_SERVICE,
	PW_REPLY_MESSAGE,
	PW_SESSION_TIMEOUT,
	PW_IDLE_TIMEOUT,
	PW_PORT_LIMIT,
	0,
};


/*
 *	Cleanup old outstanding requests.
 */
static void proxy_cleanup(void)
{
	REQUEST 		*a, *last, *next;
	time_t			now;

	last = NULL;
	now  = time(NULL);

	for (a = proxy_requests; a; a = next) {
		next = a->next;
		if (a->timestamp + MAX_REQUEST_TIME < now) {
			if (last)
				last->next = a->next;
			else
				proxy_requests = a->next;
			request_free(a);
			continue;
		}
		last = a;
	}
}
#endif

/*
 *	Add a proxy-pair to the end of the request.
 */
static void proxy_addinfo(RADIUS_PACKET *rp)
{
	VALUE_PAIR		*proxy_pair;

	proxy_pair = paircreate(PW_PROXY_STATE, PW_TYPE_STRING);
	if  (proxy_pair == NULL) {
		log(L_ERR|L_CONS, "no memory");
		exit(1);
	}
	sprintf(proxy_pair->strvalue, "%04x", rp->id);
	proxy_pair->length = 4;

	pairadd(&rp->vps, proxy_pair);
}

/*
 *	Relay the request to a remote server.
 *	Returns:  2 success (we replicate, caller replies normally)
 *		  1 success (we reply, caller returns without replying)
 *	          0 fail (caller falls through to normal processing)
 *		 -1 fail (we don't reply, caller returns without replying)
 */
int proxy_send(REQUEST *request)
{
	VALUE_PAIR		*proxypair;
	VALUE_PAIR		*replicatepair;
	VALUE_PAIR		*realmpair;
	VALUE_PAIR		*namepair;
	VALUE_PAIR		*strippednamepair;
	VALUE_PAIR		*delaypair;
	VALUE_PAIR		*vp, *vps;
	REALM			*realm;
	char			*realmname;
	int			replicating;

	/*
	 *	Ensure that the request hangs around for a little
	 *	while longer.
	 *
	 *	FIXME: This is a hack... it should be more intelligent.
	 */
	request->timestamp += 5;

	/* Look for proxy/replicate signs */
	/* FIXME - What to do if multiple Proxy-To/Replicate-To attrs are
	 * set...  Log an error? Actually replicate to multiple places? That
	 * would be cool. For now though, I'll just take the first one and
	 * ignore the rest. */
	proxypair = pairfind(request->config_items, PW_PROXY_TO_REALM);
	replicatepair = pairfind(request->config_items, PW_REPLICATE_TO_REALM);
	if (proxypair) {
		realmpair = proxypair;
		replicating = 0;
	} else if( replicatepair) {
		realmpair = replicatepair;
		replicating = 1;
	} else {
		/*
		 *	Neither proxy or replicate attributes are set,
		 *	so we can exit from the proxy code.
		 */
		return 0;
	}

	realmname = realmpair->strvalue;

	/*
	 *	Look for the realm, letting realm_find take care
	 *	of the "NULL" realm.
	 *
	 *	If there is no such realm, then exit.
	 *	Maybe we should log an error?
	 */
	realm = realm_find(realmname);
	if (realm == NULL) {
		return 0;
	}

	/*
	 *	Copy the request, then look up
	 *	name and plain-text password in the copy.
	 *
	 *	Note that the User-Name attribute is the *original*
	 *	as sent over by the client.  The Stripped-User-Name
	 *	attribute is the one hacked through the 'hints' file.
	 */
	vps = paircopy(request->packet->vps);
	namepair = pairfind(vps, PW_USER_NAME);
	strippednamepair = pairfind(vps, PW_STRIPPED_USER_NAME);

	/*
	 *	If there's a Stripped-User-Name attribute in the
	 *	request, then use THAT as the User-Name for the
	 *	proxied request, instead of the original name.
	 *
	 *	This is done by making a copy of the Stripped-User-Name
	 *	attribute, turning it into a User-Name attribute,
	 *	deleting the Stripped-User-Name and User-Name attributes
	 *	from the vps list, and making the new User-Name
	 *	the head of the vps list.
	 */
	if (strippednamepair) {
		vp = paircreate(PW_USER_NAME, PW_TYPE_STRING);
		if (!vp) {
			log(L_ERR|L_CONS, "no memory");
			exit(1);
		}
		memcpy(vp->strvalue, strippednamepair->strvalue,
		       sizeof(vp->strvalue));
		vp->length = strippednamepair->length;
		pairdelete(&vps, PW_USER_NAME);
		pairdelete(&vps, PW_STRIPPED_USER_NAME);
		vp->next = vps;
		namepair = vp;
		vps = vp;
	}

	/*
	 *	Remember that we sent the request to a Realm.
	 */
	pairadd(&request->packet->vps,
		pairmake("Realm", realm->realm, T_OP_EQ));

	/*
	 *	Now build a new RADIUS_PACKET and send it.
	 *
	 *	FIXME: it could be that the id wraps around too fast if
	 *	we have a lot of requests, it might be better to keep
	 *	a seperate ID value per remote server.
	 *
	 *	OTOH the remote radius server should be smart enough to
	 *	compare _both_ ID and vector. Right ?
	 */
	if ((request->proxy = rad_alloc(TRUE)) == NULL) {
		log(L_ERR|L_CONS, "no memory");
		exit(1);
	}

	/*
	 *	Proxied requests get sent out the proxy FD ONLY.
	 */
	request->proxy->sockfd = proxyfd;

	request->proxy->code = request->packet->code;
	request->proxy->dst_ipaddr = realm->ipaddr;
	if (request->packet->code == PW_AUTHENTICATION_REQUEST)
		request->proxy->dst_port = realm->auth_port;
	else
		request->proxy->dst_port = realm->acct_port;
	assert(request->proxy->vps == NULL);
	request->proxy->vps = vps;

	/*
	 *	Add the request to the list of outstanding requests.
	 *	Note that request->proxy->id is a 16 bits value,
	 *	while rad_send sends only the 8 least significant
	 *	bits of that same value.
	 */
	request->proxy->id = (proxy_id++) & 0xff;
	proxy_id &= 0xffff;

	/*
	 *	Add PROXY_STATE attribute.
	 */
	proxy_addinfo(request->proxy);

	/*
	 *	If there is no PW_CHAP_CHALLENGE attribute but there
	 *	is a PW_CHAP_PASSWORD we need to add it since we can't
	 *	use the request authenticator anymore - we changed it.
	 */
	if (pairfind(vps, PW_CHAP_PASSWORD) &&
	    pairfind(vps, PW_CHAP_CHALLENGE) == NULL) {
		vp = paircreate(PW_CHAP_CHALLENGE, PW_TYPE_STRING);
		if (!vp) {
			log(L_ERR|L_CONS, "no memory");
			exit(1);
		}
		vp->length = AUTH_VECTOR_LEN;
		memcpy(vp->strvalue, request->packet->vector, AUTH_VECTOR_LEN);
		pairadd(&vps, vp);
	}

	/*
	 *	Send the request.
	 */
	rad_send(request->proxy, realm->secret);
	memcpy(request->proxysecret, realm->secret, sizeof(request->proxysecret));
	request->proxy_is_replicate = replicating;
	request->proxy_try_count = RETRY_COUNT - 1;
	request->proxy_next_try = request->timestamp + RETRY_DELAY;
	delaypair = pairfind(vps, PW_ACCT_DELAY_TIME);
	request->proxy->timestamp = request->timestamp - (delaypair ? delaypair->lvalue : 0);

#if 0
	/*
	 *	We can free proxy->vps now, not needed anymore.
	 */
	pairfree(request->proxy->vps);
	request->proxy->vps = NULL;
#endif

	return replicating?2:1;
}

/*
 *  FIXME: Maybe keeping the proxy_requests list sorted by
 *  proxy_next_try would be cheaper than all this searching.
 */
struct timeval *proxy_setuptimeout(struct timeval *tv)
{
	time_t now = time(NULL);
	time_t difference, smallest;
	int foundone = 0;
	REQUEST *p;

	smallest = 0;
	for (p = proxy_requests; p; p = p->next) {
	  if (!p->proxy_is_replicate)
	    continue;
	  difference = p->proxy_next_try - now;
	  if (!foundone) {
	    foundone = 1;
	    smallest = difference;
	  } else {
	    if (difference < smallest)
	      smallest = difference;
	  }
	}
	if (!foundone)
	  return 0;

	tv->tv_sec = smallest;
	tv->tv_usec = 0;
	return tv;
}

void proxy_retry(void)
{
	time_t now = time(NULL);
	REQUEST *p;

	for (p = proxy_requests; p; p = p->next) {
	  if (p->proxy_next_try <= now) {
	    if (p->proxy_try_count) {
	      --p->proxy_try_count;
	      p->proxy_next_try = now + RETRY_DELAY;
	      
	      /* Fix up Acct-Delay-Time */
	      if (p->proxy->code == PW_ACCOUNTING_REQUEST) {
		VALUE_PAIR *delaypair;
		delaypair = pairfind(p->proxy->vps, PW_ACCT_DELAY_TIME);

		if (!delaypair) {
		  delaypair = paircreate(PW_ACCT_DELAY_TIME, PW_TYPE_INTEGER);
		  if (!delaypair) {
		    log(L_ERR|L_CONS, "no memory");
		    exit(1);
		  }
		  pairadd(&p->proxy->vps, delaypair);
		}
		delaypair->lvalue = now - p->proxy->timestamp;
		
		/* Must recompile the valuepairs to wire format */
		free(p->proxy->data);
		p->proxy->data = NULL;
	      }
	      
	      rad_send(p->proxy, p->proxysecret);
	    }
	  }
	}
}
