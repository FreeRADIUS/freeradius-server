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

#include	"radiusd.h"


static int	proxy_id = 1;
static REQUEST	*proxy_requests;

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
 *	Add the request to the list.
 */
static int proxy_addrequest(REQUEST *request, int *proxied_packet_id)
{
	REQUEST		*a, *last = NULL;
	int		id = -1;

	/*
	 *	See if we already have a similar outstanding request.
	 */
	for (a = proxy_requests; a; a = a->next) {
		if (a->packet->src_ipaddr == request->packet->src_ipaddr &&
		    a->packet->id == request->packet->id &&
		    !memcmp(a->packet->vector, request->packet->vector, 16))
			break;
		last = a;
	}
	if (a) {
		/*
		 *	Yes, this is a retransmit so delete the
		 *	old request.
		 */
		id = a->proxy->id;
		if (last)
			last->next = a->next;
		else
			proxy_requests = a->next;
		request_free(a);
		free(a);
	}
	if (id < 0) {
		id = (*proxied_packet_id)++;
		*proxied_packet_id &= 0xFFFF;
	}

	request->next = NULL;
	request->child_pid = -1;
	request->timestamp = time(NULL);

	request->next = proxy_requests;
	proxy_requests = request;

	/* Now get it off the pending request list in radiusd.c */
	remove_from_request_list(request);

	return id;
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
	 *	First cleanup old outstanding requests.
	 */
	proxy_cleanup();

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
	 *	Perhaps accounting proxying was turned off.
	 */
	if ((request->packet->code == PW_ACCOUNTING_REQUEST) &&
	    (realm->acct_port == 0)) {
		/* log a warning that the packet isn't getting proxied ??? */
		return 0;
	}

	/*
	 *	Perhaps authentication proxying was turned off.
	 */
	if ((request->packet->code == PW_AUTHENTICATION_REQUEST) &&
	    (realm->auth_port == 0)) {
		/* log a warning that the packet isn't getting proxied ??? */
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
		vp = paircopy(strippednamepair);
		vp->attribute = namepair->attribute;
		memcpy(vp->name, namepair->name, sizeof(vp->name));
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
	if ((request->proxy = rad_alloc(0)) == NULL) {
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
	request->proxy->vps = vps;

	printf("Destination port: %d, server %s (%d/%d)\n",
		request->proxy->dst_port, realm->server,
		realm->auth_port, realm->acct_port);

	/*
	 *	XXX: we re-use the vector from the original request
	 *	here, since that's easy for retransmits ...
	 */
	memcpy(request->proxy->vector, request->packet->vector,
		AUTH_VECTOR_LEN);

	/*
	 *	Add the request to the list of outstanding requests.
	 *	Note that request->proxy->id is a 16 bits value,
	 *	while rad_send sends only the 8 least significant
	 *	bits of that same value.
	 */
	request->proxy->id = proxy_addrequest(request, &proxy_id);

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
		if (!(vp = paircreate(PW_CHAP_CHALLENGE, PW_TYPE_STRING))) {
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
 *	We received a response from a remote radius server.
 *	Find the original request, then return.
 *	Returns:   1 replication don't reply
 *	           0 proxy found
 *		  -1 error don't reply
 */
int proxy_receive(REQUEST *request)
{
	VALUE_PAIR	*vp, *last, *prev, *x;
	VALUE_PAIR	*allowed_pairs;
	REQUEST	*oldreq, *lastreq;
	char		*s;
	int		pp = -1;
	int		i;
	VALUE_PAIR	*proxypair;
	VALUE_PAIR	*replicatepair;
	VALUE_PAIR	*realmpair;
	int		replicating;
        REALM           *realm;
        char            *realmname;

	/*
	 *	First cleanup old outstanding requests.
	 */
	proxy_cleanup();

	/*
	 *	FIXME: calculate md5 checksum!
	 */

	/*
	 *	Find the last PROXY_STATE attribute.
	 */
	oldreq  = NULL;
	lastreq = NULL;
	last    = NULL;
	x       = NULL;
	prev    = NULL;

	for (vp = request->packet->vps; vp; vp = vp->next) {
		if (vp->attribute == PW_PROXY_STATE) {
			prev = x;
			last = vp;
		}
		x = vp;
	}
	if (last && last->strvalue) {
		/*
		 *	Merit really rapes the Proxy-State attribute.
		 *	See if it still is a valid 4-digit hex number.
		 */
		s = last->strvalue;
		if (strlen(s) == 4 && isxdigit(s[0]) && isxdigit(s[1]) &&
		    isxdigit(s[2]) && isxdigit(s[3])) {
			pp = strtol(last->strvalue, NULL, 16);
		} else {
			log(L_PROXY, "server %s mangled Proxy-State attribute",
			client_name(request->packet->src_ipaddr));
		}
	}

	/*
	 *	Now find it in the list of outstanding requests.
	 */

	for (oldreq = proxy_requests; oldreq; oldreq = oldreq->next) {
		/*
		 *	Some servers drop the proxy pair. So
		 *	compare in another way if needed.
		 */
		if (pp >= 0 && pp == oldreq->proxy->id)
			break;
		if (pp < 0 &&
		    request->packet->src_ipaddr == oldreq->proxy->dst_ipaddr &&
		    request->packet->id     == (oldreq->proxy->id & 0xFF))
			break;
		lastreq = oldreq;
	}

	if (oldreq == NULL) {
		log(L_PROXY, "Unrecognized proxy reply from server %s - ID %d",
			client_name(request->packet->src_ipaddr),
			request->packet->id);
		return -1;
	}

	/*
	 *	Remove oldreq from list.
	 */
	if (lastreq)
		lastreq->next = oldreq->next;
	else
		proxy_requests = oldreq->next;

	/*
	 *	Remove proxy pair from list.
	 */
	if (last) {
		if (prev)
			prev->next = last->next;
		else
			request->packet->vps = last->next;
	}

	proxypair = pairfind(oldreq->config_items, PW_PROXY_TO_REALM);
	replicatepair = pairfind(oldreq->config_items, PW_REPLICATE_TO_REALM);
	if(proxypair) {
		realmpair=proxypair;
		replicating=0;
	} else if(replicatepair) {
		realmpair=replicatepair;
		replicating=1;
	} else {
		log(L_PROXY, "Proxy reply to packet with no Realm");
		return -1;
	}
	realmname=realmpair->strvalue;
	/* FIXME - this "NULL" realm is probably broken now. Does anyone
	 * still need it? */
        realm = realm_find(realmname ? realmname : "NULL");

	/* FIXME - do we want to use the trusted/allowed filters on replicate
	 * replies, which are not going to be used for anything except maybe
	 * a log file? */
	if (realm->trusted) {
	/*
	 *	Only allow some attributes to be propagated from
	 *	the remote server back to the NAS, for security.
	 */
	allowed_pairs = NULL;
	for(i = 0; trusted_allowed[i]; i++)
		pairmove2(&allowed_pairs, &(request->packet->vps), trusted_allowed[i]);
	} else {
	/*
	 *	Only allow some attributes to be propagated from
	 *	the remote server back to the NAS, for security.
	 */
	allowed_pairs = NULL;
	for(i = 0; allowed[i]; i++)
		pairmove2(&allowed_pairs, &(request->packet->vps), allowed[i]);
	}

	/*
	 *	Now rebuild the AUTHREQ struct, so that the
	 *	normal functions can process it.
	 */
	request->proxy = oldreq->proxy;
	oldreq->proxy = NULL;
	request->proxy->vps  = allowed_pairs;
	request->proxy->code = request->packet->code;

	pairfree(request->packet->vps);
	free(request->packet);
	request->packet = oldreq->packet;
	oldreq->packet = NULL;
	request->username = oldreq->username;

	request->timestamp = oldreq->timestamp;

	request_free(oldreq);

	return replicating?1:0;
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
