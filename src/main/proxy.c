/*
 * proxy.c	Proxy stuff.
 *
 * Version:	$Id$
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<ctype.h>
#include	<string.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	<assert.h>

#include	"radiusd.h"


static uint32_t	proxy_id = 1;

static const int allowed[] = {
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

static const int trusted_allowed[] = {
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
 *	We received a response from a remote radius server.
 *	Find the original request, then return.
 *	Returns:   1 replication don't reply
 *	           0 proxy found
 *		  -1 error don't reply
 */
int proxy_receive(REQUEST *request)
{
	VALUE_PAIR	*allowed_pairs;
	int		i;
	VALUE_PAIR	*proxypair;
	VALUE_PAIR	*replicatepair;
	VALUE_PAIR	*realmpair;
	int		replicating;
        REALM           *realm;
        char            *realmname;

	/*
	 *	FIXME: calculate md5 checksum!
	 */

	proxypair = pairfind(request->config_items, PW_PROXY_TO_REALM);
	replicatepair = pairfind(request->config_items, PW_REPLICATE_TO_REALM);
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

	realmname=(char *)realmpair->strvalue;
        realm = realm_find(realmname);
	allowed_pairs = NULL;

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
			pairmove2(&allowed_pairs, &(request->proxy_reply->vps), trusted_allowed[i]);
	} else {
		/*
		 *	Only allow some attributes to be propagated from
		 *	the remote server back to the NAS, for security.
		 */
		allowed_pairs = NULL;
		for(i = 0; allowed[i]; i++)
			pairmove2(&allowed_pairs, &(request->proxy_reply->vps), allowed[i]);
	}
	
	/*
	 *	Delete the left-over attributes, and move the
	 *	allowed ones back.
	 */
	pairfree(request->proxy_reply->vps);
	request->proxy_reply->vps = allowed_pairs;

	return replicating?1:0;
}

/*
 *	Add a proxy-pair to the end of the request.
 */
static void proxy_addinfo(REQUEST *request)
{
	VALUE_PAIR		*proxy_pair;

	proxy_pair = paircreate(PW_PROXY_STATE, PW_TYPE_STRING);
	if  (proxy_pair == NULL) {
		log(L_ERR|L_CONS, "no memory");
		exit(1);
	}
	sprintf((char *)proxy_pair->strvalue, "%d", request->packet->id);
	proxy_pair->length = strlen((char *)proxy_pair->strvalue);

	pairadd(&request->proxy->vps, proxy_pair);
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

#if 0	/* This looks bad to me... the timestamp is used below to figure the
	 * next_try. The request needs to "hang around" until either the
	 * other server sends a reply or the retry count has been exceeded.
	 * Until then, it should not be eligible for the time-based cleanup.
	 * --Pac. */
	/*
	 *	Ensure that the request hangs around for a little
	 *	while longer.
	 *
	 *	FIXME: This is a hack... it should be more intelligent.
	 */
	request->timestamp += 5;
#endif

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
	} else if (replicatepair) {
		realmpair = replicatepair;
		replicating = 1;
	} else {
		/*
		 *	Neither proxy or replicate attributes are set,
		 *	so we can exit from the proxy code.
		 */
		return 0;
	}

	realmname = (char *)realmpair->strvalue;

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
	proxy_addinfo(request);

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
	rad_send(request->proxy, (char *)realm->secret);
	memcpy(request->proxysecret, realm->secret, sizeof(request->proxysecret));
	request->proxy_is_replicate = replicating;
	request->proxy_try_count = proxy_retry_count - 1;
	request->proxy_next_try = request->timestamp + proxy_retry_delay;
	delaypair = pairfind(vps, PW_ACCT_DELAY_TIME);
	request->proxy->timestamp = request->timestamp - (delaypair ? delaypair->lvalue : 0);

#if 0	/* You can't do this - the pairs are needed for the retries! --Pac. */
	/*
	 *	We can free proxy->vps now, not needed anymore.
	 */
	pairfree(request->proxy->vps);
	request->proxy->vps = NULL;
#endif

	return replicating?2:1;
}
