#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"

static const char rcsid[] = "$Id$";

/*
 *  Create a (hopefully) unique Acct-Unique-Session-Id from:
 *
 * MD5(NAS-IP-Address, NAS-Identifier, NAS-Port-Id,
 *     Acct-Session-Id, Acct-Session-Start-Time)
 *
 * Of course, this RELIES on the NAS to send the SAME information
 * in ALL Accounting packets.
 */
static int unique_accounting(REQUEST *request)
{
  char buffer[2048];
  char md5_buf[16];

  VALUE_PAIR *vp;
  char *p;
  int i;
  int length, left;

  /*
   * List of elements to use for creating unique ID's
   *
   * This should really be user configurable at run time.
   */
  static int array[] = {
    PW_NAS_IP_ADDRESS,
    PW_NAS_IDENTIFIER,
    PW_NAS_PORT_ID,
    PW_ACCT_SESSION_ID,
    PW_ACCT_SESSION_START_TIME,
    0				/* end of array */
  };

  /*
   *  If there is no Acct-Session-Start-Time, then go add one.
   */
  vp = pairfind(request->packet->vps, PW_ACCT_SESSION_START_TIME);
  if (!vp) {
    time_t start_time;
    
    start_time = request->timestamp;

    /*
     *  Look for Acct-Delay-Time, and subtract it from the session
     *  start time.
     */
    vp = pairfind(request->packet->vps, PW_ACCT_DELAY_TIME);
    if (vp) {
      start_time -= vp->lvalue;
    }

    /*
     *  Fudge the start time a little, so we're not TOO worried
     *  about minor variations in clocks.
     */
    start_time &= ~0x07;	/* round it to an 8-second boundary */
    
    /*
     *  Create a new Acct-Session-Start-Time attribute, and
     *  add it to the request.
     */
    vp = paircreate(PW_ACCT_SESSION_START_TIME, PW_TYPE_DATE);
    if (!vp) {
      return RLM_ACCT_FAIL;
    }
    vp->lvalue = start_time;
    pairadd(&request->packet->vps, vp);
  }

  /* initialize variables */
  p = buffer;
  left = sizeof(buffer);
  i = 0;
  length = 0;

  /* loop over items to create unique identifiers */
  while (array[i]) {
    vp = pairfind(request->packet->vps, array[i]);
    length = vp_prints(p, length, vp);
    left -= length + 1;		/* account for ',' in between elements */
    p += length;
    *(p++) = ',';		/* ensure seperation of elements */
    *p = '\0';			/* unnecessary, but possibly helpful */
  }

  /* calculate a 'unique' string based on the above information */
  librad_md5_calc(md5_buf, buffer, (p - buffer));
  sprintf(buffer, "%02x%02x%02x%02x",
	  md5_buf[0], md5_buf[1],
	  md5_buf[2], md5_buf[3]);
  
  vp = pairmake("Acct-Unique-Session-Id", buffer, 0);
  if (!vp) {
    return RLM_ACCT_OK;		/* ??? probably wrong ... */
  }

  /* add the (hopefully) unique session ID to the packet */
  pairadd(&request->packet->vps, vp);
  
  return RLM_ACCT_OK;
}

/* FIXME: unique_accounting should probably be called from preacct */
/* globally exported name */
module_t rlm_acct_unique = {
  "Acct-Unique-Session-Id",
  0,				/* type: reserved */
  NULL,				/* initialization */
  NULL,				/* authorization */
  NULL,				/* authentication */
  NULL,				/* preaccounting */
  unique_accounting,		/* accounting */
  NULL,				/* detach */
};
