#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"

/*
 *  Create a (hopefully) unique Acct-Unique-Session-Id from:
 *
 * MD5(User-Name, NAS-IP-Address, NAS-Identifier, NAS-Port-Id, Acct-Session-Id)
 *
 *  Of course, this RELIES on the NAS to send the SAME information
 * in ALL Accounting packets.  Some NAS boxes may NOT send the User-Name
 * for the first Accounting Start packet, in which case this attempt
 * will fail.
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
    PW_USER_NAME,
    PW_NAS_IP_ADDRESS,
    PW_NAS_IDENTIFIER,
    PW_NAS_PORT_ID,
    PW_ACCT_SESSION_ID,
    0				/* end of array */
  };

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

/* globally exported name */
module_t rlm_acct_unique = {
  "Acct-Unique-Session-Id",
  0,				/* type: reserved */
  NULL,				/* initialization */
  NULL,				/* authorization */
  NULL,				/* authentication */
  unique_accounting,		/* accounting */
  NULL,				/* detach */
};
