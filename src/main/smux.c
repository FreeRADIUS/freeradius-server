/* SNMP support
 * Copyright (C) 2000 Jochen Friedrich <jochen@scram.de>
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

static const char rcsid[] =
"$Id$";

#include "autoconf.h"

#ifdef WITH_SNMP

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#include <asn1.h>
#include <snmp.h>
#include <snmp_impl.h>

#include "radiusd.h"
#include "smux.h"

#define min(A,B) ((A) < (B) ? (A) : (B))

extern enum smux_event smux_event;


/* SMUX subtree vector. */
struct list *treelist = NULL;

/* SMUX oid. */
oid *smux_oid;
size_t smux_oid_len;

/* SMUX password. */
extern char *smux_password;

/* SNMP write access allowed */
extern int snmp_write_access;

/* SMUX socket */
extern int smuxfd;

/* SMUX failure count. */
int fail = 0;

void *
oid_copy (void *dest, void *src, size_t size)
{
  return memcpy (dest, src, size * sizeof (oid));
}

void
oid2in_addr (oid oid[], int len, struct in_addr *addr)
{
  int i;
  u_char *pnt;
  
  if (len == 0)
    return;

  pnt = (u_char *) addr;

  for (i = 0; i < len; i++)
    *pnt++ = oid[i];
}

void
oid_copy_addr (oid oid[], struct in_addr *addr, int len)
{
  int i;
  u_char *pnt;
  
  if (len == 0)
    return;

  pnt = (u_char *) addr;

  for (i = 0; i < len; i++)
    oid[i] = *pnt++;
}

int
oid_compare (oid *o1, int o1_len, oid *o2, int o2_len)
{
  int i;

  for (i = 0; i < min (o1_len, o2_len); i++)
    {
      if (o1[i] < o2[i])
	return -1;
      else if (o1[i] > o2[i])
	return 1;
    }
  if (o1_len < o2_len)
    return -1;
  if (o1_len > o2_len)
    return 1;

  return 0;
}

int
oid_compare_part (oid *o1, int o1_len, oid *o2, int o2_len)
{
  int i;

  for (i = 0; i < min (o1_len, o2_len); i++)
    {
      if (o1[i] < o2[i])
	return -1;
      else if (o1[i] > o2[i])
	return 1;
    }
  if (o1_len < o2_len)
    return -1;

  return 0;
}

void
smux_oid_dump (char *prefix, oid *oid, size_t oid_len)
{
  int i;
  int first = 1;
  char buf[MAX_OID_LEN * 3];

  buf[0] = '\0';

  for (i = 0; i < oid_len; i++)
    {
      sprintf (buf + strlen (buf), "%s%d", first ? "" : ".", (int) oid[i]);
      first = 0;
    }
  DEBUG2 ("%s: %s", prefix, buf); 
}

static int
smux_sock ()
{
  int ret;
  int on = 1;
#ifdef HAVE_IPV6
  struct addrinfo hints, *res0, *res;
  int gai;
#else
  struct sockaddr_in serv;
  struct servent *sp;
#endif
  int fd;

#ifdef HAVE_IPV6
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  gai = getaddrinfo(NULL, "smux", &hints, &res0);
  if (gai == EAI_SERVICE)
    {
      char servbuf[NI_MAXSERV];
      sprintf(servbuf,"%d",SMUX_PORT_DEFAULT);
      gai = getaddrinfo(NULL, servbuf, &hints, &res0);
    }
  if (gai)
    {
      DEBUG("Cannot locate loopback service smux");
      return -1;
    }
  for(res=res0; res; res=res->ai_next)
    {
      fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
      if (fd < 0)
	continue;
      setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof (on));
#ifdef SO_REUSEPORT
      setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof (on));
#endif
      ret = connect (fd, res->ai_addr, res->ai_addrlen);
      if (ret < 0)
	{
	  close(fd);
	  fd = -1;
	  continue;
	}
      break;
    }
  freeaddrinfo(res0);
  if (fd < 0)
    DEBUG ("Can't connect to SNMP agent with SMUX");
#else
  fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    {
      DEBUG ("Can't make socket for SNMP");
      return -1;
    }

  memset (&serv, 0, sizeof (struct sockaddr_in));
  serv.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
  serv.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */

  sp = getservbyname ("smux", "tcp");
  if (sp != NULL) 
    serv.sin_port = sp->s_port;
  else
    serv.sin_port = htons (SMUX_PORT_DEFAULT);

  serv.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof (on));
#ifdef SO_REUSEPORT
  setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof (on));
#endif

  ret = connect (fd, (struct sockaddr *) &serv, sizeof (struct sockaddr_in));
  if (ret < 0)
    {
      close (fd);
      DEBUG ("Can't connect to SNMP agent with SMUX: %s", strerror(errno));
      smuxfd = -1;
    }
#endif
  return fd;
}

void
smux_getresp_send (oid objid[], size_t objid_len, long reqid, long errstat,
		   long errindex, u_char val_type, void *arg, size_t arg_len)
{
  int ret;
  u_char buf[BUFSIZ];
  u_char *ptr, *h1, *h1e, *h2, *h2e;
  int len, length;

  ptr = buf;
  len = BUFSIZ;
  length = len;

  DEBUG2("SMUX GETRSP send");
  DEBUG2("SMUX GETRSP reqid: %d", reqid);

  h1 = ptr;
  /* Place holder h1 for complete sequence */
  ptr = asn_build_sequence (ptr, &len, (u_char) SMUX_GETRSP, 0);
  h1e = ptr;
 
  ptr = asn_build_int (ptr, &len,
		       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &reqid, sizeof (reqid));

  DEBUG2("SMUX GETRSP errstat: %d", errstat);

  ptr = asn_build_int (ptr, &len,
		       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &errstat, sizeof (errstat));
  DEBUG2("SMUX GETRSP errindex: %d", errindex);

  ptr = asn_build_int (ptr, &len,
		       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &errindex, sizeof (errindex));

  h2 = ptr;
  /* Place holder h2 for one variable */
  ptr = asn_build_sequence (ptr, &len, 
			   (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
			   0);
  h2e = ptr;

  ptr = snmp_build_var_op (ptr, objid, &objid_len, 
			   val_type, arg_len, arg, &len);

  /* Now variable size is known, fill in size */
  asn_build_sequence(h2,&length,(u_char)(ASN_SEQUENCE|ASN_CONSTRUCTOR),ptr-h2e);

  /* Fill in size of whole sequence */
  asn_build_sequence(h1,&length,(u_char)SMUX_GETRSP,ptr-h1e);

  DEBUG2("SMUX getresp send: %d", ptr - buf);
  
  ret = send (smuxfd, buf, (ptr - buf), 0);
}

char *
smux_var (char *ptr, int len, oid objid[], size_t *objid_len,
          size_t *var_val_len,
          u_char *var_val_type,
          void **var_value)
{
  u_char type;
  u_char val_type;
  size_t val_len;
  u_char *val;

  DEBUG2("SMUX var parse: len %d", len);

  /* Parse header. */
  ptr = asn_parse_header (ptr, &len, &type);
  
  DEBUG2("SMUX var parse: type %d len %d", type, len);
  DEBUG2("SMUX var parse: type must be %d", (ASN_SEQUENCE | ASN_CONSTRUCTOR));

  /* Parse var option. */
  *objid_len = MAX_OID_LEN;
  ptr = snmp_parse_var_op(ptr, objid, objid_len, &val_type, 
			  &val_len, &val, &len);

  if (var_val_len)
    *var_val_len = val_len;

  if (var_value)
    *var_value = (void*) val;

  if (var_val_type)
    *var_val_type = val_type;

  /* Requested object id length is objid_len. */
  smux_oid_dump ("Request OID", objid, *objid_len);

  DEBUG2 ("SMUX val_type: %d", val_type);

  /* Check request value type. */
  switch (val_type)
    {
    case ASN_NULL:
      /* In case of SMUX_GET or SMUX_GET_NEXT val_type is set to
         ASN_NULL. */
      DEBUG2 ("ASN_NULL");
      break;

    case ASN_INTEGER:
      DEBUG2 ("ASN_INTEGER");
      break;
    case ASN_COUNTER:
    case ASN_GAUGE:
    case ASN_TIMETICKS:
    case ASN_UINTEGER:
      DEBUG2 ("ASN_COUNTER");
      break;
    case ASN_COUNTER64:
      DEBUG2 ("ASN_COUNTER64");
      break;
    case ASN_IPADDRESS:
      DEBUG2 ("ASN_IPADDRESS");
      break;
    case ASN_OCTET_STR:
      DEBUG2 ("ASN_OCTET_STR");
      break;
    case ASN_OPAQUE:
    case ASN_NSAP:
    case ASN_OBJECT_ID:
      DEBUG2 ("ASN_OPAQUE");
      break;
    case SNMP_NOSUCHOBJECT:
      DEBUG2 ("SNMP_NOSUCHOBJECT");
      break;
    case SNMP_NOSUCHINSTANCE:
      DEBUG2 ("SNMP_NOSUCHINSTANCE");
      break;
    case SNMP_ENDOFMIBVIEW:
      DEBUG2 ("SNMP_ENDOFMIBVIEW");
      break;
    case ASN_BIT_STR:
      DEBUG2 ("ASN_BIT_STR");
      break;
    default:
      DEBUG2 ("Unknown type");
      break;
    }
  return ptr;
}

/* NOTE: all 3 functions (smux_set, smux_get & smux_getnext) are based on
   ucd-snmp smux and as such suppose, that the peer receives in the message
   only one variable. Fortunately, IBM seems to do the same in AIX. */

int
smux_set (oid *reqid, size_t *reqid_len,
          u_char val_type, void *val, size_t val_len, int action)
{
  int j;
  struct subtree *subtree;
  struct variable *v;
  struct list *l;
  int subresult;
  oid *suffix;
  int suffix_len;
  int result;
  u_char *statP = NULL;
  WriteMethod *write_method = NULL;

  if (!snmp_write_access)
    return SNMP_ERR_NOSUCHNAME;

  /* Check */
  for (l = treelist; l; l=l->next)
    {
      subtree = l->data;
      subresult = oid_compare_part (reqid, *reqid_len,
                                    subtree->name, subtree->name_len);

      /* Subtree matched. */
      if (subresult == 0)
        {
          /* Prepare suffix. */
          suffix = reqid + subtree->name_len;
          suffix_len = *reqid_len - subtree->name_len;
          result = subresult;

          /* Check variables. */
          for (j = 0; j < subtree->variables_num; j++)
            {
              v = &subtree->variables[j];

              /* Always check suffix */
              result = oid_compare_part (suffix, suffix_len,
                                         v->name, v->namelen);

              /* This is exact match so result must be zero. */
              if (result == 0)
                {
                  DEBUG2 ("SMUX function call index is %d", v->magic);

                  statP = (*v->findVar) (v, suffix, &suffix_len, 1,
                    &val_len, &write_method);

                  if (write_method)
                    {
                      return (*write_method)(action, val, val_type, val_len, statP, suffix, suffix_len);

                    }
                  else
                    {
                      return SNMP_ERR_READONLY;
                    }
                }

              /* If above execution is failed or oid is small (so
                 there is no further match). */
              if (result < 0)
                return SNMP_ERR_NOSUCHNAME;
            }
        }
    }
  return SNMP_ERR_NOSUCHNAME;
}

int
smux_get (oid *reqid, size_t *reqid_len, int exact, 
	  u_char *val_type,void **val, size_t *val_len)
{
  int j;
  struct subtree *subtree;
  struct variable *v;
  struct list *l;
  int subresult;
  oid *suffix;
  int suffix_len;
  int result;
  WriteMethod *write_method=NULL;

  /* Check */
  for (l = treelist; l; l=l->next)
    {
      subtree = l->data;
      subresult = oid_compare_part (reqid, *reqid_len, 
				    subtree->name, subtree->name_len);

      /* Subtree matched. */
      if (subresult == 0)
	{
	  /* Prepare suffix. */
	  suffix = reqid + subtree->name_len;
	  suffix_len = *reqid_len - subtree->name_len;
	  result = subresult;

	  /* Check variables. */
	  for (j = 0; j < subtree->variables_num; j++)
	    {
	      v = &subtree->variables[j];

	      /* Always check suffix */
	      result = oid_compare_part (suffix, suffix_len,
					 v->name, v->namelen);

	      /* This is exact match so result must be zero. */
	      if (result == 0)
		{
		  DEBUG2 ("SMUX function call index is %d", v->magic);

		  *val = (*v->findVar) (v, suffix, &suffix_len, exact,
		    val_len, &write_method);

		  /* There is no instance. */
		  if (*val == NULL)
		    return SNMP_ERR_NOSUCHNAME;

		  /* Call is suceed. */
		  *val_type = v->type;

		  return 0;
		}

	      /* If above execution is failed or oid is small (so
                 there is no further match). */
	      if (result < 0)
		return SNMP_ERR_NOSUCHNAME;
	    }
	}
    }
  return SNMP_ERR_NOSUCHNAME;
}

int
smux_getnext (oid *reqid, size_t *reqid_len, int exact, 
		 u_char *val_type,void **val, size_t *val_len)
{
  int j;
  oid save[MAX_OID_LEN];
  int savelen = 0;
  struct subtree *subtree;
  struct variable *v;
  struct list *l;
  int subresult;
  oid *suffix;
  int suffix_len;
  int result;
  WriteMethod *write_method=NULL;

  /* Save incoming request. */
  oid_copy (save, reqid, *reqid_len);
  savelen = *reqid_len;

  /* Check for best matching subtree */

  for (l = treelist; l; l=l->next)
    {
      subtree = l->data;

      subresult = oid_compare_part (reqid, *reqid_len, 
				    subtree->name, subtree->name_len);

     /* If request is in the tree. The agent has to make sure we
        only receive requests we have registered for. */
     /* Unfortunately, that's not true. In fact, a SMUX subagent has to
        behave as if it manages the whole SNMP MIB tree itself. It's the
        duty of the master agent to collect the best answer and return it
        to the manager. See RFC 1227 chapter 3.1.6 for the glory details
        :-). ucd-snmp really behaves bad here as it actually might ask
        multiple times for the same GETNEXT request as it throws away the
        answer when it expects it in a different subtree and might come
        back later with the very same request. --jochen */

      if (subresult <= 0)
	{
	  /* Prepare suffix. */
	  suffix = reqid + subtree->name_len;
	  suffix_len = *reqid_len - subtree->name_len;
	  if (subresult < 0)
	    {
	      oid_copy(reqid, subtree->name, subtree->name_len);
	      *reqid_len = subtree->name_len;
	    }
	  for (j = 0; j < subtree->variables_num; j++)
	    {
	      result = subresult;
	      v = &subtree->variables[j];

	      /* Next then check result >= 0. */
	      if (result == 0)
		result = oid_compare_part (suffix, suffix_len,
					   v->name, v->namelen);

	      if (result <= 0)
		{
		  DEBUG2 ("SMUX function call index is %d", v->magic);
		  if(result<0)
		    {
		      oid_copy(suffix, v->name, v->namelen);
		      suffix_len = v->namelen;
		    }
		  *val = (*v->findVar) (v, suffix, &suffix_len, exact,
		    val_len, &write_method);
		  *reqid_len = suffix_len + subtree->name_len;
		  if (*val)
		    {
		      *val_type = v->type;
		      return 0;
		    }
		}
	    }
	}
    }
  memcpy (reqid, save, savelen * sizeof(oid));
  *reqid_len = savelen;

  return SNMP_ERR_NOSUCHNAME;
}

/* GET message header. */
char *
smux_parse_get_header (char *ptr, size_t *len, long *reqid)
{
  u_char type;
  long errstat;
  long errindex;

  /* Request ID. */
  ptr = asn_parse_int (ptr, len, &type, reqid, sizeof (*reqid));

  DEBUG2 ("SMUX GET reqid: %d len: %d", (int) *reqid, (int) *len);

  /* Error status. */
  ptr = asn_parse_int (ptr, len, &type, &errstat, sizeof (errstat));

  DEBUG2 ("SMUX GET errstat %d len: %d", errstat, *len);

  /* Error index. */
  ptr = asn_parse_int (ptr, len, &type, &errindex, sizeof (errindex));

  DEBUG2 ("SMUX GET errindex %d len: %d", errindex, *len);

  return ptr;
}

void
smux_parse_set (char *ptr, size_t len, int action)
{
  long reqid;
  oid oid[MAX_OID_LEN];
  size_t oid_len;
  u_char val_type;
  void *val;
  size_t val_len;
  int ret;

  DEBUG2 ("SMUX SET(%s) message parse: len %d",
    (RESERVE1 == action) ? "RESERVE1" : ((FREE == action) ? "FREE" : "COMMIT"),
    len);

  /* Parse SET message header. */
  ptr = smux_parse_get_header (ptr, &len, &reqid);

  /* Parse SET message object ID. */
  ptr = smux_var (ptr, len, oid, &oid_len, &val_len, &val_type, &val);

  ret = smux_set (oid, &oid_len, val_type, val, val_len, action);
  DEBUG2 ("SMUX SET ret %d", ret);

  /* Return result. */
  if (RESERVE1 == action)
    smux_getresp_send (oid, oid_len, reqid, ret, 3, ASN_NULL, NULL, 0);
}

void
smux_parse_get (char *ptr, size_t len, int exact)
{
  long reqid;
  oid oid[MAX_OID_LEN];
  size_t oid_len;
  u_char val_type;
  void *val;
  size_t val_len;
  int ret;

  DEBUG2 ("SMUX GET message parse: len %d", len);
  
  /* Parse GET message header. */
  ptr = smux_parse_get_header (ptr, &len, &reqid);
  
  /* Parse GET message object ID. We needn't the value come */
  ptr = smux_var (ptr, len, oid, &oid_len, NULL, NULL, NULL);

  /* Traditional getstatptr. */
  if (exact)
    ret = smux_get (oid, &oid_len, exact, &val_type, &val, &val_len);
  else
    ret = smux_getnext (oid, &oid_len, exact, &val_type, &val, &val_len);

  /* Return result. */
  if (ret == 0)
    smux_getresp_send (oid, oid_len, reqid, 0, 0, val_type, val, val_len);
  else
    smux_getresp_send (oid, oid_len, reqid, ret, 3, ASN_NULL, NULL, 0);
}

/* Parse SMUX_CLOSE message. */
void
smux_parse_close (char *ptr, int len)
{
  long reason = 0;

  while (len--)
    {
      reason = (reason << 8) | (long) *ptr;
      ptr++;
    }
  DEBUG ("SMUX_CLOSE with reason: %d", reason);
}

/* SMUX_RRSP message. */
void
smux_parse_rrsp (char *ptr, int len)
{
  char val;
  long errstat;
  
  ptr = asn_parse_int (ptr, &len, &val, &errstat, sizeof (errstat));

  DEBUG2 ("SMUX_RRSP value: %d errstat: %d", val, errstat);
}

/* Parse SMUX message. */
int
smux_parse (char *ptr, int len)
{
  /* this buffer we'll use for SOUT message. We could allocate it with malloc and 
     save only static pointer/lenght, but IMHO static buffer is a faster solusion */
  static u_char sout_save_buff[SMUXMAXPKTSIZE];
  static int sout_save_len = 0;

  int len_income = len; /* see note below: YYY */
  u_char type;
  u_char rollback;

  rollback = ptr[2]; /* important only for SMUX_SOUT */

process_rest: /* see note below: YYY */

  /* Parse SMUX message type and subsequent length. */
  ptr = asn_parse_header (ptr, &len, &type);

  DEBUG2 ("SMUX message received type: %d rest len: %d", type, len);

  switch (type)
    {
    case SMUX_OPEN:
      /* Open must be not send from SNMP agent. */
      DEBUG ("SMUX_OPEN received: resetting connection.");
      return -1;
      break;
    case SMUX_RREQ:
      /* SMUX_RREQ message is invalid for us. */
      DEBUG ("SMUX_RREQ received: resetting connection.");
      return -1;
      break;
    case SMUX_SOUT:
      /* SMUX_SOUT message is now valied for us. */
      DEBUG2 ("SMUX_SOUT(%s)", rollback ? "rollback" : "commit");

      if (sout_save_len > 0)
        {
          smux_parse_set (sout_save_buff, sout_save_len, rollback ? FREE : COMMIT);
          sout_save_len = 0;
        }
      else
        DEBUG ("SMUX_SOUT sout_save_len=%d - invalid", (int) sout_save_len);

      if (len_income > 3) 
        {
          /* YYY: this strange code has to solve the "slow peer"
             problem: When agent sends SMUX_SOUT message it doesn't
             wait any responce and may send some next message to
             subagent. Then the peer in 'smux_read()' will recieve
             from socket the 'concatenated' buffer, contaning both
             SMUX_SOUT message and the next one
             (SMUX_GET/SMUX_GETNEXT/SMUX_GET). So we should check: if
             the buffer is longer than 3 ( length of SMUX_SOUT ), we
             must process the rest of it.  This effect may be observed
             if DEBUG is set to >1 */
          ptr++;
          len = len_income - 3;
          goto process_rest;
        }
      break;
    case SMUX_GETRSP:
      /* SMUX_GETRSP message is invalid for us. */
      DEBUG ("SMUX_GETRSP received: resetting connection.");
      return -1;
      break;
    case SMUX_CLOSE:
      /* Close SMUX connection. */
      DEBUG2 ("SMUX_CLOSE");
      smux_parse_close (ptr, len);
      return -1;
      break;
    case SMUX_RRSP:
      /* This is response for register message. */
      DEBUG2 ("SMUX_RRSP");
      smux_parse_rrsp (ptr, len);
      break;
    case SMUX_GET:
      /* Exact request for object id. */
      DEBUG2 ("SMUX_GET");
      smux_parse_get (ptr, len, 1);
      break;
    case SMUX_GETNEXT:
      /* Next request for object id. */
      DEBUG2 ("SMUX_GETNEXT");
      smux_parse_get (ptr, len, 0);
      break;
    case SMUX_SET:
      /* SMUX_SET is supported with some limitations. */
      DEBUG2 ("SMUX_SET");

      /* save the data for future SMUX_SOUT */
      memcpy (sout_save_buff, ptr, len);
      sout_save_len = len;
      smux_parse_set (ptr, len, RESERVE1);
      break;
    default:
      DEBUG ("Unknown type: %d", type);
      break;
    }
  return 0;
}

/* SMUX message read function. */
int
smux_read ()
{
  int len;
  u_char buf[SMUXMAXPKTSIZE];
  int ret;

  smux_event=SMUX_NONE;
  DEBUG2 ("SMUX read start");

  /* Read message from SMUX socket. */
  len = recv (smuxfd, buf, SMUXMAXPKTSIZE, 0);

  if (len < 0)
    {
      DEBUG ("Can't read all SMUX packet: %s", strerror (errno));
      close (smuxfd);
      smuxfd = -1;
      smux_event=SMUX_CONNECT;
      return -1;
    }

  if (len == 0)
    {
      DEBUG ("SMUX connection closed: %d", smuxfd);
      close (smuxfd);
      smuxfd = -1;
      smux_event=SMUX_CONNECT;
      return -1;
    }

  DEBUG2 ("SMUX read len: %d", len);

  /* Parse the message. */
  ret = smux_parse (buf, len);

  if (ret < 0)
    {
      close (smuxfd);
      smuxfd = -1;
      smux_event=SMUX_CONNECT;
      return -1;
    }

  smux_event=SMUX_READ;

  return 0;
}

int
smux_open ()
{
  u_char buf[BUFSIZ];
  u_char *ptr;
  int len;
  u_long version;
  u_char progname[] = "radiusd";

  smux_oid_dump ("SMUX open oid", smux_oid, smux_oid_len);
  DEBUG2 ("SMUX open progname: %s", progname);
  DEBUG2 ("SMUX open password: %s", smux_password);

  ptr = buf;
  len = BUFSIZ;

  /* SMUX Header.  As placeholder. */
  ptr = asn_build_header (ptr, &len, (u_char) SMUX_OPEN, 0);

  /* SMUX Open. */
  version = 0;
  ptr = asn_build_int (ptr, &len, 
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &version, sizeof (u_long));

  /* SMUX connection oid. */
  ptr = asn_build_objid (ptr, &len,
			 (u_char) 
			 (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
			 smux_oid, smux_oid_len);

  /* SMUX connection description. */
  ptr = asn_build_string (ptr, &len, 
			  (u_char)
			  (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
			  progname, strlen (progname));

  /* SMUX connection password. */
  ptr = asn_build_string (ptr, &len, 
			  (u_char)
			  (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
			  smux_password, strlen (smux_password));

  /* Fill in real SMUX header.  We exclude ASN header size (2). */
  len = BUFSIZ;
  asn_build_header (buf, &len, (u_char) SMUX_OPEN, (ptr - buf) - 2);

  return send (smuxfd, buf, (ptr - buf), 0);
}

int
smux_register ()
{
  u_char buf[BUFSIZ];
  u_char *ptr;
  int len, ret;
  long priority;
  long operation;
  struct subtree *subtree;
  struct list *l;

  ret = 0;

  for (l = treelist; l; l=l->next)
    {
      subtree = l->data;

      ptr = buf;
      len = BUFSIZ;

      /* SMUX RReq Header. */
      ptr = asn_build_header (ptr, &len, (u_char) SMUX_RREQ, 0);

      /* Register MIB tree. */
      ptr = asn_build_objid (ptr, &len,
			    (u_char)
			    (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
			    subtree->name, subtree->name_len);

      /* Priority. */
      priority = -1;
      ptr = asn_build_int (ptr, &len, 
		          (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		          &priority, sizeof (u_long));

      /* Operation. */
      operation = snmp_write_access ? 2 : 1; /* Register R/O or R/W */
      ptr = asn_build_int (ptr, &len, 
		          (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		          &operation, sizeof (u_long));

      smux_oid_dump ("SMUX register oid", subtree->name, subtree->name_len);
      DEBUG2 ("SMUX register priority: %d", priority);
      DEBUG2 ("SMUX register operation: %d", operation);

      len = BUFSIZ;
      asn_build_header (buf, &len, (u_char) SMUX_RREQ, (ptr - buf) - 2);
      ret = send (smuxfd, buf, (ptr - buf), 0);
      if (ret < 0)
        return ret;
    }
  return ret;
}

/* Try to connect to SNMP agent. */
int
smux_connect ()
{
  int ret;

  smux_event=SMUX_NONE;
  DEBUG2 ("SMUX connect try %d", fail + 1);

  /* Make socket.  Try to connect. */
  smuxfd = smux_sock ();
  if (smuxfd < 0)
    {
      if (++fail < SMUX_MAX_FAILURE)
	smux_event=SMUX_CONNECT;
      return 0;
    }

  /* Send OPEN PDU. */
  ret = smux_open ();
  if (ret < 0)
    {
      DEBUG ("SMUX open message send failed: %s", strerror (errno));
      close (smuxfd);
      smuxfd = -1;
      smux_event=SMUX_CONNECT;
      return -1;
    }

  /* Send any outstanding register PDUs. */
  ret = smux_register ();
  if (ret < 0)
    {
      DEBUG ("SMUX register message send failed: %s", strerror (errno));
      close (smuxfd);
      smuxfd = -1;
      smux_event=SMUX_CONNECT;
      return -1;
    }

  /* Everything goes fine. */
  smux_event=SMUX_READ;

  return 0;
}

/* Clear all SMUX related resources. */
void
smux_stop ()
{
  smux_event=SMUX_NONE;
  if (smuxfd >= 0)
    close (smuxfd);
  smuxfd = -1;
}

int
smux_str2oid (char *str, oid *oid, size_t *oid_len)
{
  int len;
  int val;

  len = 0;
  val = 0;
  *oid_len = 0;

  if (*str == '.')
    str++;
  if (*str == '\0')
    return 0;

  while (1)
    {
      if (! isdigit (*str))
	return -1;

      while (isdigit (*str))
	{
	  val *= 10;
	  val += (*str - '0');
	  str++;
	}

      if (*str == '\0')
	break;
      if (*str != '.')
	return -1;

      oid[len++] = val;
      val = 0;
      str++;
    }

  oid[len++] = val;
  *oid_len = len;

  return 0;
}

oid *
smux_oid_dup (oid *objid, size_t objid_len)
{
  oid *new;

  new = (oid *)malloc(sizeof (oid) * objid_len);
  oid_copy (new, objid, objid_len);

  return new;
}

int
smux_header_generic (struct variable *v, oid *name, size_t *length, int exact,
		 size_t *var_len, WriteMethod **write_method)
{
  oid fulloid[MAX_OID_LEN];
  int ret;

  oid_copy (fulloid, v->name, v->namelen);
  fulloid[v->namelen] = 0;
  /* Check against full instance. */
  ret = oid_compare (name, *length, fulloid, v->namelen + 1);

  /* Check single instance. */
  if ((exact && (ret != 0)) || (!exact && (ret >= 0)))
	return MATCH_FAILED;

  /* In case of getnext, fill in full instance. */
  memcpy (name, fulloid, (v->namelen + 1) * sizeof (oid));
  *length = v->namelen + 1;

  *write_method = 0;
  *var_len = sizeof(long);    /* default to 'long' results */

  return MATCH_SUCCEEDED;
}

/* Initialize some values then schedule first SMUX connection. */
void
smux_init (oid defoid[], size_t defoid_len)
{
  smux_oid = defoid;
  smux_oid_len = defoid_len;
}

/* Register subtree to smux master tree. */
void
smux_register_mib(char *descr, struct variable *var, size_t width, int num, 
		  oid name[], size_t namelen)
{
  struct subtree *tree, *tt;
  struct list *l, *ll;

  tree = (struct subtree *)malloc(sizeof(struct subtree));
  oid_copy (tree->name, name, namelen);
  tree->name_len = namelen;
  tree->variables = var;
  tree->variables_num = num;
  tree->variables_width = width;
  tree->registered = 0;
  l = (struct list *)malloc(sizeof(struct list));
  l->data = tree;
  l->next = NULL;
/* Build a treelist sorted by the name. This makes GETNEXT simpler */
  if (treelist == NULL)
    {
      treelist = l;
      return;
    }
  tt = (struct subtree*) treelist->data;
  if (oid_compare(name, namelen, tt->name, tt->name_len) < 0)
    {
      l->next = treelist;
      treelist = l;
      return;
    }
  for (ll = treelist; ll->next; ll=ll->next)
    {
      tt = (struct subtree*) ll->next->data;
      if (oid_compare(name, namelen, tt->name, tt->name_len) < 0)
	{
	  l->next = ll->next;
	  ll->next = l;
	  return;
	}
    }
  ll->next = l;
}

void
smux_start(void)
{
  smux_event=SMUX_CONNECT;
  smux_connect();
}
#endif /* WITH_SNMP */
