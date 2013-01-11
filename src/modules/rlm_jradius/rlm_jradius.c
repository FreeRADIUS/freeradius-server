/**
 * rlm_jradius - The FreeRADIUS JRadius Server Module
 * Copyright (C) 2004-2006 PicoPoint, B.V.
 * Copyright (c) 2007-2008 David Bird
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 *  This module is used to connect FreeRADIUS to the JRadius server. 
 *  JRadius is a Java RADIUS client and server framework, see doc/rlm_jradius
 *  and http://jradius.net/ for more information. 
 *
 *  Author(s): David Bird <dbird@acm.org>
 *
 *  Connection pooling code based on rlm_sql, see rlm_sql/sql.c for copyright and license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <poll.h>

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/conffile.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifndef O_NONBLOCK
#define O_NONBLOCK O_NDELAY
#endif

static const int JRADIUS_PORT         = 1814;
static const int HALF_MESSAGE_LEN     = 16384;
static const int MESSAGE_LEN          = 32768;

static const int JRADIUS_authenticate = 1;
static const int JRADIUS_authorize    = 2;
static const int JRADIUS_preacct      = 3;
static const int JRADIUS_accounting   = 4;
static const int JRADIUS_checksimul   = 5;
static const int JRADIUS_pre_proxy    = 6;
static const int JRADIUS_post_proxy   = 7;
static const int JRADIUS_post_auth    = 8;
#ifdef WITH_COA
static const int JRADIUS_recv_coa     = 9;
static const int JRADIUS_send_coa     = 10;
#endif

#define LOG_PREFIX  "rlm_jradius: "
#define MAX_HOSTS   4

typedef struct jradius_socket {
  int  id;
#ifdef HAVE_PTHREAD_H
  pthread_mutex_t mutex;
#endif
  struct jradius_socket *next;
  enum { is_connected, not_connected } state;
  
  union {
    int sock;
  } con;
} JRSOCK;

typedef struct jradius_inst {
  time_t      connect_after;
  JRSOCK    * sock_pool;
  JRSOCK    * last_used;

  char     * name;
  char     * host   [MAX_HOSTS];
  uint32_t   ipaddr [MAX_HOSTS];
  int        port   [MAX_HOSTS];
  int        timeout;
  int        read_timeout;
  int        write_timeout;
  int        allow_codechange;
  int        allow_idchange;
  int        onfail;
  char     * onfail_s;
  int        keepalive;
  int        jrsock_cnt;
} JRADIUS;

typedef struct _byte_array
{
  unsigned int size;
  unsigned int pos;
  unsigned int left;
  unsigned char * b;
} byte_array;

static CONF_PARSER module_config[] = {
  { "name",         PW_TYPE_STRING_PTR,  offsetof(JRADIUS, name),       NULL,  "localhost"},
  { "primary",      PW_TYPE_STRING_PTR,  offsetof(JRADIUS, host[0]),    NULL,  "localhost"},
  { "secondary",    PW_TYPE_STRING_PTR,  offsetof(JRADIUS, host[1]),    NULL,  NULL},
  { "tertiary",     PW_TYPE_STRING_PTR,  offsetof(JRADIUS, host[2]),    NULL,  NULL},
  { "timeout",      PW_TYPE_INTEGER,     offsetof(JRADIUS, timeout),    NULL,  "5"},
  { "read_timeout", PW_TYPE_INTEGER,     offsetof(JRADIUS, read_timeout), NULL,  "90"},
  { "write_timeout",PW_TYPE_INTEGER,     offsetof(JRADIUS, write_timeout),NULL,  "90"},
  { "onfail",       PW_TYPE_STRING_PTR,  offsetof(JRADIUS, onfail_s),   NULL,  NULL},
  { "keepalive",    PW_TYPE_BOOLEAN,     offsetof(JRADIUS, keepalive),  NULL,  "yes"},
  { "connections",  PW_TYPE_INTEGER,     offsetof(JRADIUS, jrsock_cnt), NULL,  "8"},
  { "allow_codechange", PW_TYPE_BOOLEAN, offsetof(JRADIUS, allow_codechange),  NULL,  "no"},
  { "allow_idchange",   PW_TYPE_BOOLEAN, offsetof(JRADIUS, allow_idchange),    NULL,  "no"},
  { NULL, -1, 0, NULL, NULL }
};

static int
sock_read(JRADIUS * inst, JRSOCK *jrsock, uint8_t *b, size_t blen) {
  int fd = jrsock->con.sock;
  int timeout = inst->read_timeout;
  struct timeval tv;
  ssize_t c;
  size_t recd = 0;
  fd_set fds;

  while (recd < blen) {

    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    
    if (select(fd + 1, &fds, (fd_set *) 0, (fd_set *) 0, &tv) == -1)
      return -1;
    
    if (FD_ISSET(fd, &fds))
#ifdef WIN32
      c = recv(fd, b + recd, blen-recd, 0);
#else
      c = read(fd, b + recd, blen-recd);
#endif
    else
      return -1;

    if (c <= 0) return -1;
    recd += c;
  }

  if (recd < blen) return -1;
  return recd;
}

static int
sock_write(JRADIUS * inst, JRSOCK *jrsock, uint8_t *b, size_t blen) {
  int fd = jrsock->con.sock;
  int timeout = inst->write_timeout;
  struct timeval tv;
  ssize_t c;
  size_t sent = 0;
  fd_set fds;

  while (sent < blen) {

    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    
    if (select(fd + 1, (fd_set *) 0, &fds, (fd_set *) 0, &tv) == -1)
      return -1;
    
    if (FD_ISSET(fd, &fds)) 
#ifdef WIN32
      c = send(fd, b+sent, blen-sent, 0);
#else
      c = write(fd, b+sent, blen-sent);
#endif
    else
      return -1;

    if (c <= 0) return -1;
    sent += c;
  }

  if (sent != blen) return -1;
  return sent;
}

static int connect_socket(JRSOCK *jrsock, JRADIUS *inst)
{
  struct sockaddr_in local_addr, serv_addr;
  int i, connected = 0;
  char buff[128];
  int sock;

  /*
   *     Connect to jradius servers until we succeed or die trying
   */
  for (i = 0; !connected && i < MAX_HOSTS && inst->ipaddr[i] > 0; i++) {

    /*
     *     Allocate a TCP socket
     */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      radlog(L_ERR, LOG_PREFIX "could not allocate TCP socket");
      goto failed;
    }
    
    /*
     *     If we have a timeout value set, make the socket non-blocking
     */
    if (inst->timeout > 0 &&
	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) == -1) {
      radlog(L_ERR, LOG_PREFIX "could not set non-blocking on socket");
      goto failed;
    }
    
    /*
     *     Bind to any local port
     */
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(0);
    
    if (bind(sock, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0) {
      radlog(L_ERR, LOG_PREFIX "could not locally bind TCP socket");
      goto failed;
    }
    
    /*
     *     Attempt connection to remote server
     */
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy((char *) &serv_addr.sin_addr, &(inst->ipaddr[i]), 4);
    serv_addr.sin_port = htons(inst->port[i]);
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
      if (inst->timeout > 0 && (errno == EINPROGRESS || errno == EWOULDBLOCK)) {
	/*
	 *     Wait to see if non-blocking socket connects or times-out
	 */
	struct pollfd pfd;
	memset(&pfd, 0, sizeof(pfd));

	pfd.fd = sock;
	pfd.events = POLLOUT;

	if (poll(&pfd, 1, inst->timeout * 1000) == 1 && pfd.revents) {
	  /*
	   *     Lets make absolutely sure we are connected
	   */
	  struct sockaddr_in sa;
	  unsigned int salen = sizeof(sa);
	  if (getpeername(sock, (struct sockaddr *) &sa, &salen) != -1) {
	    /*
	     *     CONNECTED! break out of for-loop
	     */
	    connected = 1;
	    break;
	  }
	}
      }

      /*
       *     Timed-out
       */
      radlog(L_ERR, LOG_PREFIX "could not connect to %s:%d", 
	     ip_ntoa(buff, inst->ipaddr[i]), inst->port[i]);

    } else {
      /*
       *     CONNECTED (instantly)! break out of for-loop
       */
      connected = 1;
      break;
    }

    /*
     *     Unable to connect, cleanup and start over
     */
    close(sock); sock=0;
  }

  if (!connected) {
    radlog(L_ERR, LOG_PREFIX "could not find any jradius server!");
    goto failed;
  }

  /*
   *     If we previously set the socket to non-blocking, restore blocking 
  if (inst->timeout > 0 &&
      fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) & ~O_NONBLOCK) == -1) {
    radlog(L_ERR, LOG_PREFIX "could not set blocking on socket");
    goto failed;
  }
   */

  jrsock->state = is_connected;
  jrsock->con.sock = sock;
  return 1;

 failed:
  if (sock > 0) { shutdown(sock, 2); close(sock); }
  jrsock->state = not_connected;
  return 0;
}

static void close_socket(UNUSED JRADIUS * inst, JRSOCK *jrsock)
{
  radlog(L_INFO, "rlm_jradius: Closing JRadius connection %d", jrsock->id);
  if (jrsock->con.sock > 0) { 
    shutdown(jrsock->con.sock, 2); 
    close(jrsock->con.sock); 
  }
  jrsock->state = not_connected;
  jrsock->con.sock = 0;
}

static void free_socket(JRADIUS * inst, JRSOCK *jrsock) {
  close_socket(inst, jrsock);
  if (inst->keepalive) {
#ifdef HAVE_PTHREAD_H
    pthread_mutex_destroy(&jrsock->mutex);
#endif
    free(jrsock);
  }
}

static int init_socketpool(JRADIUS * inst)
{
  int i, rcode;
  int success = 0;
  JRSOCK *jrsock;
  
  inst->connect_after = 0;
  inst->sock_pool = NULL;
  
  for (i = 0; i < inst->jrsock_cnt; i++) {
    radlog(L_INFO, "rlm_jradius: starting JRadius connection %d", i);
    
    if ((jrsock = rad_malloc(sizeof(*jrsock))) == 0) return -1;
    
    memset(jrsock, 0, sizeof(*jrsock));
    jrsock->id = i;
    jrsock->state = not_connected;

#ifdef HAVE_PTHREAD_H
    rcode = pthread_mutex_init(&jrsock->mutex,NULL);
    if (rcode != 0) {
      radlog(L_ERR, "rlm_jradius: Failed to init lock: %s", strerror(errno));
      return 0;
    }
#endif

    if (time(NULL) > inst->connect_after)
      if (connect_socket(jrsock, inst))
	success = 1;
    
    jrsock->next = inst->sock_pool;
    inst->sock_pool = jrsock;
  }
  inst->last_used = NULL;
  
  if (!success) {
    radlog(L_DBG, "rlm_jradius: Failed to connect to JRadius server.");
  }
  
  return 1;
}

static void free_socketpool(JRADIUS * inst)
{
  JRSOCK *cur;
  JRSOCK *next;

  for (cur = inst->sock_pool; cur; cur = next) {
    next = cur->next;
    free_socket(inst, cur);
  }
  
  inst->sock_pool = NULL;
}

static JRSOCK * get_socket(JRADIUS * inst)
{
  JRSOCK *cur, *start;
  int tried_to_connect = 0;
  int unconnected = 0;

  start = inst->last_used;
  if (!start) start = inst->sock_pool;
  
  cur = start;
  
  while (cur) {
#ifdef HAVE_PTHREAD_H
    if (pthread_mutex_trylock(&cur->mutex) != 0) {
      goto next;
    } 
#endif
    
    if ((cur->state == not_connected) && (time(NULL) > inst->connect_after)) {
      radlog(L_INFO, "rlm_jradius: Trying to (re)connect unconnected handle %d", cur->id);
      tried_to_connect++;
      connect_socket(cur, inst);
    }
    
    if (cur->state == not_connected) {
      radlog(L_DBG, "rlm_jradius: Ignoring unconnected handle %d", cur->id);
      unconnected++;
#ifdef HAVE_PTHREAD_H
      pthread_mutex_unlock(&cur->mutex);
#endif
      goto next;
    }
    
    radlog(L_DBG, "rlm_jradius: Reserving JRadius socket id: %d", cur->id);
    
    if (unconnected != 0 || tried_to_connect != 0) {
      radlog(L_INFO, "rlm_jradius: got socket %d after skipping %d unconnected handles, tried to reconnect %d though", 
	     cur->id, unconnected, tried_to_connect);
    }

    inst->last_used = cur->next;
    return cur;
    
  next:
    cur = cur->next;
    if (!cur) cur = inst->sock_pool;
    if (cur == start) break;
  }
  
  radlog(L_INFO, "rlm_jradius: There are no sockets to use! skipped %d, tried to connect %d", 
	 unconnected, tried_to_connect);
  return NULL;
}

static int release_socket(UNUSED JRADIUS * inst, JRSOCK * jrsock)
{
#ifdef HAVE_PTHREAD_H
  pthread_mutex_unlock(&jrsock->mutex);
#endif
  
  radlog(L_DBG, "rlm_jradius: Released JRadius socket id: %d", jrsock->id);
  
  return 0;
}


/*
 *     Initialize the jradius module
 */
static int jradius_instantiate(CONF_SECTION *conf, void **instance)
{
  JRADIUS *inst = (JRADIUS *) instance;
  char host[128], b[128], *h;
  int i, p, idx, port;

  inst = rad_malloc(sizeof(JRADIUS));
  memset(inst, 0, sizeof(JRADIUS));

  if (cf_section_parse(conf, inst, module_config) < 0) {
    free(inst);
    return -1;
  }

  for (i = 0, idx = 0; i < MAX_HOSTS; i++) {
    if (inst->host[i] && strlen(inst->host[i]) < sizeof(host)) {
      h = inst->host[i];
      p = JRADIUS_PORT;
      
      strcpy(b, h);
      if (sscanf(b, "%[^:]:%d", host, &port) == 2) { h = host; p = port; }

      if (h) {
	fr_ipaddr_t ipaddr;
	if (ip_hton(h, AF_INET, &ipaddr) < 0) {
	  radlog(L_ERR, "Can't find IP address for host %s", h);
	  continue;
	}
	if ((inst->ipaddr[idx] = ipaddr.ipaddr.ip4addr.s_addr) != htonl(INADDR_NONE)) {
	  inst->port[idx] = p;
	  radlog(L_INFO, LOG_PREFIX "configuring jradius server %s:%d", h, p);
	  idx++;
	} else {
	  radlog(L_ERR, LOG_PREFIX "invalid jradius server %s", h);
	}
      }
    }
  }

  if (inst->keepalive) init_socketpool(inst);

  inst->onfail = RLM_MODULE_FAIL;

  if (inst->onfail_s) {
    if      (!strcmp(inst->onfail_s, "NOOP"))    inst->onfail = RLM_MODULE_NOOP;
    else if (!strcmp(inst->onfail_s, "REJECT"))  inst->onfail = RLM_MODULE_REJECT;
    else if (!strcmp(inst->onfail_s, "OK"))      inst->onfail = RLM_MODULE_OK;
    else if (!strcmp(inst->onfail_s, "FAIL"))    inst->onfail = RLM_MODULE_FAIL;
    else radlog(L_ERR, LOG_PREFIX "invalid jradius 'onfail' state %s", inst->onfail_s);
  }

  *instance = inst;

  return 0;
}

/*
 *     Initialize a byte array buffer structure
 */
static void init_byte_array(byte_array * ba, unsigned char *b, int blen)
{
  ba->b = b;
  ba->size = ba->left = blen;
  ba->pos = 0;
}

/*
 *     Pack a single byte into a byte array buffer
 */
static int pack_byte(byte_array * ba, unsigned char c)
{
  if (ba->left < 1) return -1;

  ba->b[ba->pos] = c;
  ba->pos++;
  ba->left--;

  return 0;
}

/*
 *     Pack an array of bytes into a byte array buffer
 */
static int pack_bytes(byte_array * ba, unsigned char *d, unsigned int dlen)
{
  if (ba->left < dlen) return -1;

  memcpy((void *)(ba->b + ba->pos), d, dlen);
  ba->pos  += dlen;
  ba->left -= dlen;

  return 0;
}

/*
 *     Pack an integer into a byte array buffer (adjusting for byte-order)
 */
static int pack_uint32(byte_array * ba, uint32_t i)
{
  if (ba->left < 4) return -1;

  i = htonl(i);

  memcpy((void *)(ba->b + ba->pos), (void *)&i, 4);
  ba->pos  += 4;
  ba->left -= 4;

  return 0;
}

/*
 *     Pack a short into a byte array buffer (adjusting for byte-order)
 */
static int pack_uint16(byte_array * ba, uint16_t i)
{
  if (ba->left < 2) return -1;

  i = htons(i);

  memcpy((void *)(ba->b + ba->pos), (void *)&i, 2);
  ba->pos  += 2;
  ba->left -= 2;

  return 0;
}

/*
 *     Pack a byte into a byte array buffer 
 */
static int pack_uint8(byte_array * ba, uint8_t i)
{
  if (ba->left < 1) return -1;

  memcpy((void *)(ba->b + ba->pos), (void *)&i, 1);
  ba->pos  += 1;
  ba->left -= 1;

  return 0;
}

/*
 *     Pack one byte array buffer into another byte array buffer
 */
static int pack_array(byte_array * ba, byte_array * a)
{
  if (ba->left < a->pos) return -1;

  memcpy((void *)(ba->b + ba->pos), (void *)a->b, a->pos);
  ba->pos  += a->pos;
  ba->left -= a->pos;

  return 0;
}

/*
 *     Pack radius attributes into a byte array buffer
 */
static int pack_vps(byte_array * ba, VALUE_PAIR * vps)
{
  uint32_t i;
  VALUE_PAIR * vp;

  for (vp = vps; vp != NULL; vp = vp->next) {

    radlog(L_DBG, LOG_PREFIX "packing attribute %s (type: %d; len: %u)", 	   vp->name, vp->attribute, (unsigned int) vp->length);

    i = vp->attribute;		/* element is int, not uint32_t */
    if (pack_uint32(ba, i) == -1) return -1;
    i = vp->length;
    if (pack_uint32(ba, i) == -1) return -1;
    i = vp->operator;
    if (pack_uint32(ba, i) == -1) return -1;

    switch (vp->type) {
      case PW_TYPE_BYTE:
	if (pack_uint8(ba, vp->vp_integer) == -1) return -1;
	break;
      case PW_TYPE_SHORT:
	if (pack_uint16(ba, vp->vp_integer) == -1) return -1;
	break;
      case PW_TYPE_INTEGER:
	if (pack_uint32(ba, vp->vp_integer) == -1) return -1;
	break;
      case PW_TYPE_DATE:
	if (pack_uint32(ba, vp->vp_date) == -1) return -1;
	break;
      case PW_TYPE_IPADDR:
	if (pack_bytes(ba, (void *)&vp->vp_ipaddr, vp->length) == -1) return -1;
	break;
      default:
	if (pack_bytes(ba, (void *)vp->vp_octets, vp->length) == -1) return -1;
	break;
    }
  }

  return 0;
}

/*
 *     Pack a radius packet into a byte array buffer
 */
static int pack_packet(byte_array * ba, RADIUS_PACKET * p)
{
  /*unsigned char code = p->code;*/
  unsigned char buff[HALF_MESSAGE_LEN];
  byte_array pba;

  init_byte_array(&pba, buff, sizeof(buff));

  if (pack_vps(&pba, p->vps) == -1) return -1;

  radlog(L_DBG, LOG_PREFIX "packing packet with code: %d (attr length: %d)", p->code, pba.pos);

#ifdef EXTENDED_FMT
  if (pack_uint32(ba, p->code) == -1) return -1;
  if (pack_uint32(ba, p->id) == -1) return -1;
#else
  if (pack_byte(ba, p->code) == -1) return -1;
  if (pack_byte(ba, p->id) == -1) return -1;
#endif
  if (pack_uint32(ba, pba.pos) == -1) return -1;
  if (pba.pos == 0) return 0;
  if (pack_array(ba, &pba) == -1) return -1;

  return 0;
}

static int pack_request(byte_array * ba, REQUEST *r)
{
  unsigned char buff[HALF_MESSAGE_LEN];
  byte_array pba;

  init_byte_array(&pba, buff, sizeof(buff));

  if (pack_vps(&pba, r->config_items) == -1) return -1;
  if (pack_uint32(ba, pba.pos) == -1) return -1;
  if (pba.pos == 0) return 0;
  if (pack_array(ba, &pba) == -1) return -1;
      
  return 0;
}

static uint32_t unpack_uint32(unsigned char *c)
{
  uint32_t ii;
  memcpy((void *)&ii, c, 4);
  return ntohl(ii);
}

static uint16_t unpack_uint16(unsigned char *c)
{
  uint16_t ii;
  memcpy((void *)&ii, c, 2);
  return ntohs(ii);
}

static uint8_t unpack_uint8(unsigned char *c)
{
  uint8_t ii;
  memcpy((void *)&ii, c, 1);
  return ii;
}



/*
 *     Read a single byte from socket
 */
static int read_byte(JRADIUS *inst, JRSOCK *jrsock, uint8_t *b)
{
  return (sock_read(inst, jrsock, b, 1) == 1) ? 0 : -1;
}

/*
 *     Read an integer from the socket (adjusting for byte-order)
 */
static int read_uint32(JRADIUS *inst, JRSOCK *jrsock, uint32_t *i)
{
  uint32_t ii;

  if (sock_read(inst, jrsock, (uint8_t *)&ii, 4) != 4) return -1;
  *i = ntohl(ii);

  return 0;
}

/*
 *     Read a value-pair list from the socket
 */
static int read_vps(JRADIUS *inst, JRSOCK *jrsock, VALUE_PAIR **pl, int plen)
{
  VALUE_PAIR *vp;
  unsigned char buff[MESSAGE_LEN];
  uint32_t alen, atype, aop;
  int rlen = 0;
  
  while (rlen < plen) {
    if (read_uint32(inst, jrsock, &atype) == -1) return -1; rlen += 4;
    if (read_uint32(inst, jrsock, &alen)  == -1) return -1; rlen += 4;
    if (read_uint32(inst, jrsock, &aop)   == -1) return -1; rlen += 4; 

    radlog(L_DBG, LOG_PREFIX "reading attribute: type=%d; len=%d", atype, alen);

    if (alen >= sizeof(buff)) {
      radlog(L_ERR, LOG_PREFIX "packet value too large (len: %d)", alen);
      return -1;
    }

    if (sock_read(inst, jrsock, buff, alen) != (int)alen) return -1; rlen += alen;
    buff[alen]=0;

    /*
     *     Create new attribute
     */
    vp = paircreate(atype, 0, -1);
    vp->operator = aop;

    if (vp->type == -1) {
      /*
       *     FreeRADIUS should know about the same attributes that JRadius knows
       */
      radlog(L_ERR, LOG_PREFIX "received attribute we do not recognize (type: %d)", atype);
      pairbasicfree(vp);
      continue;
    }

    /*
     *     WiMAX combo-ip address
     *     paircreate() cannot recognize the real type of the address.
     *     ..ugly code...
     */
    if (vp->type==PW_TYPE_COMBO_IP) {
        switch (alen) {
            case 4:
                vp->type = PW_TYPE_IPADDR;
                break;
            case 16:
                vp->type = PW_TYPE_IPV6ADDR;
                break;
        }
    }

    /*
     *     Fill in the attribute value based on type
     */
    switch (vp->type) {
      case PW_TYPE_BYTE:
	vp->vp_integer = unpack_uint8(buff);
	vp->length = 1;
	break;

      case PW_TYPE_SHORT:
	vp->vp_integer = unpack_uint16(buff);
	vp->length = 2;
	break;

      case PW_TYPE_INTEGER:
	vp->vp_integer = unpack_uint32(buff);
	vp->length = 4;
	break;

      case PW_TYPE_DATE:
	vp->vp_date = unpack_uint32(buff);
	vp->length = 4;
	break;

      case PW_TYPE_IPADDR:
	memcpy((void *)&vp->vp_ipaddr, buff, 4);
	vp->length = 4;
	break;

      default:
        if (alen >= sizeof(vp->vp_octets)) alen = sizeof(vp->vp_octets) - 1;
	memcpy((void *)vp->vp_octets, buff, alen);
	vp->length = alen;
	break;
    }

    /*
     *     Add the attribute to the packet
     */
    pairadd(pl, vp);
  } 

  return rlen;
}

/*
 *     Read a radius packet from the socket
 */
static int read_packet(JRADIUS * inst, JRSOCK *jrsock, RADIUS_PACKET *p)
{
  uint32_t code;
  uint32_t id;
  uint32_t plen;

#ifdef EXTENDED_FMT
  if (read_uint32(inst, jrsock, &code) == -1) return -1;
  if (read_uint32(inst, jrsock, &id)   == -1) return -1;
#else
  { uint8_t c = 0;
  if (read_byte(inst, jrsock, &c) == -1) return -1;
  code = c;
  if (read_byte(inst, jrsock, &c) == -1) return -1;
  id = c; }
#endif

  if (read_uint32(inst, jrsock, &plen) == -1) return -1;

  radlog(L_DBG, LOG_PREFIX "reading packet: code=%d len=%d", (int)code, plen);

  if (inst->allow_codechange)
    if (code != p->code) {
      radlog(L_INFO, LOG_PREFIX "changing packet code from %d to %d", p->code, code);
      p->code = code;
    }

  if (inst->allow_idchange)
    if ((int)id != p->id) {
      radlog(L_INFO, LOG_PREFIX "changing packet id from %d to %d", p->id, id);
      p->id = (int)id;
    }
  
  /*
   *     Delete previous attribute list
   */
  pairfree(&p->vps);

  if (plen == 0) return 0;

  if (read_vps(inst, jrsock, &p->vps, plen) == -1) return -1;

  return 0;
}

static int read_request(JRADIUS *inst, JRSOCK *jrsock, REQUEST *p)
{
  unsigned int plen;

  if (read_uint32(inst, jrsock, &plen) == -1) return -1;

  radlog(L_DBG, LOG_PREFIX "reading request: config_item: len=%d", plen);

  /*
   *     Delete previous attribute list
   */
  pairfree(&p->config_items);

  if (plen == 0) return 0;

  if (read_vps(inst, jrsock, &p->config_items, plen) == -1) return -1;

  return 0;
}

static rlm_rcode_t rlm_jradius_call(char func, void *instance, REQUEST *req,
				    int isproxy)
{
  JRADIUS        * inst    = instance;
  RADIUS_PACKET  * request = req->packet;
  RADIUS_PACKET  * reply   = req->reply;
  JRSOCK         * jrsock  = 0;
  JRSOCK           sjrsock;

  int exitstatus = inst->onfail;
  unsigned char rcode, pcount;

  unsigned char buff[MESSAGE_LEN];
  byte_array ba;

  char * n = inst->name;
  unsigned int nlen = strlen(n);
  const char * err = 0;
  int rc, attempt2=0;

#define W_ERR(s) { err=s; goto packerror;  }
#define R_ERR(s) { err=s; goto parseerror; }

#ifdef WITH_PROXY
  if (isproxy) {
	  request = req->proxy;
	  reply   = req->proxy_reply;
  }
#endif

  if (inst->keepalive) {
    jrsock = get_socket(inst);
    if (!jrsock) return exitstatus;
  } else {
    jrsock = &sjrsock;
    memset(jrsock, 0, sizeof(*jrsock));
    jrsock->state = not_connected;
  }

  init_byte_array(&ba, buff, sizeof(buff));

  pcount = 0;
  if (request) pcount++;
  if (reply) pcount++;

  /*
   *     Create byte array to send to jradius
   */
  if ((rc = pack_uint32 (&ba, nlen))                  == -1)  W_ERR("pack_uint32(nlen)");
  if ((rc = pack_bytes  (&ba, (void *)n, nlen))       == -1)  W_ERR("pack_bytes(name)");
  if ((rc = pack_byte   (&ba, func))                  == -1)  W_ERR("pack_byte(fun)");
  if ((rc = pack_byte   (&ba, pcount))                == -1)  W_ERR("pack_byte(pcnt)");
  if (pcount > 0 && (rc = pack_packet (&ba, request)) == -1)  W_ERR("pack_packet(req)");
  if (pcount > 1 && (rc = pack_packet (&ba, reply))   == -1)  W_ERR("pack_packet(rep)");
  if ((rc = pack_request(&ba, req))                   == -1)  W_ERR("pack_request()");

  /*
   *     Send data
   */
 start_over:
  if (jrsock->state == not_connected) {
    if (attempt2) radlog(L_ERR, LOG_PREFIX "reconnecting socket id %d", jrsock->id);
    if (!connect_socket(jrsock, inst)) {
      if (attempt2) radlog(L_ERR, LOG_PREFIX "could not reconnect socket %d, giving up", jrsock->id);
      goto cleanup;
    }
  }
  radlog(L_DBG, LOG_PREFIX "sending %d bytes to socket %d", ba.pos, jrsock->id);
  if (sock_write(inst, jrsock, ba.b, ba.pos) != (int)ba.pos ||
      (rc = read_byte(inst, jrsock, &rcode)) == -1) {
    /*
     *   With an error on the write or the first read, try closing the socket
     *   and reconnecting to see if that improves matters any (tries this only once)
     */
    radlog(L_ERR, LOG_PREFIX "error sending request with socket %d", jrsock->id);
    if (!inst->keepalive || attempt2) W_ERR("socket_send/first_read");
    close_socket(inst, jrsock);
    attempt2 = 1;
    goto start_over;
  }

  /*
   *     Read result
   */
  if ((rc = read_byte(inst, jrsock, &pcount)) == -1)  R_ERR("read_byte(pcnt)");

  radlog(L_DBG, LOG_PREFIX "return code %d; receiving %d packets", (int)rcode, (int)pcount);

  if (pcount > 0 && request) if ((rc = read_packet (inst, jrsock, request)) == -1)  R_ERR("read_packet(req)");
  if (pcount > 1 && reply)   if ((rc = read_packet (inst, jrsock, reply))   == -1)  R_ERR("read_packet(rep)");

  if ((rc = read_request(inst, jrsock, req)) == -1) R_ERR("read_request()");

  /*
   *    Since we deleted all the attribute lists in the request,
   *    we need to reconfigure a few pointers in the REQUEST object
   */
  if (req->username) {
    req->username = pairfind(request->vps, PW_USER_NAME, 0, TAG_ANY);
  }
  if (req->password) {
    req->password = pairfind(request->vps, PW_PASSWORD, 0, TAG_ANY);
    if (!req->password) req->password = pairfind(request->vps, PW_CHAP_PASSWORD, 0, TAG_ANY);
  }

  /*
   *    All done, set return code and cleanup
   */
  exitstatus = (int)rcode;
  goto cleanup;

 parseerror:
  radlog(L_ERR, LOG_PREFIX "problem parsing the data [%s]",err);
  if (inst->keepalive) close_socket(inst, jrsock);
  goto cleanup;

 packerror:
  radlog(L_ERR, LOG_PREFIX "problem packing the data[%s]",err);
  if (inst->keepalive) close_socket(inst, jrsock);

 cleanup:
  if (inst->keepalive) 
    release_socket(inst, jrsock);
  else  
    close_socket(inst, jrsock);

  return exitstatus;
}

static rlm_rcode_t jradius_authenticate(void *instance, REQUEST *request)
{
  return rlm_jradius_call(JRADIUS_authenticate, instance, request, 0);
}

static rlm_rcode_t jradius_authorize(void *instance, REQUEST *request)
{
  return rlm_jradius_call(JRADIUS_authorize, instance, request, 0);
}

static rlm_rcode_t jradius_preacct(void *instance, REQUEST *request)
{
  return rlm_jradius_call(JRADIUS_preacct, instance, request, 0);
}

static rlm_rcode_t jradius_accounting(void *instance, REQUEST *request)
{
  return rlm_jradius_call(JRADIUS_accounting, instance, request, 0);
}

static rlm_rcode_t jradius_checksimul(void *instance, REQUEST *request)
{
  return rlm_jradius_call(JRADIUS_checksimul, instance, request, 0);
}

static rlm_rcode_t jradius_pre_proxy(void *instance, REQUEST *request)
{
  return rlm_jradius_call(JRADIUS_pre_proxy, instance, request, 1);
}

static rlm_rcode_t jradius_post_proxy(void *instance, REQUEST *request)
{
  return rlm_jradius_call(JRADIUS_post_proxy, instance, request, 1);
}

static rlm_rcode_t jradius_post_auth(void *instance, REQUEST *request)
{
  return rlm_jradius_call(JRADIUS_post_auth, instance, request, 0);
}

#ifdef WITH_COA
static rlm_rcode_t jradius_recv_coa(void *instance, REQUEST *request)
{
  return rlm_jradius_call(JRADIUS_recv_coa, instance, request, 0);
}
static rlm_rcode_t jradius_send_coa(void *instance, REQUEST *request)
{
  return rlm_jradius_call(JRADIUS_send_coa, instance, request, 0);
}
#endif

static int jradius_detach(void *instance)
{
  JRADIUS *inst = (JRADIUS *) instance;
  free_socketpool(inst);
  free(inst);
  return 0;
}

module_t rlm_jradius = {
  RLM_MODULE_INIT,
  "jradius",
  RLM_TYPE_THREAD_SAFE,
  jradius_instantiate,
  jradius_detach,
  {
    jradius_authenticate,
    jradius_authorize,
    jradius_preacct,
    jradius_accounting,
    jradius_checksimul,
    jradius_pre_proxy,
    jradius_post_proxy,
    jradius_post_auth
#ifdef WITH_COA
    , jradius_recv_coa,
    jradius_send_coa
#endif
  },
};

