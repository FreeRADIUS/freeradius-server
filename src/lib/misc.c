/*
 * misc.c	Various miscellaneous functions.
 *
 * Version:	$Id$
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include	<freeradius-devel/libradius.h>

#include	<ctype.h>
#include	<sys/file.h>
#include	<fcntl.h>

#define FR_PUT_LE16(a, val)\
	do {\
		a[1] = ((uint16_t) (val)) >> 8;\
		a[0] = ((uint16_t) (val)) & 0xff;\
	} while (0)

#ifdef HAVE_PTHREAD_H
#  define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#  define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#  define PTHREAD_MUTEX_LOCK(_x)
#  define PTHREAD_MUTEX_UNLOCK(_x)
#endif

bool	fr_dns_lookups = false;	    /* IP -> hostname lookups? */
bool    fr_hostname_lookups = true; /* hostname -> IP lookups? */
int	fr_debug_flag = 0;

static char const *months[] = {
	"jan", "feb", "mar", "apr", "may", "jun",
	"jul", "aug", "sep", "oct", "nov", "dec" };

fr_thread_local_setup(char *, fr_inet_ntop_buffer);	/* macro */

typedef struct fr_talloc_link {
	bool armed;
	TALLOC_CTX *child;
} fr_talloc_link_t;

/** Sets a signal handler using sigaction if available, else signal
 *
 * @param sig to set handler for.
 * @param func handler to set.
 */
int fr_set_signal(int sig, sig_t func)
{
#ifdef HAVE_SIGACTION
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	act.sa_handler = func;

	if (sigaction(sig, &act, NULL) < 0) {
		fr_strerror_printf("Failed setting signal %i handler via sigaction(): %s", sig, fr_syserror(errno));
		return -1;
	}
#else
	if (signal(sig, func) < 0) {
		fr_strerror_printf("Failed setting signal %i handler via signal(): %s", sig, fr_syserror(errno));
		return -1;
	}
#endif
	return 0;
}

static int _fr_trigger_talloc_ctx_free(fr_talloc_link_t *trigger)
{
	if (trigger->armed) talloc_free(trigger->child);

	return 0;
}

static int _fr_disarm_talloc_ctx_free(bool **armed)
{
	**armed = false;
	return 0;
}

/** Link a parent and a child context, so the child is freed before the parent
 *
 * @note This is not thread safe. Do not free parent before threads are joined, do not call from a child thread.
 * @note It's OK to free the child before threads are joined, but this will leak memory until the parent is freed.
 *
 * @param parent who's fate the child should share.
 * @param child bound to parent's lifecycle.
 * @return 0 on success -1 on failure.
 */
int fr_link_talloc_ctx_free(TALLOC_CTX *parent, TALLOC_CTX *child)
{
	fr_talloc_link_t *trigger;
	bool **disarm;

	trigger = talloc(parent, fr_talloc_link_t);
	if (!trigger) return -1;

	disarm = talloc(child, bool *);
	if (!disarm) {
		talloc_free(trigger);
		return -1;
	}

	trigger->child = child;
	trigger->armed = true;
	*disarm = &trigger->armed;

	talloc_set_destructor(trigger, _fr_trigger_talloc_ctx_free);
	talloc_set_destructor(disarm, _fr_disarm_talloc_ctx_free);

	return 0;
}

/*
 *	Explicitly cleanup the memory allocated to the error inet_ntop
 *	buffer.
 */
static void _fr_inet_ntop_free(void *arg)
{
	free(arg);
}

/** Wrapper around inet_ntop, prints IPv4/IPv6 addresses
 *
 * inet_ntop requires the caller pass in a buffer for the address.
 * This would be annoying and cumbersome, seeing as quite often the ASCII
 * address is only used for logging output.
 *
 * So as with lib/log.c use TLS to allocate thread specific buffers, and
 * write the IP address there instead.
 *
 * @param af address family, either AF_INET or AF_INET6.
 * @param src pointer to network address structure.
 * @return NULL on error, else pointer to ASCII buffer containing text version of address.
 */
char const *fr_inet_ntop(int af, void const *src)
{
	char *buffer;

	if (!src) {
		return NULL;
	}

	buffer = fr_thread_local_init(fr_inet_ntop_buffer, _fr_inet_ntop_free);
	if (!buffer) {
		int ret;

		/*
		 *	malloc is thread safe, talloc is not
		 */
		buffer = malloc(sizeof(char) * INET6_ADDRSTRLEN);
		if (!buffer) {
			fr_perror("Failed allocating memory for inet_ntop buffer");
			return NULL;
		}

		ret = fr_thread_local_set(fr_inet_ntop_buffer, buffer);
		if (ret != 0) {
			fr_perror("Failed setting up TLS for inet_ntop buffer: %s", fr_syserror(ret));
			free(buffer);
			return NULL;
		}
	}
	buffer[0] = '\0';

	return inet_ntop(af, src, buffer, INET6_ADDRSTRLEN);
}

/*
 *	Return an IP address in standard dot notation
 *
 *	FIXME: DELETE THIS
 */
char const *ip_ntoa(char *buffer, uint32_t ipaddr)
{
	ipaddr = ntohl(ipaddr);

	sprintf(buffer, "%d.%d.%d.%d",
		(ipaddr >> 24) & 0xff,
		(ipaddr >> 16) & 0xff,
		(ipaddr >>  8) & 0xff,
		(ipaddr      ) & 0xff);
	return buffer;
}

/** Parse an IPv4 address or IPv4 prefix in presentation format (and others)
 *
 * @param out Where to write the ip address value.
 * @param value to parse, may be dotted quad [+ prefix], or integer, or octal number, or '*' (INADDR_ANY).
 * @param inlen Length of value, if value is \0 terminated inlen may be 0.
 * @param resolve If true and value doesn't look like an IP address, try and resolve value as a hostname.
 * @param fallback to IPv4 resolution if no A records can be found.
 * @return 0 if ip address was parsed successfully, else -1 on error.
 */
int fr_pton4(fr_ipaddr_t *out, char const *value, size_t inlen, bool resolve, bool fallback)
{
	char *p;
	unsigned int prefix;
	char *eptr;

	/* Dotted quad + / + [0-9]{1,2} */
	char buffer[INET_ADDRSTRLEN + 3];

	/*
	 *	Copy to intermediary buffer if we were given a length
	 */
	if (inlen > 0) {
		if (inlen >= sizeof(buffer)) {
			fr_strerror_printf("Invalid IPv4 address string \"%s\"", value);
			return -1;
		}
		memcpy(buffer, value, inlen);
		buffer[inlen] = '\0';
	}

	p = strchr(value, '/');
	/*
	 *	192.0.2.2 is parsed as if it was /32
	 */
	if (!p) {
		/*
		 *	Allow '*' as the wildcard address usually 0.0.0.0
		 */
		if ((value[0] == '*') && (value[1] == '\0')) {
			out->ipaddr.ip4addr.s_addr = htonl(INADDR_ANY);
		/*
		 *	Convert things which are obviously integers to IP addresses
		 *
		 *	We assume the number is the bigendian representation of the
		 *	IP address.
		 */
		} else if (is_integer(value) || ((value[0] == '0') && (value[1] == 'x'))) {
			out->ipaddr.ip4addr.s_addr = htonl(strtoul(value, NULL, 0));
		} else if (!resolve) {
			if (inet_pton(AF_INET, value, &(out->ipaddr.ip4addr.s_addr)) <= 0) {
				fr_strerror_printf("Failed to parse IPv4 address string \"%s\"", value);
				return -1;
			}
		} else if (ip_hton(out, AF_INET, value, fallback) < 0) return -1;

		out->prefix = 32;
		out->af = AF_INET;

		return 0;
	}

	/*
	 *	Otherwise parse the prefix
	 */
	if ((size_t)(p - value) >= INET_ADDRSTRLEN) {
		fr_strerror_printf("Invalid IPv4 address string \"%s\"", value);
		return -1;
	}

	/*
	 *	Copy the IP portion into a temporary buffer if we haven't already.
	 */
	if (inlen == 0) memcpy(buffer, value, p - value);
	buffer[p - value] = '\0';

	if (!resolve) {
		if (inet_pton(AF_INET, buffer, &(out->ipaddr.ip4addr.s_addr)) <= 0) {
			fr_strerror_printf("Failed to parse IPv4 address string \"%s\"", value);
			return -1;
		}
	} else if (ip_hton(out, AF_INET, buffer, fallback) < 0) return -1;

	prefix = strtoul(p + 1, &eptr, 10);
	if (prefix > 32) {
		fr_strerror_printf("Invalid IPv4 mask length \"%s\".  Should be between 0-32", p);
		return -1;
	}
	if (eptr[0] != '\0') {
		fr_strerror_printf("Failed to parse IPv4 address string \"%s\", "
				   "got garbage after mask length \"%s\"", value, eptr);
		return -1;
	}

	if (prefix < 32) {
		out->ipaddr.ip4addr = fr_inaddr_mask(&(out->ipaddr.ip4addr), prefix);
	}

	out->prefix = (uint8_t) prefix;
	out->af = AF_INET;

	return 0;
}

/** Parse an IPv6 address or IPv6 prefix in presentation format (and others)
 *
 * @param out Where to write the ip address value.
 * @param value to parse.
 * @param inlen Length of value, if value is \0 terminated inlen may be 0.
 * @param resolve If true and value doesn't look like an IP address, try and resolve value as a hostname.
 * @param fallback to IPv4 resolution if no AAAA records can be found.
 * @return 0 if ip address was parsed successfully, else -1 on error.
 */
int fr_pton6(fr_ipaddr_t *out, char const *value, size_t inlen, bool resolve, bool fallback)
{
	char const *p;
	unsigned int prefix;
	char *eptr;

	/* IPv6  + / + [0-9]{1,3} */
	char buffer[INET6_ADDRSTRLEN + 4];

	/*
	 *	Copy to intermediary buffer if we were given a length
	 */
	if (inlen > 0) {
		if (inlen >= sizeof(buffer)) {
			fr_strerror_printf("Invalid IPv6 address string \"%s\"", value);
			return -1;
		}
		memcpy(buffer, value, inlen);
		buffer[inlen] = '\0';
	}

	p = strchr(value, '/');
	if (!p) {
		/*
		 *	Allow '*' as the wildcard address
		 */
		if ((value[0] == '*') && (value[1] == '\0')) {
			memset(&out->ipaddr.ip6addr.s6_addr, 0, sizeof(out->ipaddr.ip6addr.s6_addr));
		} else if (!resolve) {
			if (inet_pton(AF_INET6, value, &(out->ipaddr.ip6addr.s6_addr)) <= 0) {
				fr_strerror_printf("Failed to parse IPv6 address string \"%s\"", value);
				return -1;
			}
		} else if (ip_hton(out, AF_INET6, value, fallback) < 0) return -1;

		out->prefix = 128;
		out->af = AF_INET6;

		return 0;
	}

	if ((p - value) >= INET6_ADDRSTRLEN) {
		fr_strerror_printf("Invalid IPv6 address string \"%s\"", value);
		return -1;
	}

	/*
	 *	Copy string to temporary buffer if we didn't do it earlier
	 */
	if (inlen == 0) memcpy(buffer, value, p - value);
	buffer[p - value] = '\0';

	if (!resolve) {
		if (inet_pton(AF_INET6, buffer, &(out->ipaddr.ip6addr.s6_addr)) <= 0) {
			fr_strerror_printf("Failed to parse IPv6 address string \"%s\"", value);
			return -1;
		}
	} else if (ip_hton(out, AF_INET6, buffer, fallback) < 0) return -1;

	prefix = strtoul(p + 1, &eptr, 10);
	if (prefix > 128) {
		fr_strerror_printf("Invalid IPv6 mask length \"%s\".  Should be between 0-128", p);
		return -1;
	}
	if (eptr[0] != '\0') {
		fr_strerror_printf("Failed to parse IPv6 address string \"%s\", "
				   "got garbage after mask length \"%s\"", value, eptr);
		return -1;
	}

	if (prefix < 128) {
		struct in6_addr addr;

		addr = fr_in6addr_mask(&(out->ipaddr.ip6addr), prefix);
		memcpy(&(out->ipaddr.ip6addr.s6_addr), &addr, sizeof(addr));
	}

	out->prefix = (uint8_t) prefix;
	out->af = AF_INET6;

	return 0;
}

/** Simple wrapper to decide whether an IP value is v4 or v6 and call the appropriate parser.
 *
 * @param out Where to write the ip address value.
 * @param value to parse.
 * @param inlen Length of value, if value is \0 terminated inlen may be 0.
 * @param resolve If true and value doesn't look like an IP address, try and resolve value as a hostname.
 * @return 0 if ip address was parsed successfully, else -1 on error.
 */
int fr_pton(fr_ipaddr_t *out, char const *value, size_t inlen, bool resolve)
{
	size_t len, i;

	len = (inlen == 0) ? strlen(value) : inlen;
	for (i = 0; i < len; i++) switch (value[i]) {
	/*
	 *	Chars illegal in domain names and IPv4 addresses.
	 *	Must be v6 and cannot be a domain.
	 */
	case ':':
	case '[':
	case ']':
		return fr_pton6(out, value, inlen, false, false);

	/*
	 *	Chars which don't really tell us anything
	 */
	case '.':
	case '/':
		continue;

	default:
		/*
		 *	Outside the range of IPv4 chars, must be a domain
		 *	Use A record in preference to AAAA record.
		 */
		if ((value[i] < '0') || (value[i] > '9')) {
			if (!resolve) return -1;
			return fr_pton4(out, value, inlen, true, true);
		}
		break;
	}

 	/*
 	 *	All chars were in the IPv4 set [0-9/.], must be an IPv4
 	 *	address.
 	 */
	return fr_pton4(out, value, inlen, false, false);
}

/** Check if the IP address is equivalent to INADDR_ANY
 *
 * @param addr to chec.
 * @return true if IP address matches INADDR_ANY or INADDR6_ANY (assumed to be 0), else false.
 */
bool is_wildcard(fr_ipaddr_t *addr)
{
	static struct in6_addr in6_addr;

	switch (addr->af) {
	case AF_INET:
		return (addr->ipaddr.ip4addr.s_addr == htons(INADDR_ANY));

	case AF_INET6:
		return (memcmp(addr->ipaddr.ip6addr.s6_addr, in6_addr.s6_addr, sizeof(in6_addr.s6_addr)) == 0) ? true :false;

	default:
		fr_assert(0);
		return false;
	}
}

int fr_ntop(char *out, size_t outlen, fr_ipaddr_t *addr)
{
	char buffer[INET6_ADDRSTRLEN];

	if (inet_ntop(addr->af, &(addr->ipaddr), buffer, sizeof(buffer)) == NULL) return -1;

	return snprintf(out, outlen, "%s/%i", buffer, addr->prefix);
}

/*
 *	Internal wrapper for locking, to minimize the number of ifdef's
 *
 *	Use fcntl or error
 */
int rad_lockfd(int fd, int lock_len)
{
#ifdef F_WRLCK
	struct flock fl;

	fl.l_start = 0;
	fl.l_len = lock_len;
	fl.l_pid = getpid();
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_CUR;

	return fcntl(fd, F_SETLKW, (void *)&fl);
#else
#error "missing definition for F_WRLCK, all file locks will fail"

	return -1;
#endif
}

/*
 *	Internal wrapper for locking, to minimize the number of ifdef's
 *
 *	Lock an fd, prefer lockf() over flock()
 *	Nonblocking version.
 */
int rad_lockfd_nonblock(int fd, int lock_len)
{
#ifdef F_WRLCK
	struct flock fl;

	fl.l_start = 0;
	fl.l_len = lock_len;
	fl.l_pid = getpid();
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_CUR;

	return fcntl(fd, F_SETLK, (void *)&fl);
#else
#error "missing definition for F_WRLCK, all file locks will fail"

	return -1;
#endif
}

/*
 *	Internal wrapper for unlocking, to minimize the number of ifdef's
 *	in the source.
 *
 *	Unlock an fd, prefer lockf() over flock()
 */
int rad_unlockfd(int fd, int lock_len)
{
#ifdef F_WRLCK
	struct flock fl;

	fl.l_start = 0;
	fl.l_len = lock_len;
	fl.l_pid = getpid();
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_CUR;

	return fcntl(fd, F_UNLCK, (void *)&fl);
#else
#error "missing definition for F_WRLCK, all file locks will fail"

	return -1;
#endif
}

/*
 *	Return an interface-id in standard colon notation
 */
char *ifid_ntoa(char *buffer, size_t size, uint8_t const *ifid)
{
	snprintf(buffer, size, "%x:%x:%x:%x",
		 (ifid[0] << 8) + ifid[1], (ifid[2] << 8) + ifid[3],
		 (ifid[4] << 8) + ifid[5], (ifid[6] << 8) + ifid[7]);
	return buffer;
}


/*
 *	Return an interface-id from
 *	one supplied in standard colon notation.
 */
uint8_t *ifid_aton(char const *ifid_str, uint8_t *ifid)
{
	static char const xdigits[] = "0123456789abcdef";
	char const *p, *pch;
	int num_id = 0, val = 0, idx = 0;

	for (p = ifid_str; ; ++p) {
		if (*p == ':' || *p == '\0') {
			if (num_id <= 0)
				return NULL;

			/*
			 *	Drop 'val' into the array.
			 */
			ifid[idx] = (val >> 8) & 0xff;
			ifid[idx + 1] = val & 0xff;
			if (*p == '\0') {
				/*
				 *	Must have all entries before
				 *	end of the string.
				 */
				if (idx != 6)
					return NULL;
				break;
			}
			val = 0;
			num_id = 0;
			if ((idx += 2) > 6)
				return NULL;
		} else if ((pch = strchr(xdigits, tolower(*p))) != NULL) {
			if (++num_id > 4)
				return NULL;
			/*
			 *	Dumb version of 'scanf'
			 */
			val <<= 4;
			val |= (pch - xdigits);
		} else
			return NULL;
	}
	return ifid;
}


#ifndef HAVE_INET_PTON
static int inet_pton4(char const *src, struct in_addr *dst)
{
	int octet;
	unsigned int num;
	char const *p, *off;
	uint8_t tmp[4];
	static char const digits[] = "0123456789";

	octet = 0;
	p = src;
	while (1) {
		num = 0;
		while (*p && ((off = strchr(digits, *p)) != NULL)) {
			num *= 10;
			num += (off - digits);

			if (num > 255) return 0;

			p++;
		}
		if (!*p) break;

		/*
		 *	Not a digit, MUST be a dot, else we
		 *	die.
		 */
		if (*p != '.') {
			return 0;
		}

		tmp[octet++] = num;
		p++;
	}

	/*
	 *	End of the string.  At the fourth
	 *	octet is OK, anything else is an
	 *	error.
	 */
	if (octet != 3) {
		return 0;
	}
	tmp[3] = num;

	memcpy(dst, &tmp, sizeof(tmp));
	return 1;
}


#ifdef HAVE_STRUCT_SOCKADDR_IN6
/* int
 * inet_pton6(src, dst)
 *	convert presentation level address to network order binary form.
 * return:
 *	1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *	(1) does not touch `dst' unless it's returning 1.
 *	(2) :: in a full address is silently ignored.
 * credit:
 *	inspired by Mark Andrews.
 * author:
 *	Paul Vixie, 1996.
 */
static int inet_pton6(char const *src, unsigned char *dst)
{
	static char const xdigits_l[] = "0123456789abcdef",
			  xdigits_u[] = "0123456789ABCDEF";
	u_char tmp[IN6ADDRSZ], *tp, *endp, *colonp;
	char const *xdigits, *curtok;
	int ch, saw_xdigit;
	u_int val;

	memset((tp = tmp), 0, IN6ADDRSZ);
	endp = tp + IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		char const *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			}
			if (tp + INT16SZ > endp)
				return (0);
			*tp++ = (u_char) (val >> 8) & 0xff;
			*tp++ = (u_char) val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + INADDRSZ) <= endp) &&
		    inet_pton4(curtok, (struct in_addr *) tp) > 0) {
			tp += INADDRSZ;
			saw_xdigit = 0;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + INT16SZ > endp)
			return (0);
		*tp++ = (u_char) (val >> 8) & 0xff;
		*tp++ = (u_char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		int const n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	/* bcopy(tmp, dst, IN6ADDRSZ); */
	memcpy(dst, tmp, IN6ADDRSZ);
	return (1);
}
#endif

/*
 *	Utility function, so that the rest of the server doesn't
 *	have ifdef's around IPv6 support
 */
int inet_pton(int af, char const *src, void *dst)
{
	if (af == AF_INET) {
		return inet_pton4(src, dst);
	}
#ifdef HAVE_STRUCT_SOCKADDR_IN6

	if (af == AF_INET6) {
		return inet_pton6(src, dst);
	}
#endif

	return -1;
}
#endif

#ifndef HAVE_INET_NTOP
/*
 *	Utility function, so that the rest of the server doesn't
 *	have ifdef's around IPv6 support
 */
char const *inet_ntop(int af, void const *src, char *dst, size_t cnt)
{
	if (af == AF_INET) {
		uint8_t const *ipaddr = src;

		if (cnt <= INET_ADDRSTRLEN) return NULL;

		snprintf(dst, cnt, "%d.%d.%d.%d",
			 ipaddr[0], ipaddr[1],
			 ipaddr[2], ipaddr[3]);
		return dst;
	}

	/*
	 *	If the system doesn't define this, we define it
	 *	in missing.h
	 */
	if (af == AF_INET6) {
		struct in6_addr const *ipaddr = src;

		if (cnt <= INET6_ADDRSTRLEN) return NULL;

		snprintf(dst, cnt, "%x:%x:%x:%x:%x:%x:%x:%x",
			 (ipaddr->s6_addr[0] << 8) | ipaddr->s6_addr[1],
			 (ipaddr->s6_addr[2] << 8) | ipaddr->s6_addr[3],
			 (ipaddr->s6_addr[4] << 8) | ipaddr->s6_addr[5],
			 (ipaddr->s6_addr[6] << 8) | ipaddr->s6_addr[7],
			 (ipaddr->s6_addr[8] << 8) | ipaddr->s6_addr[9],
			 (ipaddr->s6_addr[10] << 8) | ipaddr->s6_addr[11],
			 (ipaddr->s6_addr[12] << 8) | ipaddr->s6_addr[13],
			 (ipaddr->s6_addr[14] << 8) | ipaddr->s6_addr[15]);
		return dst;
	}

	return NULL;		/* don't support IPv6 */
}
#endif

/** Wrappers for IPv4/IPv6 host to IP address lookup
 *
 * This function returns only one IP address, of the specified address family,
 * or the first address (of whatever family), if AF_UNSPEC is used.
 *
 * If fallback is specified and af is AF_INET, but no AF_INET records were
 * found and a record for AF_INET6 exists that record will be returned.
 *
 * If fallback is specified and af is AF_INET6, and a record with AF_INET4 exists
 * that record will be returned instead.
 *
 * @param out Where to write result.
 * @param af To search for in preference.
 * @param hostname to search for.
 * @param fallback to the other adress family, if no records matching af, found.
 * @return 0 on success, else -1 on failure.
 */
int ip_hton(fr_ipaddr_t *out, int af, char const *hostname, bool fallback)
{
	int rcode;
	struct addrinfo hints, *ai = NULL, *alt = NULL, *res = NULL;

	if (!fr_hostname_lookups) {
#ifdef HAVE_STRUCT_SOCKADDR_IN6
		if (af == AF_UNSPEC) {
			char const *p;

			for (p = hostname; *p != '\0'; p++) {
				if ((*p == ':') ||
				    (*p == '[') ||
				    (*p == ']')) {
					af = AF_INET6;
					break;
				}
			}
		}
#endif

		if (af == AF_UNSPEC) af = AF_INET;

		if (!inet_pton(af, hostname, &(out->ipaddr))) {
			return -1;
		}

		out->af = af;
		return 0;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;

#ifdef TALLOC_DEBUG
	/*
	 *	Avoid malloc for IP addresses.  This helps us debug
	 *	memory errors when using talloc.
	 */
	if (af == AF_INET) {
		/*
		 *	If it's all numeric, avoid getaddrinfo()
		 */
		if (inet_pton(af, hostname, &out->ipaddr.ip4addr) == 1) {
			return 0;
		}
	}
#endif

	if ((rcode = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
		fr_strerror_printf("ip_hton: %s", gai_strerror(rcode));
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if ((af == ai->ai_family) || (af == AF_UNSPEC)) break;
		if (!alt && fallback && ((ai->ai_family == AF_INET) || (ai->ai_family == AF_INET6))) alt = ai;
	}

	if (!ai) ai = alt;
	if (!ai) {
		fr_strerror_printf("ip_hton failed to find requested information for host %.100s", hostname);
		freeaddrinfo(res);
		return -1;
	}

	rcode = fr_sockaddr2ipaddr((struct sockaddr_storage *)ai->ai_addr,
				   ai->ai_addrlen, out, NULL);
	freeaddrinfo(res);
	if (!rcode) return -1;

	return 0;
}

/*
 *	Look IP addresses up, and print names (depending on DNS config)
 */
char const *ip_ntoh(fr_ipaddr_t const *src, char *dst, size_t cnt)
{
	struct sockaddr_storage ss;
	int error;
	socklen_t salen;

	/*
	 *	No DNS lookups
	 */
	if (!fr_dns_lookups) {
		return inet_ntop(src->af, &(src->ipaddr), dst, cnt);
	}

	if (!fr_ipaddr2sockaddr(src, 0, &ss, &salen)) {
		return NULL;
	}

	if ((error = getnameinfo((struct sockaddr *)&ss, salen, dst, cnt, NULL, 0,
				 NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
		fr_strerror_printf("ip_ntoh: %s", gai_strerror(error));
		return NULL;
	}
	return dst;
}

/** Mask off a portion of an IPv4 address
 *
 * @param ipaddr to mask.
 * @param prefix Number of contiguous bits to mask.
 * @return an ipv6 address with the host portion zeroed out.
 */
struct in_addr fr_inaddr_mask(struct in_addr const *ipaddr, uint8_t prefix)
{
	uint32_t ret;

	if (prefix > 32) {
		prefix = 32;
	}

	/* Short circuit */
	if (prefix == 32) {
		return *ipaddr;
	}

	if (prefix == 0)
		ret = 0;
	else ret = htonl(~((0x00000001UL << (32 - prefix)) - 1)) & ipaddr->s_addr;
	return (*(struct in_addr *)&ret);
}

/** Mask off a portion of an IPv6 address
 *
 * @param ipaddr to mask.
 * @param prefix Number of contiguous bits to mask.
 * @return an ipv6 address with the host portion zeroed out.
 */
struct in6_addr fr_in6addr_mask(struct in6_addr const *ipaddr, uint8_t prefix)
{
	uint64_t const *p = (uint64_t const *) ipaddr;
	uint64_t ret[2], *o = ret;

	if (prefix > 128) {
		prefix = 128;
	}

	/* Short circuit */
	if (prefix == 128) {
		return *ipaddr;
	}

	if (prefix >= 64) {
		prefix -= 64;
		*o++ = 0xffffffffffffffffULL & *p++;
	} else {
		ret[1] = 0;
	}

	*o = htonll(~((0x0000000000000001ULL << (64 - prefix)) - 1)) & *p;

	return *(struct in6_addr *) &ret;
}

/** Zeroes out the host portion of an fr_ipaddr_t
 *
 * @param[in,out] addr to mask
 * @param[in] prefix Length of the network portion.
 */
void fr_ipaddr_mask(fr_ipaddr_t *addr, uint8_t prefix)
{

	switch (addr->af) {
	case AF_INET:
		addr->ipaddr.ip4addr = fr_inaddr_mask(&addr->ipaddr.ip4addr, prefix);
		break;

	case AF_INET6:
		addr->ipaddr.ip6addr = fr_in6addr_mask(&addr->ipaddr.ip6addr, prefix);
		break;

	default:
		return;
	}
	addr->prefix = prefix;
}

static char const hextab[] = "0123456789abcdef";

/** Convert hex strings to binary data
 *
 * @param bin Buffer to write output to.
 * @param outlen length of output buffer (or length of input string / 2).
 * @param hex input string.
 * @param inlen length of the input string
 * @return length of data written to buffer.
 */
size_t fr_hex2bin(uint8_t *bin, size_t outlen, char const *hex, size_t inlen)
{
	size_t i;
	size_t len;
	char *c1, *c2;

	/*
	 *	Smartly truncate output, caller should check number of bytes
	 *	written.
	 */
	len = inlen >> 1;
	if (len > outlen) len = outlen;

	for (i = 0; i < len; i++) {
		if(!(c1 = memchr(hextab, tolower((int) hex[i << 1]), sizeof(hextab))) ||
		   !(c2 = memchr(hextab, tolower((int) hex[(i << 1) + 1]), sizeof(hextab))))
			break;
		bin[i] = ((c1-hextab)<<4) + (c2-hextab);
	}

	return i;
}

/** Convert binary data to a hex string
 *
 * Ascii encoded hex string will not be prefixed with '0x'
 *
 * @warning If the output buffer isn't long enough, we have a buffer overflow.
 *
 * @param[out] hex Buffer to write hex output.
 * @param[in] bin input.
 * @param[in] inlen of bin input.
 * @return length of data written to buffer.
 */
size_t fr_bin2hex(char *hex, uint8_t const *bin, size_t inlen)
{
	size_t i;

	for (i = 0; i < inlen; i++) {
		hex[0] = hextab[((*bin) >> 4) & 0x0f];
		hex[1] = hextab[*bin & 0x0f];
		hex += 2;
		bin++;
	}

	*hex = '\0';
	return inlen * 2;
}

/** Convert binary data to a hex string
 *
 * Ascii encoded hex string will not be prefixed with '0x'
 *
 * @param[in] ctx to alloc buffer in.
 * @param[in] bin input.
 * @param[in] inlen of bin input.
 * @return length of data written to buffer.
 */
char *fr_abin2hex(TALLOC_CTX *ctx, uint8_t const *bin, size_t inlen)
{
	char *buff;

	buff = talloc_array(ctx, char, (inlen << 2));
	if (!buff) return NULL;

	fr_bin2hex(buff, bin, inlen);

	return buff;
}

/** Consume the integer (or hex) portion of a value string
 *
 * @param value string to parse.
 * @param end pointer to the first non numeric char.
 * @return integer value.
 */
uint32_t fr_strtoul(char const *value, char **end)
{
	if ((value[0] == '0') && (value[1] == 'x')) {
		return strtoul(value, end, 16);
	}

	return strtoul(value, end, 10);
}

/** Check whether the string is all whitespace
 *
 * @return true if the entirety of the string is whitespace, else false.
 */
bool is_whitespace(char const *value)
{
	do {
		if (!isspace(*value)) return false;
	} while (*++value);

	return true;
}

/** Check whether the string is all numbers
 *
 * @return true if the entirety of the string is are numebrs, else false.
 */
bool is_integer(char const *value)
{
	do {
		if (!isdigit(*value)) return false;
	} while (*++value);

	return true;
}

/** Check whether the string is allzeros
 *
 * @return true if the entirety of the string is are numebrs, else false.
 */
bool is_zero(char const *value)
{
	do {
		if (*value != '0') return false;
	} while (*++value);

	return true;
}

/*
 *	So we don't have ifdef's in the rest of the code
 */
#ifndef HAVE_CLOSEFROM
int closefrom(int fd)
{
	int i;
	int maxfd = 256;

#ifdef _SC_OPEN_MAX
	maxfd = sysconf(_SC_OPEN_MAX);
	if (maxfd < 0) {
	  maxfd = 256;
	}
#endif

	if (fd > maxfd) return 0;

	/*
	 *	FIXME: return EINTR?
	 *
	 *	Use F_CLOSEM?
	 */
	for (i = fd; i < maxfd; i++) {
		close(i);
	}

	return 0;
}
#endif

int fr_ipaddr_cmp(fr_ipaddr_t const *a, fr_ipaddr_t const *b)
{
	if (a->af < b->af) return -1;
	if (a->af > b->af) return +1;

	switch (a->af) {
	case AF_INET:
		return memcmp(&a->ipaddr.ip4addr,
			      &b->ipaddr.ip4addr,
			      sizeof(a->ipaddr.ip4addr));
		break;

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	case AF_INET6:
		if (a->scope < b->scope) return -1;
		if (a->scope > b->scope) return +1;

		return memcmp(&a->ipaddr.ip6addr,
			      &b->ipaddr.ip6addr,
			      sizeof(a->ipaddr.ip6addr));
		break;
#endif

	default:
		break;
	}

	return -1;
}

int fr_ipaddr2sockaddr(fr_ipaddr_t const *ipaddr, uint16_t port,
		       struct sockaddr_storage *sa, socklen_t *salen)
{
	if (ipaddr->af == AF_INET) {
		struct sockaddr_in s4;

		*salen = sizeof(s4);

		memset(&s4, 0, sizeof(s4));
		s4.sin_family = AF_INET;
		s4.sin_addr = ipaddr->ipaddr.ip4addr;
		s4.sin_port = htons(port);
		memset(sa, 0, sizeof(*sa));
		memcpy(sa, &s4, sizeof(s4));

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (ipaddr->af == AF_INET6) {
		struct sockaddr_in6 s6;

		*salen = sizeof(s6);

		memset(&s6, 0, sizeof(s6));
		s6.sin6_family = AF_INET6;
		s6.sin6_addr = ipaddr->ipaddr.ip6addr;
		s6.sin6_port = htons(port);
		s6.sin6_scope_id = ipaddr->scope;
		memset(sa, 0, sizeof(*sa));
		memcpy(sa, &s6, sizeof(s6));
#endif
	} else {
		return 0;
	}

	return 1;
}


int fr_sockaddr2ipaddr(struct sockaddr_storage const *sa, socklen_t salen,
		       fr_ipaddr_t *ipaddr, uint16_t *port)
{
	if (sa->ss_family == AF_INET) {
		struct sockaddr_in	s4;

		if (salen < sizeof(s4)) {
			fr_strerror_printf("IPv4 address is too small");
			return 0;
		}

		memcpy(&s4, sa, sizeof(s4));
		ipaddr->af = AF_INET;
		ipaddr->prefix = 32;
		ipaddr->ipaddr.ip4addr = s4.sin_addr;
		if (port) *port = ntohs(s4.sin_port);

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (sa->ss_family == AF_INET6) {
		struct sockaddr_in6	s6;

		if (salen < sizeof(s6)) {
			fr_strerror_printf("IPv6 address is too small");
			return 0;
		}

		memcpy(&s6, sa, sizeof(s6));
		ipaddr->af = AF_INET6;
		ipaddr->prefix = 128;
		ipaddr->ipaddr.ip6addr = s6.sin6_addr;
		if (port) *port = ntohs(s6.sin6_port);
		ipaddr->scope = s6.sin6_scope_id;
#endif

	} else {
		fr_strerror_printf("Unsupported address famility %d",
				   sa->ss_family);
		return 0;
	}

	return 1;
}

/** Convert UTF8 string to UCS2 encoding
 *
 * @note Borrowed from src/crypto/ms_funcs.c of wpa_supplicant project (http://hostap.epitest.fi/wpa_supplicant/)
 *
 * @param[out] out Where to write the ucs2 string.
 * @param[in] outlen Size of output buffer.
 * @param[in] in UTF8 string to convert.
 * @param[in] inlen length of UTF8 string.
 * @return the size of the UCS2 string written to the output buffer (in bytes).
 */
ssize_t fr_utf8_to_ucs2(uint8_t *out, size_t outlen, char const *in, size_t inlen)
{
	size_t i;
	uint8_t *start = out;

	for (i = 0; i < inlen; i++) {
		uint8_t c, c2, c3;

		c = in[i];
		if ((size_t)(out - start) >= outlen) {
			/* input too long */
			return -1;
		}

		/* One-byte encoding */
		if (c <= 0x7f) {
			FR_PUT_LE16(out, c);
			out += 2;
			continue;
		} else if ((i == (inlen - 1)) || ((size_t)(out - start) >= (outlen - 1))) {
			/* Incomplete surrogate */
			return -1;
		}

		c2 = in[++i];
		/* Two-byte encoding */
		if ((c & 0xe0) == 0xc0) {
			FR_PUT_LE16(out, ((c & 0x1f) << 6) | (c2 & 0x3f));
			out += 2;
			continue;
		}
		if ((i == inlen) || ((size_t)(out - start) >= (outlen - 1))) {
			/* Incomplete surrogate */
			return -1;
		}

		/* Three-byte encoding */
		c3 = in[++i];
		FR_PUT_LE16(out, ((c & 0xf) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f));
		out += 2;
	}

	return out - start;
}

/** Write 128bit unsigned integer to buffer
 *
 * @author Alexey Frunze
 *
 * @param out where to write result to.
 * @param outlen size of out.
 * @param num 128 bit integer.
 */
size_t fr_prints_uint128(char *out, size_t outlen, uint128_t const num)
{
	char buff[128 / 3 + 1 + 1];
	uint64_t n[2];
	char *p = buff;
	int i;

	memset(buff, '0', sizeof(buff) - 1);
	buff[sizeof(buff) - 1] = '\0';

	memcpy(n, &num, sizeof(n));

	for (i = 0; i < 128; i++) {
		ssize_t j;
		int carry;

		carry = (n[1] >= 0x8000000000000000);

		// Shift n[] left, doubling it
		n[1] = ((n[1] << 1) & 0xffffffffffffffff) + (n[0] >= 0x8000000000000000);
		n[0] = ((n[0] << 1) & 0xffffffffffffffff);

		// Add s[] to itself in decimal, doubling it
		for (j = sizeof(buff) - 2; j >= 0; j--) {
			buff[j] += buff[j] - '0' + carry;
			carry = (buff[j] > '9');
			if (carry) {
				buff[j] -= 10;
			}
		}
	}

	while ((*p == '0') && (p < &buff[sizeof(buff) - 2])) {
		p++;
	}

	return strlcpy(out, p, outlen);
}

/** Calculate powers
 *
 * @author Orson Peters
 * @note Borrowed from the gist here: https://gist.github.com/nightcracker/3551590.
 *
 * @param base a 32bit signed integer.
 * @param exp amount to raise base by.
 * @return base ^ pow, or 0 on underflow/overflow.
 */
int64_t fr_pow(int32_t base, uint8_t exp) {
	static const uint8_t highest_bit_set[] = {
		0, 1, 2, 2, 3, 3, 3, 3,
		4, 4, 4, 4, 4, 4, 4, 4,
		5, 5, 5, 5, 5, 5, 5, 5,
		5, 5, 5, 5, 5, 5, 5, 5,
		6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 6,
		6, 6, 6, 6, 6, 6, 6, 255, // anything past 63 is a guaranteed overflow with base > 1
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
	};

	uint64_t result = 1;

	switch (highest_bit_set[exp]) {
	case 255: // we use 255 as an overflow marker and return 0 on overflow/underflow
		if (base == 1) {
			return 1;
		}

		if (base == -1) {
			return 1 - 2 * (exp & 1);
		}
		return 0;
	case 6:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
	case 5:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
	case 4:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
	case 3:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
	case 2:
		if (exp & 1) result *= base;
		exp >>= 1;
		base *= base;
	case 1:
		if (exp & 1) result *= base;
	default:
		return result;
	}
}

/*
 *	Sort of strtok/strsep function.
 */
static char *mystrtok(char **ptr, char const *sep)
{
	char	*res;

	if (**ptr == 0) {
		return NULL;
	}

	while (**ptr && strchr(sep, **ptr)) {
		(*ptr)++;
	}
	if (**ptr == 0) {
		return NULL;
	}

	res = *ptr;
	while (**ptr && strchr(sep, **ptr) == NULL) {
		(*ptr)++;
	}

	if (**ptr != 0) {
		*(*ptr)++ = 0;
	}
	return res;
}

/** Convert string in various formats to a time_t
 *
 * @param date_str input date string.
 * @param date time_t to write result to.
 * @return 0 on success or -1 on error.
 */
int fr_get_time(char const *date_str, time_t *date)
{
	int		i;
	time_t		t;
	struct tm	*tm, s_tm;
	char		buf[64];
	char		*p;
	char		*f[4];
	char		*tail = NULL;

	/*
	 * Test for unix timestamp date
	 */
	*date = strtoul(date_str, &tail, 10);
	if (*tail == '\0') {
		return 0;
	}

	tm = &s_tm;
	memset(tm, 0, sizeof(*tm));
	tm->tm_isdst = -1;	/* don't know, and don't care about DST */

	strlcpy(buf, date_str, sizeof(buf));

	p = buf;
	f[0] = mystrtok(&p, " \t");
	f[1] = mystrtok(&p, " \t");
	f[2] = mystrtok(&p, " \t");
	f[3] = mystrtok(&p, " \t"); /* may, or may not, be present */
	if (!f[0] || !f[1] || !f[2]) return -1;

	/*
	 *	The time has a colon, where nothing else does.
	 *	So if we find it, bubble it to the back of the list.
	 */
	if (f[3]) {
		for (i = 0; i < 3; i++) {
			if (strchr(f[i], ':')) {
				p = f[3];
				f[3] = f[i];
				f[i] = p;
				break;
			}
		}
	}

	/*
	 *  The month is text, which allows us to find it easily.
	 */
	tm->tm_mon = 12;
	for (i = 0; i < 3; i++) {
		if (isalpha( (int) *f[i])) {
			/*
			 *  Bubble the month to the front of the list
			 */
			p = f[0];
			f[0] = f[i];
			f[i] = p;

			for (i = 0; i < 12; i++) {
				if (strncasecmp(months[i], f[0], 3) == 0) {
					tm->tm_mon = i;
					break;
				}
			}
		}
	}

	/* month not found? */
	if (tm->tm_mon == 12) return -1;

	/*
	 *  The year may be in f[1], or in f[2]
	 */
	tm->tm_year = atoi(f[1]);
	tm->tm_mday = atoi(f[2]);

	if (tm->tm_year >= 1900) {
		tm->tm_year -= 1900;

	} else {
		/*
		 *  We can't use 2-digit years any more, they make it
		 *  impossible to tell what's the day, and what's the year.
		 */
		if (tm->tm_mday < 1900) return -1;

		/*
		 *  Swap the year and the day.
		 */
		i = tm->tm_year;
		tm->tm_year = tm->tm_mday - 1900;
		tm->tm_mday = i;
	}

	/*
	 *  If the day is out of range, die.
	 */
	if ((tm->tm_mday < 1) || (tm->tm_mday > 31)) {
		return -1;
	}

	/*
	 *	There may be %H:%M:%S.  Parse it in a hacky way.
	 */
	if (f[3]) {
		f[0] = f[3];	/* HH */
		f[1] = strchr(f[0], ':'); /* find : separator */
		if (!f[1]) return -1;

		*(f[1]++) = '\0'; /* nuke it, and point to MM:SS */

		f[2] = strchr(f[1], ':'); /* find : separator */
		if (f[2]) {
		  *(f[2]++) = '\0';	/* nuke it, and point to SS */
		  tm->tm_sec = atoi(f[2]);
		}			/* else leave it as zero */

		tm->tm_hour = atoi(f[0]);
		tm->tm_min = atoi(f[1]);
	}

	/*
	 *  Returns -1 on error.
	 */
	t = mktime(tm);
	if (t == (time_t) -1) return -1;

	*date = t;

	return 0;
}

/** Compares two pointers
 *
 * @param a first pointer to compare.
 * @param b second pointer to compare.
 * @return -1 if a < b, +1 if b > a, or 0 if both equal.
 */
int8_t fr_pointer_cmp(void const *a, void const *b)
{
	if (a < b) return -1;
	if (a == b) return 0;

	return 1;
}

static int _quick_partition(void const *to_sort[], int min, int max, fr_cmp_t cmp) {
	void const *pivot = to_sort[min];
	int i = min;
	int j = max + 1;
	void const *tmp;

	for (;;) {
		do ++i; while((cmp(to_sort[i], pivot) <= 0) && i <= max);
		do --j; while(cmp(to_sort[j], pivot) > 0);

		if (i >= j) break;

		tmp = to_sort[i];
		to_sort[i] = to_sort[j];
		to_sort[j] = tmp;
	}

	tmp = to_sort[min];
	to_sort[min] = to_sort[j];
	to_sort[j] = tmp;

	return j;
}

/** Quick sort an array of pointers using a comparator
 *
 * @param to_sort array of pointers to sort.
 * @param min_idx the lowest index (usually 0).
 * @param max_idx the highest index (usually length of array - 1).
 * @param cmp the comparison function to use to sort the array elements.
 */
void fr_quick_sort(void const *to_sort[], int min_idx, int max_idx, fr_cmp_t cmp)
{
	int part;

	if (min_idx >= max_idx) return;

	part = _quick_partition(to_sort, min_idx, max_idx, cmp);
	fr_quick_sort(to_sort, min_idx, part - 1, cmp);
	fr_quick_sort(to_sort, part + 1, max_idx, cmp);
}

#ifdef TALLOC_DEBUG
void fr_talloc_verify_cb(UNUSED const void *ptr, UNUSED int depth,
			 UNUSED int max_depth, UNUSED int is_ref,
			 UNUSED void *private_data)
{
	/* do nothing */
}
#endif
