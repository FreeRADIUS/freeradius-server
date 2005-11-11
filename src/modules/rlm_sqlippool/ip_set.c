/*
 * ip_set.c
 *
 * Version:  $Id$
 *
 * Copyright 2002  Globe.Net Communications Limited
 */

#if 0
#include "config.h"
#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/libradius.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/conffile.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#include "ip_set.h"

void ip_set_initialize(ip_set * ips)
{
	ips->length = 0;
	ips->allocated = 0;
	ips->ranges = NULL;
}

void ip_set_free(ip_set * ips)
{
	if (ips->ranges)
		free(ips->ranges);
	ip_set_initialize(ips);
}

int ip_set_add(ip_set * ips, uint32_t h_ip)
{
	int i;
	int new_i;
	ip_range * ipr;

	for (i = 0; i < ips->length; i++) {
		ipr = &ips->ranges[i];

		if (h_ip == (ipr->h_start - 1))
		{
			ipr->h_start = h_ip;
			return 1;
		}
		else if (h_ip < ipr->h_start)
			break;
		else if (h_ip <= ipr->h_finish)
			return 0;
		else if (h_ip == (ipr->h_finish + 1))
		{
			ipr->h_finish = h_ip;

			if (i+1 < ips->length && h_ip == ((ipr+1)->h_start - 1)) {
				/*
				 * Join two ranges
				 */
				ipr->h_finish = (ipr+1)->h_finish;

				for (i = i+1; i < ips->length; i++) {
					ipr = &ips->ranges[i];

					ipr->h_start = (ipr+1)->h_start;
					ipr->h_finish = (ipr+1)->h_finish;
				}
				ips->length--;
			}

			return 1;
		}
	}
	new_i = i;

	/*
	 * Ok, add another range
	 */
	ips->length++;

	if (ips->ranges == NULL) {
#ifdef TEST_IP_SET
		ips->allocated = 4;
#else /* !TEST_IP_SET */
		ips->allocated = 64;
#endif /* !TEST_IP_SET */
		ips->ranges = malloc(ips->allocated * sizeof(ip_range));
		if (ips->ranges == NULL)
			return -1;
	}
	else if (ips->length > ips->allocated) {
		ip_range * ranges;

		ips->allocated *= 2;
		ranges = realloc(ips->ranges, ips->allocated * sizeof(ip_range));
		if (ranges == NULL)
			return -1;
		ips->ranges = ranges;
	}

	for (i = ips->length-2; i >= new_i; i--) {
		ipr = &ips->ranges[i];

		(ipr+1)->h_start = ipr->h_start;
		(ipr+1)->h_finish = ipr->h_finish;
	}

	ipr = &ips->ranges[new_i];
	ipr->h_start = h_ip;
	ipr->h_finish = h_ip;

	return 1;
}

int ip_set_test(ip_set * ips, uint32_t h_ip)
{
	int i;
	ip_range * ipr;

	for (i = 0; i < ips->length; i++) {
		ipr = &ips->ranges[i];

		if (h_ip < ipr->h_start)
			break;

		else if (ipr->h_start <= h_ip && h_ip <= ipr->h_finish)
			return 1;
	}

	return 0;
}

#ifdef TEST_IP_SET
void ip_set_dump(ip_set * ips, FILE * f)
{
	int i;
	ip_range * ipr;
	uint32_t h_ip;

	fprintf(f, "ip_set: length=%d, allocated=%d\n", ips->length, ips->allocated);
	for (i = 0; i < ips->length; i++) {
		fprintf(f, "\t%d: %08x-%08x\n",
			i,
			ips->ranges[i].h_start,
			ips->ranges[i].h_finish);
	}

	h_ip = 0;
	for (i = 0; i < ips->length; i++) {
		ipr = &ips->ranges[i];

		if (h_ip+1 == ipr->h_start) {
			fprintf(f, "\tinvalid gap at %d\n", i);
		}
		if (h_ip >= ipr->h_start) {
			fprintf(f, "\tinvalid start at %d\n", i);
		}
		if (ipr->h_start > ipr->h_finish) {
			fprintf(f, "\tinvalid range at %d\n", i);
		}

		h_ip = ipr->h_finish;
	}
	fprintf(f, "\n");

	for (h_ip = 0x0a000030; h_ip < 0x0a000090; h_ip++)
	{
		if (h_ip % 16 == 0)
			fprintf(f, "\t%08x: ", h_ip);
		fprintf(f, "%d", ip_set_test(ips, h_ip));
		fprintf(f, (h_ip % 16 == 15) ? "\n" : " ");
	}
}

int main(void)
{
	ip_set ips;
	uint32_t h_ip;

	ip_set_initialize(&ips);
	ip_set_add(&ips, 0x0a000040);
	ip_set_add(&ips, 0x0a000050);
	ip_set_add(&ips, 0x0a000060);
	ip_set_add(&ips, 0x0a000070);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	ip_set_add(&ips, 0x0a000048);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	ip_set_add(&ips, 0x0a000058);
	ip_set_add(&ips, 0x0a000068);
	ip_set_add(&ips, 0x0a000078);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	ip_set_add(&ips, 0x0a000038);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	ip_set_add(&ips, 0x0a000039);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	ip_set_add(&ips, 0x0a000077);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	ip_set_add(&ips, 0x0a000037);
	ip_set_add(&ips, 0x0a000079);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	ip_set_add(&ips, 0x0a000080);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	ip_set_add(&ips, 0x0a000080);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	for (h_ip = 0x0a000070; h_ip <= 0x0a000075; h_ip++)
		ip_set_add(&ips, h_ip);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	ip_set_add(&ips, 0x0a000076);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	for (h_ip = 0x0a000070; h_ip <= 0x0a00007f; h_ip++)
		ip_set_add(&ips, h_ip);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	for (h_ip = 0x0a000062; h_ip >= 0x0a000041; h_ip--)
		ip_set_add(&ips, h_ip);
	ip_set_dump(&ips, stdout); fprintf(stdout, "\n");

	ip_set_free(&ips);

	return 0;
}
#endif /* TEST_IP_SET */
