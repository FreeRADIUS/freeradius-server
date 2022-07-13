/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 of the
 *   License as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Functions for getting information about the system architecture
 *
 * @file src/lib/util/hw.c
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#define CACHE_LINE_DEFAULT	128
#define CORES_DEFAULT		1

#include <freeradius-devel/util/hw.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sysctl.h>
size_t fr_hw_cache_line_size(void)
{
	size_t cache_line_size		= CACHE_LINE_DEFAULT;
	size_t cache_line_size_len	= sizeof(cache_line_size);

	sysctlbyname("hw.cachelinesize", &cache_line_size, &cache_line_size_len, 0, 0);

	return cache_line_size;
}

uint32_t fr_hw_num_cores_active(void)
{
	uint32_t num_cores		= CORES_DEFAULT;
	size_t num_cores_len		= sizeof(num_cores);

	sysctlbyname("hw.physicalcpu", &num_cores, &num_cores_len, 0, 0);

	return num_cores;
}

#elif defined(__linux__)
#include <stdio.h>
#include <unistd.h>
size_t fr_hw_cache_line_size(void)
{
	FILE *file			= NULL;
	unsigned int cache_line_size	= CACHE_LINE_DEFAULT;

	file = fopen("/sys/devices/system/cpu/cpu0/cache/index0/coherency_cache_line_size", "r");
	if (file) {
		if (fscanf(file, "%d", &cache_line_size) != 1) {
			cache_line_size = CACHE_LINE_DEFAULT;
		}
		fclose(file);
	}

	return cache_line_size;
}

uint32_t fr_hw_num_cores_active(void)
{
	uint32_t lcores = 0, tsibs = 0;

	char buff[32];
	char path[64];

	for (lcores = 0;;lcores++) {
		FILE *cpu;

		snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%u/topology/thread_siblings_list", lcores);

		cpu = fopen(path, "r");
		if (!cpu) break;

		while (fscanf(cpu, "%[0-9]", buff)) {
			tsibs++;
			if (fgetc(cpu) != ',') break;
		}

		fclose(cpu);
	}

	/*
	 *	Catch Linux weirdness.
	 *
	 *	You'd think this'd be enough to quiet clang scan,
	 *	but it's not.
	 */
	if (unlikely((tsibs == 0) || (lcores == 0) || (lcores > tsibs))) return 1;

#ifdef STATIC_ANALYZER
	/*
	 *	Prevent static analyzer from warning about divide by zero
	 */
	if ((tsibs / lcores) == 0) return 1;
#endif

	return lcores / (tsibs / lcores);
}
#else
size_t fr_hw_cache_line_size(void)
{
	return CACHE_LINE_DEFAULT;
}

uint32_t fr_hw_num_cores_active(void)
{
	return CORES_DEFAULT;
}
#endif
