/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>

#include "src/shared/util.h"

void util_debug(util_debug_func_t function, void *user_data,
						const char *format, ...)
{
	char str[78];
	va_list ap;

	if (!function || !format)
		return;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

	function(str, user_data);
}

void util_hexdump(const char dir, const unsigned char *buf, size_t len,
				util_debug_func_t function, void *user_data)
{
	static const char hexdigits[] = "0123456789abcdef";
	char str[68];
	size_t i;

	if (!function || !len)
		return;

	str[0] = dir;

	for (i = 0; i < len; i++) {
		str[((i % 16) * 3) + 1] = ' ';
		str[((i % 16) * 3) + 2] = hexdigits[buf[i] >> 4];
		str[((i % 16) * 3) + 3] = hexdigits[buf[i] & 0xf];
		str[(i % 16) + 51] = isprint(buf[i]) ? buf[i] : '.';

		if ((i + 1) % 16 == 0) {
			str[49] = ' ';
			str[50] = ' ';
			str[67] = '\0';
			function(str, user_data);
			str[0] = ' ';
		}
	}

	if (i % 16 > 0) {
		size_t j;
		for (j = (i % 16); j < 16; j++) {
			str[(j * 3) + 1] = ' ';
			str[(j * 3) + 2] = ' ';
			str[(j * 3) + 3] = ' ';
			str[j + 51] = ' ';
		}
		str[49] = ' ';
		str[50] = ' ';
		str[67] = '\0';
		function(str, user_data);
	}
}

void util_iso8601_to_timeval(char *str, struct timeval *time)
{
	struct tm tm;
	time_t t;
	char *p;

	p = strptime(str, "%FT%T", &tm);
	if (!p)
		return;

	if (*p != 'Z') {
		/* backwards compatibility */
		if (*p != '.' || p[strlen(p) - 1] != 'Z')
			return;
	}

	t = mktime(&tm);
	if (t < 0)
		return;

	time->tv_sec = t;
	time->tv_usec = 0;
}

char *util_timeval_to_iso8601(struct timeval *time)
{
	char buf[255];
	struct tm tm;
	time_t t;

	t = time->tv_sec;
	if (!localtime_r(&t, &tm))
		return NULL;
	if (!strftime(buf, sizeof(buf), "%FT%TZ", &tm))
		return NULL;

	return g_strdup(buf);
}

void util_set_afs(bool *afs, int family)
{
	if (!afs)
		return;

	switch (family) {
	case AF_INET:
		afs[AF_INET_POS] = true;
		break;
	case AF_INET6:
		afs[AF_INET6_POS] = true;
		break;
	default:
		break;
	}
}

bool util_get_afs(bool *afs, int family)
{
	if (!afs)
		return false;

	switch (family) {
	case AF_INET:
		return afs[AF_INET_POS];
	case AF_INET6:
		return afs[AF_INET6_POS];
	default:
		return false;
	}
}

void util_reset_afs(bool *afs)
{
	if (!afs)
		return;

	afs[AF_INET_POS] = afs[AF_INET6_POS] = false;
}
