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

#include <sys/time.h>

#include <glib.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define AF_INET_POS 0
#define AF_INET6_POS 1
#define AF_ARRAY_LENGTH 2

typedef void (*util_debug_func_t)(const char *str, void *user_data);

void util_debug(util_debug_func_t function, void *user_data,
						const char *format, ...)
					__attribute__((format(printf, 3, 4)));

void util_hexdump(const char dir, const unsigned char *buf, size_t len,
				util_debug_func_t function, void *user_data);

struct cb_data {
	void *cb;
	void *user_data;
	void *data;
};

static inline struct cb_data *cb_data_new(void *cb, void *user_data)
{
	struct cb_data *ret;

	ret = g_new0(struct cb_data, 1);
	ret->cb = cb;
	ret->user_data = user_data;

	return ret;
}

void util_iso8601_to_timeval(char *str, struct timeval *time);
char *util_timeval_to_iso8601(struct timeval *time);

void util_set_afs(bool *afs, int family);
bool util_get_afs(bool *afs, int family);
void util_reset_afs(bool *afs);

typedef int (*config_callback) (const char *filepath);
/* Returns -ENOTSUP for non G_FILE_ERROR in error */
int util_g_file_error_to_errno(GError *error);
int util_read_config_files_from(const char *path, const char *suffix,
					GList **conffiles, config_callback cb);
