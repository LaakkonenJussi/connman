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
#include <fcntl.h>
#include <unistd.h>

#include <connman/log.h>

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

static bool is_file_symlink(const char *filename)
{
	int fd;

	fd = open(filename, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd == -1 && errno == ELOOP)
		return true;

	if (fd >= 0)
		close(fd);

	return false;
}

int util_g_file_error_to_errno(GError *error)
{
	if (!error)
		return -EBADMSG;

	if (error->domain != G_FILE_ERROR)
		return -ENOTSUP;

	switch (error->code) {
	case G_FILE_ERROR_EXIST:
		return -EEXIST;
	case G_FILE_ERROR_ISDIR:
		return -EISDIR;
	case G_FILE_ERROR_ACCES:
		return -EACCES;
	case G_FILE_ERROR_NAMETOOLONG:
		return -ENAMETOOLONG;
	case G_FILE_ERROR_NOENT:
		return -ENOENT;
	case G_FILE_ERROR_NOTDIR:
		return -ENOTDIR;
	case G_FILE_ERROR_NXIO:
		return -ENXIO;
	case G_FILE_ERROR_NODEV:
		return -ENODEV;
	case G_FILE_ERROR_ROFS:
		return -EROFS;
	case G_FILE_ERROR_TXTBSY:
		return -ETXTBSY;
	case G_FILE_ERROR_FAULT:
		return -EFAULT;
	case G_FILE_ERROR_LOOP:
		return -ELOOP;
	case G_FILE_ERROR_NOSPC:
		return -ENOSPC;
	case G_FILE_ERROR_NOMEM:
		return -ENOMEM;
	case G_FILE_ERROR_MFILE:
		return -EMFILE;
	case G_FILE_ERROR_NFILE:
		return -ENFILE;
	case G_FILE_ERROR_BADF:
		return EBADF;
	case G_FILE_ERROR_INVAL:
		return -EINVAL;
	case G_FILE_ERROR_PIPE:
		return -EPIPE;
	case G_FILE_ERROR_AGAIN:
		return -EAGAIN;
	case G_FILE_ERROR_INTR:
		return -EINTR;
	case G_FILE_ERROR_IO:
		return -EIO;
	case G_FILE_ERROR_PERM:
		return -EPERM;
	case G_FILE_ERROR_NOSYS:
		return -ENOSYS;
	case G_FILE_ERROR_FAILED:
		return -EINVAL;
	}

	return -EINVAL;
}

int util_read_config_files_from(const char *path, const char *suffix,
					GList **conffiles, config_callback cb)
{
	GList *files = NULL;
	GList *iter;
	GError *error = NULL;
	GDir *dir;
	const char *filename = NULL;
	int err = 0;

	if (!path || !suffix)
		return -EINVAL;

	if (!g_file_test(path, G_FILE_TEST_IS_DIR))
		return -ENOTDIR;

	dir = g_dir_open(path, 0, &error);
	if (!dir) {
		if (error) {
			connman_warn("cannot open dir %s, error: %s", path,
								error->message);
			err = util_g_file_error_to_errno(error);
		} else {
			err = -ENOMEM;
		}
	}

	g_clear_error(&error);

	if (err)
		return err;

	/*
	 * Ordering of files is not guaranteed with g_dir_open(). Read
	 * the filenames into list to be sorted after.
	 */
	while ((filename = g_dir_read_name(dir))) {
		char *filepath;

		/* Read configs that have the requested conf suffix */
		if (!g_str_has_suffix(filename, suffix)) {
			connman_warn("suffix mismatch in %s required: %s",
							filename, suffix);
			continue;
		}

		filepath = g_build_filename(path, filename, NULL);

		/* Allow only regular files */
		if (!g_file_test(filepath, G_FILE_TEST_IS_REGULAR)) {
			connman_warn("invalid non-regular file %s", filepath);
			g_free(filepath);
			continue;
		}

		/* Do not allow symlinks */
		if (is_file_symlink(filepath)) {
			connman_warn("config %s is a symlink, ignore",
							filepath);
			g_free(filepath);
			continue;
		}

		/*
		 * Prepend read files into list of configuration
		 * files to be used in checks when new configurations
		 * are added to avoid unnecessary reads of already read
		 * configurations. Sort list after all are added.
		 */
		files = g_list_prepend(files, filepath);
	}

	g_dir_close(dir);

	files = g_list_sort(files, (GCompareFunc)g_strcmp0);

	if (cb) {
		for (iter = files; iter; iter = iter->next) {
			filename = iter->data;

			err = cb(filename);
			if (err)
				connman_warn("cannot process config %s: %d",
								filename, err);
		}
	}

	if (conffiles)
		*conffiles = files;
	else
		g_list_free_full(files, g_free);

	return 0;
}

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static const char *wpa3_sae_pwe_options[] = {	WPA3_SAE_PWE_STR_HNP,
						WPA3_SAE_PWE_STR_H2E,
						WPA3_SAE_PWE_STR_BOTH,
						WPA3_SAE_PWE_STR_FORCE,
						NULL,
					};

int util_wpa3_sae_pwe_index(const char *str)
{
	int i;

	if (!str || !*str)
		return -EINVAL;

	for (i = 0; wpa3_sae_pwe_options[i]; i++) {
		if (!g_ascii_strcasecmp(str, wpa3_sae_pwe_options[i])) 
			return i;
	}

	return -EINVAL;
}
