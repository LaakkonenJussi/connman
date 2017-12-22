/*
 *
 *  Connection Manager unit test for the exposed iptables functions
 *  for SailfishOS MDM.
 *
 *  Copyright (C) 2017 Jolla Ltd. All rights reserved.
 *  Contact: Jussi Laakkonen <jussi.laakkonen@jolla.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <glib.h>
#include <stdio.h>
#include <unistd.h>
#include "src/connman.h"
#include "include/iptables_extension.h"

#define PREFIX 	"/iptables"

const gchar const * invalid_paths[] = {
	"/",
	"/bin/",
	"/boot/",
	"/etc/",
	"/etc/default/",
	"/home/",
	"/home/nemo/",
	"/lib/",
	"/media/",
	"/mnt/",
	"/opt/",
	"/proc/",
	"/root/",
	"/run/",
	"/sbin/",
	"/srv/",
	"/sys/",
	"/tmp/",
	"/test/",
	"/usr/",
	"/usr/bin/",
	"/usr/local/bin/",
	"/usr/local/lib/",
	"/usr/local/sbin/",
	"/var/",
	NULL
	};

const gchar const * test_files[] = {
	"test.file",
	"connman/",
	"connman/test.file",
	NULL
	};

// From sailfish_iptables_extension.c since this is not defined anywhere
typedef struct output_capture_data {
	gint stdout_pipes[2];
	gint stdout_saved;
	gint stdout_read_limit;
	gint stdout_bytes_read;
	gchar *stdout_data;
} output_capture_data;

// Function protos
gint check_save_directory(const char* fpath);
gboolean iptables_set_file_contents(const gchar *fpath, GString *str);
GString* iptables_get_file_contents(const gchar* fpath);

gint stdout_capture_start(output_capture_data *data);
void stdout_capture_data(output_capture_data *data);
gint stdout_capture_end(output_capture_data *data);

int iptables_check_table(const char *table_name);

void test_iptables_file_access_basic()
{
	__connman_storage_init(NULL, 0700, 0600); // From main.c
	
	g_assert(!iptables_set_file_contents(NULL, NULL));
	g_assert(!iptables_set_file_contents("", NULL));
	
	gchar *path = g_strdup("some/path");
	g_assert(!iptables_set_file_contents(path,NULL));
	
	g_assert(!iptables_get_file_contents(NULL));
	g_assert(!iptables_get_file_contents(""));
	
	GString *str = g_string_new(NULL);
	g_assert(!iptables_set_file_contents(path, str));
	
	g_string_printf(str, "content");
	g_assert(!iptables_set_file_contents(path, str));
	
	g_free(path);
	g_string_free(str, true);
	
	__connman_storage_cleanup();
}

void test_iptables_file_access_fail()
{	
	gint i = 0, j = 0;
	GString *str = g_string_new("content");
	
	__connman_storage_init(NULL, 0700, 0600); // From main.c
	
	for(i = 0; invalid_paths[i]; i++)
	{
		for(j = 0; test_files[j]; j++)
		{
			gchar *path = g_strdup_printf("%s%s", invalid_paths[i],
				test_files[j]);
			
			// First check that these paths cannot be written to
			g_assert(check_save_directory(path));
			g_assert(!iptables_set_file_contents(path,str));
			
			g_free(path);
		}	
	}
	
	g_string_free(str,true);
	
	__connman_storage_cleanup();
}

void test_iptables_file_access_success()
{
	gchar content[] = "content";
	GString *str = g_string_new(content);
	gchar *path = g_strdup("/tmp/connman/iptables-test/test.file");
	
	// Initialize custom dir for testing
	__connman_storage_init("/tmp", 0700, 0600); // From main.c

	g_assert(!check_save_directory(path));
	g_assert(iptables_set_file_contents(path,str));
	g_assert(g_file_test(path,G_FILE_TEST_EXISTS));
	
	GString* str_get = iptables_get_file_contents(path);
	g_assert(str_get);

	g_assert(!g_ascii_strcasecmp(str_get->str, content));
	
	g_free(path);
	g_string_free(str_get, true);
	
	__connman_storage_cleanup();
}

void test_iptables_save_fail()
{
	gint i = 0, j = 0;
	gchar table_name[] = "filter";
	
	__connman_storage_init(NULL, 0700, 0600); // From main.c
	
	g_assert(connman_iptables_save(NULL,NULL));
	g_assert(connman_iptables_save("",NULL));
	g_assert(connman_iptables_save(NULL,""));
	
	g_assert(connman_iptables_save(table_name,NULL));
	g_assert(connman_iptables_save(table_name,""));
	
	for(i = 0; invalid_paths[i]; i++)
	{
		for(j = 0; test_files[j]; j++)
		{
			gchar *path = g_strdup_printf("%s%s", invalid_paths[i],
				test_files[j]);
			
			g_assert(connman_iptables_save(table_name, path));
			
			g_free(path);
		}	
	}
	
	__connman_storage_cleanup();
}

void test_iptables_restore_fail()
{
	gint i = 0, j = 0;
	gchar table_name[] = "filter";
	
	__connman_storage_init(NULL, 0700, 0600); // From main.c
	
	g_assert(connman_iptables_restore(NULL,NULL));
	g_assert(connman_iptables_restore("",NULL));
	g_assert(connman_iptables_restore(NULL,""));
	
	g_assert(connman_iptables_restore(table_name,NULL));
	g_assert(connman_iptables_restore(table_name,""));
	
	for(i = 0; invalid_paths[i]; i++)
	{
		for(j = 0; test_files[j]; j++)
		{
			gchar *path = g_strdup_printf("%s%s", invalid_paths[i],
				test_files[j]);
			
			g_assert(connman_iptables_restore(table_name, path));
			
			g_free(path);
		}	
	}
	
	__connman_storage_cleanup();
}

void test_iptables_clear_fail()
{
	g_assert(connman_iptables_clear(NULL));
	g_assert(connman_iptables_clear(""));
	g_assert(connman_iptables_clear("not-table"));
}

void test_iptables_stdout_capture()
{
	gchar testprint[] = "A line";
	gint error = 0;
	
	output_capture_data data = {
		.stdout_pipes = {0},
		.stdout_saved = 0,
		.stdout_read_limit = 2000,
		.stdout_bytes_read = 0,
		.stdout_data = NULL
	};
	
	g_assert(!stdout_capture_start(&data));
	
	printf("%s", testprint);
	
	fflush(stdout);
	
	stdout_capture_data(&data);
	
	// This should not be asserted, output will remain captured if this fails
	// Check return value later, try to recover calling dup2 again
	if((error = stdout_capture_end(&data)))
	{
		perror("stdout_capture_end() failed, trying to recover with dup2");
		error = dup2(data.stdout_saved,fileno(stdout));
	}
	
	g_assert(!error);
	
	g_assert(data.stdout_bytes_read);
	
	g_assert(!g_ascii_strcasecmp(data.stdout_data, testprint));
	
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	
	g_test_add_func(PREFIX "/file_access_basic", test_iptables_file_access_basic);
	g_test_add_func(PREFIX "/file_access_fail", test_iptables_file_access_fail);
	g_test_add_func(PREFIX "/file_access_success", test_iptables_file_access_success);
	
	g_test_add_func(PREFIX "/save_fail", test_iptables_save_fail);
	g_test_add_func(PREFIX "/restore_fail", test_iptables_restore_fail);
	g_test_add_func(PREFIX "/clear_fail", test_iptables_clear_fail);
	
	g_test_add_func(PREFIX "/stdout_capture", test_iptables_stdout_capture);
	
	return g_test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
