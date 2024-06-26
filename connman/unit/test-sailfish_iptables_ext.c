/*
 *
 *  Connection Manager unit test for the exposed iptables functions
 *  for SailfishOS MDM.
 *
 *  Copyright (C) 2017-2020  Jolla Ltd. All rights reserved.
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
#include <glib/gstdio.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "src/connman.h"
#include "include/iptables_ext.h"

#define PREFIX 	"/iptables"
#define TEST_PATH_PREFIX "/tmp/connman_test"

static const gchar *invalid_paths[] = {
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

static const gchar *test_files[] = {
	"test.file",
	"connman/",
	"connman/test.file",
	NULL
};

static const gchar *iptables_output[] = {
	"# Generated by iptables-save v1.4.15 on Tue Jan  2 12:55:06 2018\n",
	"*filter\n",
	":INPUT ACCEPT [33:3739]\n",
	":FORWARD DROP [0:0]\n",
	":OUTPUT ACCEPT [13423:1770065]\n",
	":testchain - [0:0]\n",
	":testchain2 - [0:0]\n",
	"-A INPUT -s 192.168.10.90/32 -j DROP\n",
	"-A INPUT -s 192.168.10.10/32 -j DROP\n",
	"-A INPUT -p tcp -m state --state RELATED,ESTABLISHED -j ACCEPT\n",
	"-A INPUT -p tcp -m multiport --dports 443,8080 -j ACCEPT\n",
	"-A INPUT -p tcp -m tcp --dport 22 -j LOG --log-prefix SSH\n",
	"-A INPUT -s 192.168.1.22/32 -j DROP\n",
	"-A INPUT -s 192.168.10.0/24 -j ACCEPT\n",
	"-A INPUT -s 192.168.10.23/32 -j ACCEPT\n",
	"-A INPUT -s 192.168.0.2/32 -p tcp -j DROP\n",
	"-A INPUT -s 192.168.0.2/32 -p udp -j ACCEPT\n",
	"-A INPUT -s 192.168.0.2/32 -p udp -m udp --dport 23 -j ACCEPT\n",
	"-A INPUT -s 192.168.0.2/32 -p udp -m udp --dport 4000:4011 -j ACCEPT\n",
	"-A INPUT -s 192.168.0.2/32 -p udp -m udp --dport 23 -j ACCEPT\n",
	"-A OUTPUT -d 8.9.9.9/32 -j DROP\n",
	"-A OUTPUT -d 8.9.9.9/32 -j DROP\n",
	"COMMIT\n",
	"# Completed on Tue Jan  2 12:55:06 2018\n",
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
int iptables_set_file_contents(const gchar *fpath, GString *str,
			gboolean free_str);
GString* iptables_get_file_contents(const gchar* fpath);

gint stdout_capture_start(output_capture_data *data);
void stdout_capture_data(output_capture_data *data);
gint stdout_capture_end(output_capture_data *data);

int iptables_check_table(const char *table_name);

struct iptables_content* iptables_get_content(GString *output,
			const gchar* table_name);


/* Dummies */
struct xtc_handle {
	gint i;
};

struct xt_counters {
	__u64 pcnt, bcnt;
};

struct ipt_entry {
	gint i;
};

int xtables_load_ko(const char *name, bool value)
{
	return 0;
}

gboolean check_table(const char *table_name)
{
	gint i = 0;
	const gchar *tables[] = {
		"filter",
		"mangle",
		"nat",
		"raw",
		"security",
		NULL
		};

	if (!table_name || !*table_name)
		return FALSE;

	for (i = 0 ; tables[i] && *tables[i] ; i++) {
		if(g_ascii_strcasecmp(table_name, tables[i]) == 0)
			return TRUE;
	}
	return FALSE;
}

gboolean check_chain(const char *chain)
{
	gint i = 0;
	const gchar *chains[] = {
		"INPUT",
		"OUTPUT",
		"FORWARD",
		"POSTROUTING",
		"PREROUTING",
		NULL
		};

	if (!chain || !*chain)
		return FALSE;

	for (i = 0 ; chains[i] && *chains[i] ; i++) {
		gchar *connman_c = g_strconcat("connman-", chains[i], NULL);
		if(g_ascii_strcasecmp(chain, chains[i]) == 0 ||
			g_ascii_strcasecmp(chain, connman_c) == 0)
			return TRUE;
		g_free(connman_c);
	}
	return FALSE;
}

gboolean check_policy(const char *policy)
{
	gint i = 0;
	const gchar *policies[] = {
		"ACCEPT",
		"DROP",
		NULL
		};

	if (!policy || !*policy)
		return FALSE;

	for (i = 0 ; policies[i] && *policies[i] ; i++) {
		if(g_ascii_strcasecmp(policy, policies[i]) == 0)
			return TRUE;
	}
	return FALSE;
}


struct xtc_handle* iptc_init(const char *table_name)
{
	if (!check_table(table_name))
		return NULL;

	return g_try_new0(struct xtc_handle,1);
}

const char* iptc_first_chain(struct xtc_handle *handle)
{
	if (!handle)
		return NULL;

	return "INPUT";
}

const char* iptc_next_chain(struct xtc_handle *handle)
{
	return NULL;
}

const struct ipt_entry *iptc_first_rule(const char *chain,
	struct xtc_handle *handle)
{
	return NULL;
}

const struct ipt_entry *iptc_next_rule(const struct ipt_entry *prev,
	struct xtc_handle *handle)
{
	return NULL;
}

int iptc_is_chain(const char *chain, struct xtc_handle *handle)
{
	if (!check_chain(chain) || !handle)
		return 0;

	return 1;
}

int iptc_builtin(const char *chain, struct xtc_handle *handle)
{
	if (!check_chain(chain) || !handle)
		return 0;

	return 1;
}

int iptc_flush_entries(const char* chain, struct xtc_handle *handle)
{
	if (!check_chain(chain) || !handle)
		return 0;

	return 1;
}

int iptc_commit(struct xtc_handle *handle)
{
	return handle ? 1 : 0;
}

void iptc_free(struct xtc_handle *handle)
{
	g_free(handle);
	return;
}

int iptc_set_policy(const char *chain, const char *policy,
	struct xt_counters *counters, struct xtc_handle *handle)
{
	if (!check_chain(chain) || !check_policy(policy) ||
		!counters || !handle)
		return 0;
	return 1;
}

const char *iptc_get_policy(const char *chain,
	struct xt_counters *counters, struct xtc_handle *handle)
{
	if (!check_chain(chain) || !counters || !handle)
		return NULL;
	return "TEST_POLICY";
}

int __connman_iptables_init(void)
{
	return 0;
}

void __connman_iptables_cleanup(void)
{
	return;
}

int __connman_iptables_append(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	if (!check_table(table_name) || !check_chain(chain) ||
		!rule_spec || !*rule_spec)
		return -1;

	return 0;
}

int __connman_iptables_insert(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	if (!check_table(table_name) || !check_chain(chain) ||
		!rule_spec || !*rule_spec)
		return -1;

	return 0;
}

int __connman_iptables_delete(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	if (!check_table(table_name) || !check_chain(chain) ||
		!rule_spec || !*rule_spec)
		return -1;

	return 0;
}

int __connman_iptables_commit(int type, const char *table_name)
{
	if (!check_table(table_name))
		return -1;

	return 0;
}

int __connman_iptables_delete_chain(int type,
				const char *table_name,
				const char *chain)
{
	if (!check_table(table_name) || !check_chain(chain))
		return -1;

	return 0;
}

int __connman_iptables_new_chain(int type,
				const char *table_name,
				const char *chain)
{
	if (!check_table(table_name) || !check_chain(chain))
		return -1;

	return 0;
}

int __connman_iptables_flush_chain(int type,
				const char *table_name,
				const char *chain)
{
	if (!check_table(table_name) || !check_chain(chain))
		return -1;

	return 0;
}

int __connman_iptables_find_chain(int type,
				const char *table_name,
				const char *chain)
{
	if (!check_table(table_name) || !check_chain(chain))
		return -1;

	return 0;
}

int __connman_iptables_iterate_chains(int type,
				const char *table_name,
				connman_iptables_iterate_chains_cb_t cb,
				void *user_data)
{
	if (!check_table(table_name))
		return -1;

	return 0;
}

int __connman_iptables_change_policy(int type,
					const char *table_name,
					const char *chain,
					const char *policy)
{
	if (!check_table(table_name) || !check_chain(chain) ||
		!check_policy(policy))
		return -1;

	return 0;
}

DBusConnection *connman_dbus_get_connection(void)
{
	return NULL;
}


/* End dummies */

static gchar* setup_test_directory()
{
	gchar *test_path = NULL, *temp_path = NULL;

	test_path = g_strdup_printf("%s.XXXXXX", TEST_PATH_PREFIX);

	g_assert(test_path);

	if (!g_file_test(test_path, G_FILE_TEST_EXISTS)) {
		temp_path = g_mkdtemp(test_path);
		if (!temp_path) { // Error
			g_free(test_path);
			test_path = NULL;
			goto out;
		}
	}

	g_assert(g_file_test(test_path, G_FILE_TEST_EXISTS));
	g_assert(g_file_test(test_path, G_FILE_TEST_IS_DIR));

out:
	return test_path;
}

/* Thanks Slava Monich */
static int rmdir_r(const gchar* path)
{
	DIR *d = opendir(path);

	if (d) {
		const struct dirent *p;
		int r = 0;

		while (!r && (p = readdir(d))) {
			char *buf;
			struct stat st;

			if (!strcmp(p->d_name, ".") ||
						!strcmp(p->d_name, "..")) {
				continue;
			}

			buf = g_strdup_printf("%s/%s", path, p->d_name);
			if (!stat(buf, &st)) {
				r =  S_ISDIR(st.st_mode) ? rmdir_r(buf) :
								unlink(buf);
			}
			g_free(buf);
		}
		closedir(d);
		return r ? r : rmdir(path);
	} else {
		return -1;
	}
}

static void cleanup_test_directory(gchar *test_path)
{
	gint access_mode = R_OK|W_OK|X_OK;

	if (g_file_test(test_path, G_FILE_TEST_IS_DIR)) {
		g_assert(!access(test_path, access_mode));
		
		rmdir_r(test_path);
	}

	g_free(test_path);
}

static void test_iptables_file_access_basic()
{
	gchar *test_path = setup_test_directory();
	g_assert(test_path);

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	g_assert(iptables_set_file_contents(NULL, NULL, true));
	g_assert(iptables_set_file_contents(NULL, NULL, false));

	g_assert(iptables_set_file_contents("", NULL, true));

	gchar *path = g_strdup("some/path");
	g_assert(iptables_set_file_contents(path,NULL, true));

	g_assert(!iptables_get_file_contents(NULL));
	g_assert(!iptables_get_file_contents(""));

	GString *str = g_string_new(NULL);
	g_assert(iptables_set_file_contents(path, str, false));

	g_string_printf(str, "content");
	g_assert(iptables_set_file_contents(path, str, false));

	g_free(path);
	g_string_free(str, true);

	__connman_storage_cleanup();

	cleanup_test_directory(test_path);
}

static void test_iptables_file_access_fail()
{	
	gint i = 0, j = 0;
	GString *str = g_string_new("content");
	gchar *test_path = setup_test_directory();
	g_assert(test_path);

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	for (i = 0; invalid_paths[i]; i++) {
		for (j = 0; test_files[j]; j++) {
			gchar *path = g_strdup_printf("%s%s%s", test_path,
				invalid_paths[i], test_files[j]);

			/*
			 * Check that the path cannot be accessed. This check
			 * is done for the system directories and to avoid
			 * littering the filesystem is not attempted to be
			 * written to if check_save_directory() is not
			 * checking properly.
			 */
			g_assert(check_save_directory(path));
			
			g_free(path);
		}
	}

	g_string_free(str,true);

	__connman_storage_cleanup();

	cleanup_test_directory(test_path);
}

static void test_iptables_file_access_fail2()
{
	gint i = 0;
	gchar str[] = "content";
	gchar *test_path = setup_test_directory();
	g_assert(test_path);

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	for (i = 0; invalid_paths[i]; i++) {
		gchar *path = g_strdup_printf("%s%s", test_path,
			invalid_paths[i]);

		if (g_file_test(path, G_FILE_TEST_EXISTS) && 
			g_file_test(path, G_FILE_TEST_IS_DIR))
			continue;

		path[strlen(path) -1 ] = '\0';

		if(g_file_set_contents(path,str,strlen(str),NULL))
			g_assert(check_save_directory(path));

		g_free(path);
	}

	__connman_storage_cleanup();

	cleanup_test_directory(test_path);
}

static void test_iptables_file_access_write_fail()
{
	gint i = 0, j = 0;
	gchar *init_path = NULL;
	gchar *test_path = NULL;

	GString *str = g_string_new("content");

	test_path = setup_test_directory();
	g_assert(test_path);

	init_path = g_strdup_printf("%s%s", test_path, "/var/lib");

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	for (i = 0; invalid_paths[i]; i++) {
		for (j = 0; test_files[j]; j++) {
			gchar *path = g_strdup_printf("%s%s%s",
				test_path, invalid_paths[i], test_files[j]);

			/*
			 * First check that these paths cannot be written to,
			 * the system paths are prefixed, so system
			 * directories are not touched here.
			*/
			g_assert(check_save_directory(path));
			g_assert(iptables_set_file_contents(path, str, false));

			g_free(path);
		}
	}

	g_string_free(str,true);

	__connman_storage_cleanup();

	g_free(init_path);

	cleanup_test_directory(test_path);
}

/* Cannot be run, works only when running as root, TODO figure this out
static void test_iptables_file_access_failure()
{
	gchar content[] = "content";
	GString *str = g_string_new(content);
	gchar *test_path = NULL;
	gchar *path = NULL;

	test_path = setup_test_directory();
	g_assert(test_path);

	path = g_strconcat(test_path, "/connman/iptables-test/test.file", NULL);

	__connman_storage_init(test_path, 0700, 0600); // From main.c

	printf("path %s\n", path);
	g_assert(g_mkdir_with_parents(path,R_OK|W_OK|X_OK) == 0);

	g_assert(!check_save_directory(path));

	g_assert(iptables_set_file_contents(path, str, true));
	g_assert(g_file_test(path,G_FILE_TEST_EXISTS));

	g_free(path);

	__connman_storage_cleanup();

	cleanup_test_directory(test_path);
}
*/

static void test_iptables_file_access_success()
{
	gchar content[] = "content";
	GString *str = g_string_new(content);
	gchar *test_path = NULL;
	gchar *path = NULL;

	// Initialize custom dir for testing
	test_path = setup_test_directory();
	g_assert(test_path);

	path = g_strconcat(test_path, "/connman/iptables-test/test.file",
				NULL);

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	g_assert(!check_save_directory(path));

	g_assert(!iptables_set_file_contents(path, str, true));
	g_assert(g_file_test(path,G_FILE_TEST_EXISTS));

	GString* str_get = iptables_get_file_contents(path);
	g_assert(str_get);

	g_assert(!g_ascii_strcasecmp(str_get->str, content));

	g_free(path);
	g_string_free(str_get, true);

	__connman_storage_cleanup();

	cleanup_test_directory(test_path);
}

int iptables_save(const char* table_name);
int iptables_restore(const char* table_name);

static void test_iptables_save_fail()
{
	char* test_path = setup_test_directory();
	g_assert(test_path);

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	g_assert(iptables_save(NULL));
	g_assert(iptables_save(""));
	g_assert(iptables_save("not-table"));

	g_assert(iptables_save("filter") == 0);

	__connman_storage_cleanup();
	cleanup_test_directory(test_path);
}

static void test_iptables_save_ok()
{
	const char *tables[] = {
		"filter",
		"nat",
		"mangle",
		"raw",
		"security",
		NULL
	};

	gint i = 0;

	char* test_path = setup_test_directory();
	g_assert(test_path);

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	for (i = 0 ; tables[i] ; i++) {
		g_assert(iptables_save(tables[i]) == 0);
		g_assert(iptables_restore(tables[i]) == 0);
	}

	__connman_storage_cleanup();
	cleanup_test_directory(test_path);
}

static void test_iptables_restore_fail()
{
	char* test_path = setup_test_directory();
	g_assert(test_path);

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	g_assert(iptables_restore(NULL));
	g_assert(iptables_restore(""));
	g_assert(iptables_restore("not-table"));

	__connman_storage_cleanup();
	cleanup_test_directory(test_path);
}

static void test_iptables_clear_fail()
{
	char* test_path = setup_test_directory();
	g_assert(test_path);

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	g_assert(connman_iptables_clear(NULL));
	g_assert(connman_iptables_clear(""));
	g_assert(connman_iptables_clear("not-table"));
	g_assert(connman_iptables_clear("mangle"));
	g_assert(connman_iptables_clear("nat"));
	g_assert(connman_iptables_clear("security"));
	g_assert(connman_iptables_clear("raw"));

	g_assert(connman_iptables_clear("filter") == 0);

	__connman_storage_cleanup();
	cleanup_test_directory(test_path);
}

static void test_iptables_stdout_capture()
{
	gchar testprint[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc malesuada eleifend tincidunt. Ut vestibulum luctus consequat. Quisque sodales sapien at justo eleifend malesuada. Nunc eget maximus ipsum. Donec interdum nibh ut felis commodo, vitae elementum ligula blandit. Proin in neque a quam gravida viverra eu tincidunt eros. Donec posuere neque a massa imperdiet hendrerit. Sed tempor ut purus eget porta.\nVestibulum placerat dui at mauris commodo, a vehicula arcu pulvinar. Cras eu rutrum ipsum. Integer ac volutpat velit. Aliquam vulputate interdum libero nec porta. Duis sagittis sapien turpis, vitae rhoncus elit tempor ac. Nulla id quam in lorem euismod sodales at in sapien. Nulla facilisis urna vitae sapien eleifend aliquam. Nam ullamcorper interdum nunc, non consectetur magna placerat at. Curabitur sit amet leo finibus, lacinia leo sed, bibendum ipsum. Phasellus molestie sed orci sit amet elementum. Fusce sit amet lacus laoreet purus dapibus venenatis. Nullam quam ligula, egestas id aliquet sed, sagittis sollicitudin massa. Etiam tristique tortor faucibus, semper ex ac, convallis arcu. Integer aliquet ligula non auctor efficitur. Sed nec suscipit libero.\nEtiam justo lorem, pellentesque et erat molestie, ultrices maximus enim. Cras vitae fringilla elit. Vivamus imperdiet tellus eu felis varius porttitor. Etiam quis mauris nec eros viverra consequat. Suspendisse leo felis, consequat et urna nec, vestibulum tincidunt orci. Sed nec ipsum ut neque pharetra lacinia. Sed in nibh eu arcu hendrerit volutpat a id elit.\n Duis vulputate eros at tortor porttitor, ac rutrum magna vehicula. Proin pretium libero urna, sed egestas quam aliquet eget. Proin et porta leo, ac iaculis erat. Proin elementum ornare ultricies. Mauris vestibulum nisi dui. Nunc ut velit dignissim, gravida ligula eget, vehicula sapien. Nunc nec porta nisi. Nulla congue ex auctor velit porttitor, a pharetra elit consectetur. Etiam vel dapibus velit. Aliquam erat volutpat. Donec a sollicitudin sem. Morbi bibendum metus sed sapien iaculis tincidunt. Proin aliquet nulla et maximus suscipit. Sed et mauris mollis, mollis lacus id, pharetra lorem. Pellentesque lobortis sapien justo, a vulputate leo aliquet id. Suspendisse convallis mollis magna non gravida.\nSed faucibus consequat leo, sed pretium sem sagittis sit amet. Fusce et quam fermentum, feugiat nisl nec, placerat urna. Etiam consequat eget nisi sed molestie. Cras bibendum, tellus nec aliquet auctor, velit dui ultricies nisl, a semper nisl sem eget erat. Etiam tincidunt ut sem a scelerisque. Etiam finibus fringilla dolor, ac malesuada leo lacinia eu. Pellentesque id neque eget ligula tincidunt pretium.";

	gint error = 0;

	output_capture_data data = {
		.stdout_pipes = {-1},
		.stdout_saved = -1,
		.stdout_read_limit = 2000,
		.stdout_bytes_read = 0,
		.stdout_data = NULL
	};

	g_assert(!stdout_capture_start(&data));

	printf("%s", testprint);

	stdout_capture_data(&data);

	/* 
	 * This should not be asserted, output will remain captured if this
	 * fails. Check return value later, try to recover calling dup2 again.
	 */
	if ((error = stdout_capture_end(&data))) {
		perror("stdout_capture_end() failed, trying to recover with "
					" dup2");
		error = dup2(data.stdout_saved,fileno(stdout));
	}

	g_assert(!error);

	g_assert(data.stdout_bytes_read);
	g_assert(data.stdout_bytes_read == (int)strlen(testprint));
	g_assert(data.stdout_pipes[0] == -1);
	g_assert(data.stdout_pipes[1] == -1);
	g_assert(data.stdout_saved == -1);

	g_assert(!g_ascii_strcasecmp(data.stdout_data, testprint));

	g_free(data.stdout_data);
}

static GString* create_iptables_output()
{
	GString *output = g_string_new(NULL);
	gint i = 0;

	for (i = 0; iptables_output[i]; i++)
		g_string_append(output,iptables_output[i]);

	return output;
}

static void test_iptables_get_content()
{
	struct iptables_content *content = NULL;
	GList *iter = NULL;
	gint index = 0;

	__connman_iptables_init();

	g_assert(!connman_iptables_get_content(""));
	g_assert(!connman_iptables_get_content(NULL));

	/*
	 * connman_iptables_get_content() returns null as no connection to
	 * iptables.
	 */
	content = connman_iptables_get_content("filter");
	g_assert(content);

	/* Proper chain */
	g_assert(content->table);
	g_assert(g_ascii_strcasecmp(content->table, "filter") == 0);

	/* One chain */
	g_assert(content->chains);
	g_assert(g_list_length(content->chains) == 1);

	/* No rules */
	g_assert(!content->rules);

	connman_iptables_free_content(content);

	/* Create proper output of iptables manually */
	GString* output = create_iptables_output();
	g_assert(output);
	g_assert(output->len);

	content = iptables_get_content(output, "filter");

	g_string_free(output, true);

	g_assert(content);
	g_assert(!g_ascii_strcasecmp(content->table, "filter"));

	g_assert(content->chains);
	g_assert(g_list_length(content->chains) == 5);

	index = 2;
	for (iter = content->chains; iter ; iter = iter->next, index++) {
		gint compare_len = strlen(iter->data);

		g_assert(!g_ascii_strncasecmp((gchar*)iter->data,
			&(iptables_output[index][1]), compare_len));
	}

	g_assert(content->rules);
	g_assert(g_list_length(content->rules) == 15);

	index = 7;
	for (iter = content->rules; iter ; iter = iter->next, index++) {
		gint compare_len = strlen(iter->data);

		g_assert(!g_ascii_strncasecmp((gchar*)iter->data,
			iptables_output[index], compare_len));
	}

	connman_iptables_free_content(content);
	__connman_iptables_cleanup();
}

static void test_iptables_operation_chain(
	int (*chainfunc)(const char *table_name, const char *chain))
{
	const char *tables[] = {NULL, "", "filter"};
	const char *chains[] = {NULL, "", "connman-INPUT", "INPUT"};

	gint i, j, last_table, last_chain;

	last_table = G_N_ELEMENTS(tables) - 1;
	last_chain = G_N_ELEMENTS(chains) - 1;

	for (i = 0; i < last_table ; i++) {
		for (j = 0; j < last_chain; j++)
			g_assert(chainfunc(tables[i], chains[j]) != 0);
	}

	g_assert(chainfunc(tables[last_table], chains[last_chain]) == 0);
}

static void test_iptables_operation_new_chain()
{
	test_iptables_operation_chain(connman_iptables_new_chain);
}

static void test_iptables_operation_delete_chain()
{
	test_iptables_operation_chain(connman_iptables_delete_chain);
}

static void test_iptables_operation_flush_chain()
{
	test_iptables_operation_chain(connman_iptables_flush_chain);
}

static void test_iptables_operations_find_chain()
{
	test_iptables_operation_chain(connman_iptables_find_chain);
}

static void test_iptables_operation(int (*operation)(const char* table,
			const char* chain, const char* rule))
{
	const char *tables[] = {NULL, "", "filter"};
	const char *chains[] = {NULL, "", "connman-INPUT", "INPUT"};
	const char *rules[] = {NULL, "", 
		"-p tcp -m tcp --dport 443 -j connman-INPUT",
		"-p tcp -m tcp --dport 443 -j ACCEPT"};

	gint i, j, k, last_table, last_chain, last_rule;

	last_table = G_N_ELEMENTS(tables) - 1;
	last_chain = G_N_ELEMENTS(chains) - 1;
	last_rule = G_N_ELEMENTS(rules) - 1;

	/* fail */
	for (i = 0 ; i < last_table ; i++) {
		for (j = 0 ; j < last_chain ; j++) {
			for (k = 0; k < last_rule ; k++)
				g_assert(operation(tables[i], chains[j],
					rules[k]) != 0);
		}
	}

	g_assert(operation(tables[last_table], chains[last_chain],
		rules[last_rule]) == 0);
}

static void test_iptables_operations_insert()
{
	test_iptables_operation(connman_iptables_insert);
}

static void test_iptables_operations_append()
{
	test_iptables_operation(connman_iptables_append);
}

static void test_iptables_operations_delete()
{
	test_iptables_operation(connman_iptables_delete);
}

static void test_iptables_operations_commit()
{
	g_assert(connman_iptables_commit(NULL) != 0);
	g_assert(connman_iptables_commit("") != 0);

	g_assert(connman_iptables_commit("non-table") != 0);

	g_assert(connman_iptables_commit("filter") == 0);

}

static void test_iptables_operations_change_policy()
{
	const char *tables[] = {NULL, "", "filter"};
	const char *chains[] = {NULL, "", "connman-INPUT", "INPUT"};
	const char *policies[] = {NULL, "", "connman-INPUT", "DROP"};

	gint i, j, k, last_table, last_chain, last_policy;

	last_table = G_N_ELEMENTS(tables) - 1;
	last_chain = G_N_ELEMENTS(chains) - 1;
	last_policy = G_N_ELEMENTS(policies) - 1;

	for (i = 0 ; i < last_table ; i++) {
		for (j = 0 ; j < last_chain ; j++) {
			for (k = 0; k < last_policy ; k++)
				g_assert(connman_iptables_change_policy(tables[i], chains[j],
					policies[k]) != 0);
		}
	}

	g_assert(connman_iptables_change_policy(tables[last_table],
		chains[last_chain], policies[last_policy]) == 0);

	__connman_iptables_cleanup();
}

static void test_iptables_default_save_path()
{
	gint i = 0;

	g_assert_cmpint(__connman_storage_init(DEFAULT_STORAGE_ROOT,
						DEFAULT_USER_STORAGE, 0700,
						0600), ==, 0);
	for (i = 0; i < 4 ; i++)
		g_assert(!connman_iptables_default_save_path(i));

	g_assert(connman_iptables_default_save_path(4));
	g_assert(!connman_iptables_default_save_path(6));

	for (i = 7; i < 10 ; i++)
		g_assert(!connman_iptables_default_save_path(i));

	__connman_storage_cleanup();
}

int __connman_iptables_save_all();
int __connman_iptables_restore_all();

static void test_iptables_save_restore_all()
{
	char* test_path = setup_test_directory();

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	g_assert(__connman_iptables_save_all());
	g_assert(__connman_iptables_restore_all());

	__connman_storage_cleanup();

	cleanup_test_directory(test_path);
}

static void test_iptables_restore_rules_1()
{
	const char rules[] = "#Generated by test\n*filter\n"
		":INPUT ACCEPT [0:0]\n"
		":FORWARD ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
		":test-INPUT ACCEPT [0:0]\n"
		":connman-OUTPUT DROP [0:0]\n"
		"-A INPUT -p udp -m udp --dport 80 -m comment --comment \"\" -j DROP\n"
		"-A INPUT -p udp -m udp --dport 80 -m comment --comment a -j DROP\n"
		"-A INPUT -p udp -m udp --dport 80 -m comment --comment \"a\" -j DROP\n"
		"-A INPUT -p udp -m udp --dport 80 -m comment --comment \" \" -j DROP\n"
		"-I INPUT -p tcp -m tcp --dport 22 -m comment --comment \"\" -j DROP\n"
		"-I INPUT -p tcp -m tcp --dport 22 -m comment --comment a -j DROP\n"
		"-I INPUT -p tcp -m tcp --dport 22 -m comment --comment \"a\" -j DROP\n"
		"-I INPUT -p udp -m udp --dport 80 -m comment --comment \" \" -j DROP\n"
		"-D INPUT -p udp -m udp --dport 80 -m comment --comment \"\" -j DROP\n"
		"-D INPUT -p udp -m udp --dport 80 -m comment --comment a -j DROP\n"
		"-D INPUT -p udp -m udp --dport 80 -m comment --comment \"a\" -j DROP\n"
		"-D INPUT -p udp -m udp --dport 80 -m comment --comment \" \" -j DROP\n"
		"-A INPUT -p udp -m comment --comment \"a comment\" -j DROP\n"
		"-A INPUT -p udp -m comment --comment a comment -j DROP\n"
		"COMMIT\n#Completed";

	gchar *test_path = setup_test_directory();
	g_assert(test_path);

	gchar *rule_path = g_strconcat(test_path,
				"/connman/iptables/filter.v4", NULL);

	GString *str = g_string_new(rules);

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	g_assert(iptables_set_file_contents(rule_path, str, true) == 0);

	g_assert(iptables_restore("filter") == 0);

	__connman_storage_cleanup();

	cleanup_test_directory(test_path);
}

static void test_iptables_restore_rules_2()
{
	const char rules[] = "#Generated by test\n*filter\n"
		":INPUT ACCEPT [0:0]\n"
		":FORWARD ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
		"-A INPUT -p udp -m udp --dport 80 -m comment --comment  -j DROP\n"
		"-A INPUT -p udp -m udp --dport 80 -m comment --comment -j DROP\n"
		"-A INPUT -p udp -m udp --dport 80 -m comment -j DROP\n"
		"COMMIT\n#Completed";

	gchar *test_path = setup_test_directory();
	g_assert(test_path);

	gchar *rule_path = g_strconcat(test_path,
				"/connman/iptables/filter.v4", NULL);

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	GString *str = g_string_new(rules);

	g_assert(iptables_set_file_contents(rule_path, str, true) == 0);

	g_assert(iptables_restore("filter") == 0);

	__connman_storage_cleanup();

	cleanup_test_directory(test_path);
}

static void test_iptables_restore_rules_3()
{
	/* Invalid set of rules */
	const char rules[] = "#Generated by test\n*filter\n"
		":INPUT REJECT [0:0]\n"
		":FORWARD MOVE [0:0]\n"
		":OUTPUT OK [0:0]\n"
		"-A connman-INPUT -p tcp -m tcp --dport 23 -j ACCEPT\n"
		"-F INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"
		"COMMIT\n#Completed";

	gchar *test_path = setup_test_directory();
	g_assert(test_path);

	gchar *rule_path = g_strconcat(test_path,
				"/connman/iptables/filter.v4", NULL);

	g_assert_cmpint(__connman_storage_init(test_path, ".local", 0700,
								0600), ==, 0);

	GString *str = g_string_new(rules);

	g_assert(iptables_set_file_contents(rule_path, str, true) == 0);

	g_assert(iptables_restore("filter") == 0);

	__connman_storage_cleanup();

	cleanup_test_directory(test_path);
}

int main(int argc, char **argv)
{
	int rval = 0;

	__connman_log_init(argv[0], g_test_verbose() ? "*" : NULL,
		FALSE, FALSE, "connman", CONNMAN_VERSION);

	g_test_init(&argc, &argv, NULL);

	g_test_add_func(PREFIX "/file_access_basic",
				test_iptables_file_access_basic);
	g_test_add_func(PREFIX "/file_access_fail",
				test_iptables_file_access_fail);
	g_test_add_func(PREFIX "/file_access_fail2",
				test_iptables_file_access_fail2);
	g_test_add_func(PREFIX "/file_access_write_fail",
				test_iptables_file_access_write_fail);
	g_test_add_func(PREFIX "/file_access_success",
				test_iptables_file_access_success);

	/* disabled for now
	 * g_test_add_func(PREFIX "/file_access_failure",
	 * 			test_iptables_file_access_failure);
	*/

	g_test_add_func(PREFIX "/save_fail", test_iptables_save_fail);
	g_test_add_func(PREFIX "/save_ok", test_iptables_save_ok);
	g_test_add_func(PREFIX "/restore_fail", test_iptables_restore_fail);
	g_test_add_func(PREFIX "/clear_fail", test_iptables_clear_fail);

	g_test_add_func(PREFIX "/stdout_capture",
				test_iptables_stdout_capture);

	g_test_add_func(PREFIX "/get_content", test_iptables_get_content);

	g_test_add_func(PREFIX "/new_chain",
				test_iptables_operation_new_chain);

	g_test_add_func(PREFIX "/delete_chain",
				test_iptables_operation_delete_chain);

	g_test_add_func(PREFIX "/flush_chain",
				test_iptables_operation_flush_chain);

	g_test_add_func(PREFIX "/find_chain",
				test_iptables_operations_find_chain);

	g_test_add_func(PREFIX "/insert", test_iptables_operations_insert);

	g_test_add_func(PREFIX "/append", test_iptables_operations_append);

	g_test_add_func(PREFIX "/delete", test_iptables_operations_delete);

	g_test_add_func(PREFIX "/commit", test_iptables_operations_commit);

	g_test_add_func(PREFIX "/policy",
				test_iptables_operations_change_policy);

	g_test_add_func(PREFIX "/save_path", test_iptables_default_save_path);

	g_test_add_func(PREFIX "/save_restore",
				test_iptables_save_restore_all);

	g_test_add_func(PREFIX "rules_1", test_iptables_restore_rules_1);

	g_test_add_func(PREFIX "rules_2", test_iptables_restore_rules_2);

	g_test_add_func(PREFIX "rules_3", test_iptables_restore_rules_3);

	rval =  g_test_run();

	__connman_log_cleanup(FALSE);

	return rval;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
