/*
 *
 *  ConnMan VPN daemon
 *
 *  Copyright (C) 2012-2013  Intel Corporation. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netdb.h>

#include <gdbus.h>

#include "../src/connman.h"
#include "vpn.h"

#include "connman/vpn-dbus.h"

#define CONFIGMAINFILE CONFIGDIR "/connman-vpn.conf"

static GMainLoop *main_loop = NULL;

static unsigned int __terminated = 0;

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		if (__terminated == 0) {
			DBG("Terminating");
			g_main_loop_quit(main_loop);
		}

		__terminated = 1;
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static void disconnect_callback(DBusConnection *conn, void *user_data)
{
	connman_error("D-Bus disconnect");

	g_main_loop_quit(main_loop);
}

static gchar *option_config = NULL;
static gchar *option_debug = NULL;
static gchar *option_plugin = NULL;
static gchar *option_noplugin = NULL;
static bool option_detach = true;
static bool option_version = false;
static bool option_routes = false;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return true;
}

static GOptionEntry options[] = {
	{ "config", 'c', 0, G_OPTION_ARG_STRING, &option_config,
				"Load the specified configuration file "
				"instead of " CONFIGMAINFILE, "FILE" },
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ "plugin", 'p', 0, G_OPTION_ARG_STRING, &option_plugin,
				"Specify plugins to load", "NAME,..." },
	{ "noplugin", 'P', 0, G_OPTION_ARG_STRING, &option_noplugin,
				"Specify plugins not to load", "NAME,..." },
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't fork daemon to background" },
	{ "routes", 'r', 0, G_OPTION_ARG_NONE, &option_routes,
				"Create/delete VPN routes" },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ NULL },
};

/*
 * This function will be called from generic src/agent.c code so we have
 * to use connman_ prefix instead of vpn_ one.
 */
unsigned int connman_timeout_input_request(void)
{
	return __vpn_settings_get_timeout_inputreq();
}

static int set_user_dir(const char *root)
{
	DBG("");
	int err;

	err = __connman_storage_set_user_root(root, STORAGE_DIR_TYPE_VPN,
				vpn_provider_unload_providers,
				vpn_provider_load_providers,
				NULL, NULL);
	if (err) {
		DBG("cannot change user VPN root to %s error %s", root,
					strerror(-err));
		return err;
	}

	err = __connman_storage_create_dir(USER_VPN_STORAGEDIR,
				__vpn_settings_get_storage_dir_permissions(),
				STORAGE_DIR_TYPE_VPN);
	if (err) {
		DBG("cannot create user VPN storage dir in %s error %s", root,
					strerror(-err));
		__connman_storage_set_user_root(NULL, STORAGE_DIR_TYPE_VPN,
					vpn_provider_unload_providers,
					vpn_provider_load_providers,
					NULL, NULL);
		return err;
	}

	return 0;
}

static DBusMessage *change_user(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *user;
	const char *path;
	int err;

	DBG("conn %p", conn);

	// TODO Add D-Bus access control

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &user,
				DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID))
		return __connman_error_invalid_arguments(msg);

	/*
	 * Empty string or setting user as root causes user dirs to be
	 * removed from use.
	 */
	if (!*user || !g_strcmp0(user, "root")) {
		user = NULL;
		path = NULL;
	}

	err = set_user_dir(path);
	switch (err) {
	case 0:
		break;
	case -EALREADY:
		return __connman_error_already_enabled(msg);
	default:
		return __connman_error_failed(msg, -err);
	}

	__vpn_settings_set_binary_user_override(user);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable storage_methods[] = {
	{ GDBUS_ASYNC_METHOD("ChangeUser", NULL, NULL, change_user) },
	{ },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	DBusConnection *conn;
	DBusError err;
	guint signal;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version) {
		printf("%s\n", VERSION);
		exit(0);
	}

	if (option_detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	__connman_log_init(argv[0], option_debug, option_detach, false,
			"Connection Manager VPN daemon", VERSION);

	if (!option_config)
		__vpn_settings_init(CONFIGMAINFILE);
	else
		__vpn_settings_init(option_config);

	const char* fs_identity = NULL;
	if ((fs_identity = __vpn_settings_get_fs_identity()))
		__connman_set_fsid(fs_identity);

	__connman_inotify_init();
	__connman_storage_init(__vpn_settings_get_storage_root(),
			__vpn_settings_get_storage_dir_permissions(),
			__vpn_settings_get_storage_file_permissions());

	if (__connman_storage_create_dir(VPN_STATEDIR,
				__vpn_settings_get_storage_dir_permissions(),
				STORAGE_DIR_TYPE_STATE))
		perror("Failed to create state directory");

	if (__connman_storage_create_dir(VPN_STORAGEDIR,
				__vpn_settings_get_storage_dir_permissions(),
				STORAGE_DIR_TYPE_VPN))
		perror("Failed to create VPN storage directory");

	umask(__vpn_settings_get_umask());

	main_loop = g_main_loop_new(NULL, FALSE);

	signal = setup_signalfd();

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, VPN_SERVICE, &err);
	if (!conn) {
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with system bus\n");
		exit(1);
	}

	g_dbus_set_disconnect_function(conn, disconnect_callback, NULL, NULL);
	
	if (!g_dbus_register_interface(conn, "/", VPN_SERVICE ".Storage",
				storage_methods, NULL, NULL, NULL, NULL))
		DBG("cannot register storage/user changer method call");

	__connman_dbus_init(conn);
	__connman_agent_init();
	__vpn_provider_init(option_routes);
	__vpn_manager_init();
	__vpn_ipconfig_init();
	__vpn_rtnl_init();
	__connman_task_init();
	__connman_plugin_init(option_plugin, option_noplugin);
	__vpn_config_init();

	__vpn_rtnl_start();

	g_free(option_plugin);
	g_free(option_noplugin);

	g_main_loop_run(main_loop);

	g_source_remove(signal);

	__vpn_config_cleanup();
	__connman_plugin_cleanup();
	__connman_task_cleanup();
	__vpn_rtnl_cleanup();
	__vpn_ipconfig_cleanup();
	__vpn_manager_cleanup();
	__vpn_provider_cleanup();
	__connman_agent_cleanup();
	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	__connman_dbus_cleanup();
	__connman_log_cleanup(false);
	__vpn_settings_cleanup();

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	g_free(option_debug);

	return 0;
}
