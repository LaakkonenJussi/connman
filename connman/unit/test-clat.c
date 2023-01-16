/*
 *  ConnMan blacklist monitor plugin unit tests
 *
 *  Copyright (C) 2022 Jolla Ltd. All rights reserved..
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <gdbus.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "plugin.h"

#include "src/connman.h"
#include <gweb/gresolv.h>

extern struct connman_plugin_desc __connman_builtin_clat;

/* Dummies */

int connman_inet_ifup(int index)
{
	g_assert_cmpint(index, >, 0);
	return 0;
}

int connman_inet_ifdown(int index)
{
	g_assert_cmpint(index, >, 0);
	return 0;
}

int connman_inet_ifindex(const char *name)
{
	g_assert(name);
	return 1;
}

char *connman_inet_ifname(int index)
{
	g_assert_cmpint(index, >, 0);
	return NULL;
}

int connman_inet_add_ipv6_network_route(int index, const char *host,
					const char *gateway,
					unsigned char prefix_len)
{
	g_assert_cmpint(index, >, 0);
	g_assert(host);
	g_assert(gateway);
	return 0;
}

int connman_inet_del_ipv6_network_route(int index, const char *host,
						unsigned char prefix_len)
{
	g_assert_cmpint(index, >, 0);
	g_assert(host);
	return 0;
}

int connman_inet_set_address(int index, struct connman_ipaddress *ipaddress)
{
	g_assert_cmpint(index, >, 0);
	g_assert(ipaddress);
	return 0;
}

int connman_inet_add_host_route(int index, const char *host,
						const char *gateway)
{
	g_assert_cmpint(index, >, 0);
	return 0;
}

int connman_inet_del_host_route(int index, const char *host)
{
	g_assert_cmpint(index, >, 0);
	g_assert(host);
	return 0;
}

int connman_inet_clear_address(int index, struct connman_ipaddress *ipaddress)
{
	g_assert_cmpint(index, >, 0);
	g_assert(ipaddress);
	return 0;
}

int connman_inet_check_ipaddress(const char *host)
{
	g_assert(host);
	return 0;
}

struct connman_task {
	char *path;
	pid_t pid;
	guint child_watch;
	GPtrArray *argv;
	GPtrArray *envp;
	connman_task_exit_t exit_func;
	connman_task_setup_t setup_func;
	void *exit_data;
	GHashTable *notify;
	void *setup_data;
};

struct connman_task __task = { 0 };

struct connman_task *connman_task_create(const char *program,
					connman_task_setup_t custom_task_setup,
					void *setup_data)
{
	g_assert(program);
	return &__task;
}
int connman_task_add_argument(struct connman_task *task,
					const char *name,
					const char *format, ...)
{
	g_assert(task);
	g_assert(name);
	return 0;
}
int connman_task_set_notify(struct connman_task *task, const char *member,
					connman_task_notify_t function,
					void *user_data)
{
	g_assert(task);
	g_assert(member);
	g_assert(function);
	return 0;
}
void connman_task_destroy(struct connman_task *task)
{
	g_assert(task);
	return;
}

int connman_task_run(struct connman_task *task,
			connman_task_exit_t function, void *user_data,
			int *stdin_fd, int *stdout_fd, int *stderr_fd)
{
	g_assert(task);
	g_assert(function);
	return 0;
}

int connman_task_stop(struct connman_task *task)
{
	g_assert(task);
	return 0;
}

enum connman_ipconfig_type connman_ipconfig_get_config_type(
					struct connman_ipconfig *ipconfig)
{
	g_assert(ipconfig);

	return CONNMAN_IPCONFIG_TYPE_IPV4;
}

struct connman_ipaddress *connman_ipconfig_get_ipaddress(
					struct connman_ipconfig *ipconfig)
{
	g_assert(ipconfig);
	return NULL;
}

int connman_nat6_prepare(struct connman_ipconfig *ipconfig)
{
	g_assert(ipconfig);
	return 0;
}

void connman_nat6_restore(struct connman_ipconfig *ipconfig)
{
	g_assert(ipconfig);
}


int connman_notifier_register(struct connman_notifier *notifier)
{
	g_assert(notifier);
	return 0;
}

void connman_notifier_unregister(struct connman_notifier *notifier)
{
	g_assert(notifier);
}

struct connman_ipconfig *connman_service_get_ipconfig(
					struct connman_service *service,
					int family)
{
	g_assert(service);
	return NULL;
}

enum connman_ipconfig_method connman_service_get_ipconfig_method(
					struct connman_service *service,
					enum connman_ipconfig_type type)
{
	g_assert(service);
	return CONNMAN_IPCONFIG_TYPE_UNKNOWN;
}


struct connman_service *connman_service_get_default(void)
{
	return NULL;
}

const char *connman_service_get_identifier(struct connman_service *service)
{
	g_assert(service);
	return NULL;
}


enum connman_service_type connman_service_get_type(
					struct connman_service *service)
{
	g_assert(service);
	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

struct connman_network *connman_service_get_network(
					struct connman_service *service)
{
	g_assert(service);
	return NULL;
}


int connman_network_get_index(struct connman_network *network)
{
	g_assert(network);
	return 0;
}

bool connman_network_get_connected(struct connman_network *network)
{
	g_assert(network);
	return false;
}

bool connman_network_is_configured(struct connman_network *network,
					enum connman_ipconfig_type type)
{
	g_assert(network);
	return false;
}

GResolv *g_resolv_new(int index)
{
	g_assert_cmpint(index, >, 0);
	return NULL;
}

void g_resolv_unref(GResolv *resolv)
{
	g_assert(resolv);
}

guint g_resolv_lookup_hostname(GResolv *resolv, const char *hostname,
				GResolvResultFunc func, gpointer user_data)
{
	g_assert(resolv);
	g_assert(hostname);
	g_assert(func);
	return 0;
}

bool g_resolv_cancel_lookup(GResolv *resolv, guint id)
{
	g_assert(resolv);
	g_assert_cmpint(id, >, 0);
	return true;
}

bool g_resolv_set_address_family(GResolv *resolv, int family)
{
	g_assert(resolv);
	return true;
}

int connman_rtnl_register(struct connman_rtnl *r)
{
	g_assert(r);
	return 0;
}

void connman_rtnl_unregister(struct connman_rtnl *r)
{
	g_assert(r);
}

void connman_rtnl_handle_rtprot_ra(bool value)
{
	return;
}

static gchar *option_debug = NULL;

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
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ NULL },
};

#define TEST_PREFIX "/clat/"

static void clat_plugin_test1()
{
	g_assert(true);
}


int main (int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;

	g_test_init(&argc, &argv, NULL);

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		return 1;
	}

	g_option_context_free(context);

	__connman_log_init(argv[0], option_debug, false, false,
			"Unit Tests Connection Manager", VERSION);

	g_test_add_func(TEST_PREFIX "test1", clat_plugin_test1);

	return g_test_run();
}
