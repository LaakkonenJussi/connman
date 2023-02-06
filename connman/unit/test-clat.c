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

int connman_inet_add_ipv6_network_route_with_metric(int index, const char *host,
					const char *gateway,
					unsigned char prefix_len, short metric)
{
	g_assert_cmpint(index, >, 0);
	g_assert(host);

	DBG("index %d host %s gateway %s prefix_len %u metric %d", index, host,
						gateway, prefix_len, metric);
	return 0;
}

int connman_inet_add_ipv6_network_route(int index, const char *host,
					const char *gateway,
					unsigned char prefix_len)
{
	return connman_inet_add_ipv6_network_route_with_metric(index, host,
						gateway, prefix_len, 1);
}

int connman_inet_del_ipv6_network_route_with_metric(int index, const char *host,
					unsigned char prefix_len, short metric)
{
	g_assert_cmpint(index, >, 0);
	g_assert(host);

	DBG("index %d host %s prefix_len %u metric %d", index, host,
						prefix_len, metric);
	return 0;
}

int connman_inet_del_ipv6_network_route(int index, const char *host,
						unsigned char prefix_len)
{
	return connman_inet_del_ipv6_network_route_with_metric(index, host,
						prefix_len, 1);
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
	g_assert(host);
	return 0;
}

int connman_inet_add_network_route_with_metric(int index, const char *host,
					const char *gateway,
					const char *netmask, short metric,
					unsigned long mtu)
{
	g_assert_cmpint(index, >, 0);
	g_assert(host);
	return 0;
}

int connman_inet_add_network_route(int index, const char *host,
						const char *gateway,
						const char *netmask)
{
	return connman_inet_add_network_route_with_metric(index, host,
							gateway, netmask, 0, 0);
}

int connman_inet_del_host_route(int index, const char *host)
{
	g_assert_cmpint(index, >, 0);
	g_assert(host);
	return 0;
}

int connman_inet_del_network_route_with_metric(int index, const char *host,
					short metric)
{
	g_assert_cmpint(index, >, 0);
	g_assert(host);
	return 0;
}

int connman_inet_del_network_route(int index, const char *host)
{
	return connman_inet_del_network_route_with_metric(index, host, 0);
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

int connman_inet_ipv6_do_dad(int index, int timeout_ms, struct in6_addr *addr,
				connman_inet_ns_cb_t callback, void *user_data)
{
	g_assert_cmpint(index, >, 0);
	g_assert(addr);
	g_assert(callback);

	return 0;
}

struct connman_task {
	char *path;
	GPtrArray *argv;
	connman_task_exit_t exit_func;
	void *exit_data;
	bool running;
};

static struct connman_task __task = { 0 };
static int __task_exit_value = 0;

struct connman_task *connman_task_create(const char *program,
					connman_task_setup_t custom_task_setup,
					void *setup_data)
{
	g_assert(program);
	g_assert_null(custom_task_setup);
	g_assert_null(setup_data);

	g_assert_true(g_str_has_suffix(program, "tayga"));
	__task.path = g_strdup(program);
	__task.argv = g_ptr_array_new();

	return &__task;
}

int connman_task_add_argument(struct connman_task *task,
					const char *name,
					const char *format, ...)
{
	g_assert(task);
	g_assert(task == &__task);
	g_assert(name);

	va_list ap;
	char *str;

	DBG("task %p arg %s", task, name);

	str = g_strdup(name);
	g_ptr_array_add(task->argv, str);

	va_start(ap, format);

	if (format) {
		str = g_strdup_vprintf(format, ap);
		g_ptr_array_add(task->argv, str);
	}

	va_end(ap);

	return 0;
}

static void free_pointer(gpointer data, gpointer user_data)
{
	g_free(data);
}

#define TASK_STDOUT 1
#define TASK_STDERR 2

int connman_task_run(struct connman_task *task,
			connman_task_exit_t function, void *user_data,
			int *stdin_fd, int *stdout_fd, int *stderr_fd)
{
	DBG("task %p function %p user_data %p", task, function, user_data);

	g_assert(task);
	g_assert(task == &__task);

	g_assert(function);
	__task.exit_func = function;
	__task.exit_data = user_data;
	__task.running = true;

	if (stdout_fd)
		*stdout_fd = TASK_STDOUT;

	if (stderr_fd)
		*stderr_fd = TASK_STDERR;

	DBG("stdin %d stdout %d stderr %d", stdin_fd ? *stdin_fd : -1,
					stdout_fd ? *stdout_fd : -1,
					stderr_fd ? *stderr_fd : -1);

	return 0;
}

int connman_task_stop(struct connman_task *task)
{
	DBG("task %p", task);

	g_assert(task);
	g_assert(task == &__task);

	if (__task.running) {
		__task.running = false;
		__task.exit_func(&__task, __task_exit_value, __task.exit_data);
	}

	return 0;
}

void connman_task_destroy(struct connman_task *task)
{
	DBG("task %p", task);

	g_assert(task);
	g_assert(task == &__task);

	if (__task.running)
		connman_task_stop(task);

	g_free(task->path);
	g_ptr_array_foreach(task->argv, free_pointer, NULL);
	g_ptr_array_free(task->argv, TRUE);

	return;
}

enum task_setup {
	TASK_SETUP_UNKNOWN = 0,
	TASK_SETUP_PRE,
	TASK_SETUP_CONF,
	TASK_SETUP_POST,
};

static enum task_setup get_task_setup()
{
	g_assert(__task.path);

	g_assert_true(g_ptr_array_find_with_equal_func(__task.argv, "--config",
						g_str_equal, NULL));

	if (g_ptr_array_find_with_equal_func(__task.argv, "--mktun",
							g_str_equal, NULL))
		return TASK_SETUP_PRE;

	if (g_ptr_array_find_with_equal_func(__task.argv, "--rmtun",
							g_str_equal, NULL))
		return TASK_SETUP_POST;

	if (g_ptr_array_find_with_equal_func(__task.argv, "--nodetach",
							g_str_equal, NULL))
		return TASK_SETUP_CONF;

	return TASK_SETUP_UNKNOWN;
}

static void call_task_exit(int exit_code)
{
	g_assert(__task.exit_func);
	if (__task.running) {
		__task.running = false;
		__task.exit_func(&__task, exit_code, __task.exit_data);
	}
}

static gboolean check_task_running()
{
	return __task.path && __task.running;
}

struct connman_ipconfig {
	struct connman_ipaddress *ipaddress;
	enum connman_ipconfig_type type;
	enum connman_ipconfig_method method;
};

enum connman_ipconfig_type connman_ipconfig_get_config_type(
					struct connman_ipconfig *ipconfig)
{
	DBG("ipconfig %p", ipconfig);

	g_assert(ipconfig);

	return ipconfig->type;
}

struct connman_ipaddress *connman_ipconfig_get_ipaddress(
					struct connman_ipconfig *ipconfig)
{
	DBG("ipconfig %p", ipconfig);

	g_assert(ipconfig);
	return ipconfig->ipaddress;
}

enum connman_ipconfig_method get_method(struct connman_ipconfig *ipconfig)
{
	DBG("ipconfig %p", ipconfig);

	g_assert(ipconfig);
	return ipconfig->method;
}

static void assign_ipaddress(struct connman_ipconfig *ipconfig)
{
	switch (ipconfig->type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		ipconfig->ipaddress = connman_ipaddress_alloc(AF_INET);
		connman_ipaddress_set_ipv4(ipconfig->ipaddress, "10.10.10.2",
					"255.255.255.0", "10.10.10.1");
		break;
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		ipconfig->ipaddress = connman_ipaddress_alloc(AF_INET6);
		connman_ipaddress_set_ipv6(ipconfig->ipaddress,
					"dead:beef:feed:abba:caba:daba::1234",
					64, NULL);
		break;
	default:
		return;
	}

	g_assert(ipconfig->ipaddress);
}

int connman_nat_enable_double_nat_override(const char *ifname,
						const char *ipaddr_range,
						unsigned char ipaddr_netmask)
{
	DBG("interface %s ipaddr_range %s ipaddr_netmask %u", ifname,
						ipaddr_range, ipaddr_netmask);
	g_assert(ifname);
	return 0;
}

void connman_nat_disable_double_nat_override(const char *ifname)
{
	g_assert(ifname);
}

int connman_nat6_prepare(struct connman_ipconfig *ipconfig,
						const char *ipv6address,
						unsigned char ipv6prefixlen,
						const char *ifname_in,
						bool ndproxy)
{
	g_assert(ipconfig);
	return 0;
}

void connman_nat6_restore(struct connman_ipconfig *ipconfig,
						const char *ipv6address,
						unsigned char ipv6prefixlen)
{
	g_assert(ipconfig);
}

static struct connman_notifier *n;

int connman_notifier_register(struct connman_notifier *notifier)
{
	g_assert(notifier);
	g_assert_null(n);
	n = notifier;
	return 0;
}

void connman_notifier_unregister(struct connman_notifier *notifier)
{
	g_assert(notifier);
	g_assert(notifier == n);
	n = NULL;
}

struct connman_network {
	int index;
	bool connected;
	bool ipv4_configured;
	bool ipv6_configured;
};

int connman_network_get_index(struct connman_network *network)
{
	DBG("network %p", network);

	g_assert(network);
	return network->index;
}

bool connman_network_get_connected(struct connman_network *network)
{
	DBG("network %p", network);

	g_assert(network);
	return network->connected;
}

bool connman_network_is_configured(struct connman_network *network,
					enum connman_ipconfig_type type)
{
	DBG("network %p type %d", network, type);

	g_assert(network);

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		break;
	case CONNMAN_IPCONFIG_TYPE_ALL:
		return network->ipv4_configured && network->ipv6_configured;
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		return network->ipv4_configured;
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		return network->ipv6_configured;
	default:
		break;
	}

	return false;
}

struct connman_service {
	char *identifier;
	char *path;
	enum connman_service_state state;
	enum connman_service_type type;
	char *name;
	struct connman_ipconfig *ipconfig_ipv4;
	struct connman_ipconfig *ipconfig_ipv6;
	struct connman_network *network;
};

static struct connman_service *__def_service = NULL;

struct connman_ipconfig *connman_service_get_ipconfig(
					struct connman_service *service,
					int family)
{
	DBG("service %p family %d", service, family);

	g_assert(service);

	if (family == AF_INET)
		return service->ipconfig_ipv4;

	if (family == AF_INET6)
		return service->ipconfig_ipv6;

	return NULL;
}

enum connman_ipconfig_method connman_service_get_ipconfig_method(
					struct connman_service *service,
					enum connman_ipconfig_type type)
{
	DBG("service %p type %d", service, type);

	g_assert(service);

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		return get_method(service->ipconfig_ipv4);
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		return get_method(service->ipconfig_ipv6);
	case CONNMAN_IPCONFIG_TYPE_ALL:
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		break;
	}

	return CONNMAN_IPCONFIG_TYPE_UNKNOWN;
}

struct connman_service *connman_service_get_default(void)
{
	DBG("default %p", __def_service);

	return __def_service;
}

const char *connman_service_get_identifier(struct connman_service *service)
{
	DBG("service %p", service);

	g_assert(service);
	return service->identifier;
}


enum connman_service_type connman_service_get_type(
					struct connman_service *service)
{
	DBG("service %p", service);

	g_assert(service);
	return service->type;
}

enum connman_service_state connman_service_get_state(
					struct connman_service *service)
{
	DBG("service %p", service);

	g_assert(service);
	return service->state;
}

struct connman_network *connman_service_get_network(
					struct connman_service *service)
{
	DBG("service %p", service);

	g_assert(service);
	return service->network;
}

struct _GResolv {
	int index;
	GResolvResultFunc result_func;
	gpointer result_data;
	char *hostname;
};

static struct _GResolv *__resolv = NULL;

GResolv *g_resolv_new(int index)
{
	DBG("index %d", index);
	g_assert_cmpint(index, >= , 0);

	g_assert_null(__resolv);
	__resolv = g_new0(struct _GResolv, 1);
	g_assert(__resolv);

	__resolv->index = index;

	return __resolv;
}

void g_resolv_unref(GResolv *resolv)
{
	DBG("resolv %p", resolv);

	g_assert(resolv);
	g_assert(resolv == __resolv);

	g_free(__resolv->hostname);
	g_free(__resolv);
	__resolv = NULL;
}

static guint resolv_id = 0;

guint g_resolv_lookup_hostname(GResolv *resolv, const char *hostname,
				GResolvResultFunc func, gpointer user_data)
{
	DBG("resolv %p hostname %s func %p user_data %p", resolv, hostname,
							func, user_data);

	g_assert(resolv);
	g_assert(resolv == __resolv);
	g_assert(hostname);
	g_assert(func);

	g_assert_cmpstr(hostname, ==, "ipv4only.arpa");
	__resolv->hostname = g_strdup(hostname);
	__resolv->result_func = func;
	__resolv->result_data = user_data;

	return ++resolv_id;
}

bool g_resolv_cancel_lookup(GResolv *resolv, guint id)
{
	DBG("resolv %p id %d", resolv, id);
	g_assert(resolv);
	g_assert(resolv == __resolv);

	g_assert_cmpint(id, ==, resolv_id);

	g_free(__resolv->hostname);
	__resolv->hostname = NULL;

	return true;
}

bool g_resolv_set_address_family(GResolv *resolv, int family)
{
	DBG("resolv %p family %d", resolv, family);

	g_assert(resolv);
	g_assert(resolv == __resolv);
	g_assert_cmpint(family, ==, AF_INET6);

	return true;
}

static void call_resolv_result(GResolvResultStatus status)
{
	/* TODO add more and make configurable */
	char **r = g_new0(char*, 4);
	r[0] = g_strdup("64:ff9b::c000:aa");
	r[1] = g_strdup("64:ff9b::c000:ab");
	r[2] = g_strdup("64:ff9b::/96");
	r[3] = g_strdup("dead:beef:0000:feed:abba:cabb:1234:");

	g_assert(__resolv);
	g_assert(__resolv->hostname);
	g_assert(__resolv->result_func);
	g_assert(__resolv->result_data);

	__resolv->result_func(status, r, __resolv->result_data);

	g_strfreev(r);
}

static char *__last_write = NULL;

gboolean g_file_set_contents(const gchar* filename, const gchar* contents,
						gssize length, GError** error)
{
	DBG("filename %s", filename);

	g_assert(filename);
	g_assert(contents);

	g_free(__last_write);
	__last_write = g_strdup(filename);

	/* TODO parse contents */

	return TRUE;
}

static int stdout_fd_ch_ptr = 0x12345678;
static int stderr_fd_ch_ptr = 0x12344321;

static GIOFunc stdout_func = NULL;
static GIOFunc stderr_func = NULL;
static gpointer stdout_data = NULL;
static gpointer stderr_data = NULL;

GIOChannel* g_io_channel_unix_new(int fd)
{
	DBG("fd %d", fd);

	g_assert_cmpint(fd, >, 0);

	if (fd == TASK_STDOUT)
		return (GIOChannel *)&stdout_fd_ch_ptr;

	if (fd == TASK_STDERR)
		return (GIOChannel *)&stderr_fd_ch_ptr;

	return NULL;
}

static unsigned int io_watch_id = 0;

guint g_io_add_watch(GIOChannel* channel, GIOCondition condition, GIOFunc func,
							gpointer user_data)
{
	DBG("channel %p func %p user_data %p", channel, func, user_data);

	g_assert(channel);
	g_assert(func);

	if (channel == (GIOChannel *)&stdout_fd_ch_ptr) {
		stdout_func = func;
		stdout_data = user_data;
	}

	if (channel == (GIOChannel *)&stderr_fd_ch_ptr) {
		stderr_func = func;
		stderr_data = user_data;
	}

	return ++io_watch_id;
}

GIOStatus g_io_channel_shutdown(GIOChannel* channel, gboolean flush,
								GError** error)
{
	DBG("channel %p", channel);

	if (channel == (GIOChannel *)&stdout_fd_ch_ptr ||
				channel == (GIOChannel *)&stderr_fd_ch_ptr)
		return G_IO_STATUS_NORMAL;

	return G_IO_STATUS_ERROR;
}

void g_io_channel_unref(GIOChannel* channel)
{
	DBG("channel %p", channel);

	if (channel == (GIOChannel *)&stdout_fd_ch_ptr) {
		stdout_func = NULL;
		stdout_data = NULL;
	}

	if (channel == (GIOChannel *)&stderr_fd_ch_ptr) {
		stderr_func = NULL;
		stderr_data = NULL;
	}
}

gboolean g_source_remove(guint id)
{
	DBG("id %u", id);
	return true;
}

static struct connman_rtnl *r = NULL;

int connman_rtnl_register(struct connman_rtnl *rtnl)
{
	g_assert(rtnl);
	g_assert_null(r);
	r = rtnl;
	return 0;
}

void connman_rtnl_unregister(struct connman_rtnl *rtnl)
{
	g_assert(rtnl);
	g_assert(rtnl == r);
	r = NULL;
}

static bool rtprot_ra = false;

void connman_rtnl_handle_rtprot_ra(bool value)
{
	rtprot_ra = value;
	return;
}

const char *connman_setting_get_string(const char *key)
{
	return NULL;
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
	struct connman_network network = { 0 };
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	/* There is no default service, nothing will get done */
	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_FAILURE;
					state++) {
		n->service_state_changed(&service, state);
		service.state = state;
		g_assert_null(__task.path);
		g_assert_null(__resolv);
	}

	__connman_builtin_clat.exit();

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
}

/* SErvice goes to ready state and then becomes default */
static void clat_plugin_test2()
{
	struct connman_network network = {
			.index = 1,
	};
	struct connman_ipconfig ipv6config = {
			.type = CONNMAN_IPCONFIG_TYPE_IPV6,
			.method = CONNMAN_IPCONFIG_METHOD_AUTO,
	};
	struct connman_service service = {
			.type = CONNMAN_SERVICE_TYPE_CELLULAR,
			.state = CONNMAN_SERVICE_STATE_UNKNOWN,
	};
	enum connman_service_state state;

	DBG("");

	service.network = &network;
	service.ipconfig_ipv6 = &ipv6config;
	assign_ipaddress(&ipv6config);

	g_assert(__connman_builtin_clat.init() == 0);

	g_assert(n);
	g_assert(r);
	g_assert_true(rtprot_ra);

	for (state = CONNMAN_SERVICE_STATE_UNKNOWN;
					state <= CONNMAN_SERVICE_STATE_READY;
					state++) {
		n->service_state_changed(&service, state);
		service.state = state;
		g_assert_null(__task.path);
		g_assert_null(__resolv);
	}

	__def_service = &service;
	n->default_changed(&service);

	/* Query is made -> call with success */
	g_assert(__resolv);
	g_assert_null(__last_write);
	call_resolv_result(G_RESOLV_RESULT_STATUS_SUCCESS);

	/* This transitions state to pre-configure */
	g_assert_true(check_task_running());
	g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_PRE);
	g_assert(__last_write);
	g_assert_true(g_str_has_suffix(__last_write, "tayga.conf"));
	g_free(__last_write);
	__last_write = NULL;

	/* State transition to running */
	DBG("PRE CONFIGURE stops");
	call_task_exit(0);

	g_assert_true(check_task_running());
	g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_CONF);
	g_assert_null(__last_write);

	/* State transition to post-configure */
	DBG("RUNNING STOPS");
	call_task_exit(0);

	g_assert_true(check_task_running());
	g_assert_cmpint(get_task_setup(), ==, TASK_SETUP_POST);
	g_assert_null(__last_write);

	/* Task is ended */
	DBG("POST CONFIGURE stops");
	call_task_exit(0);

	g_assert_false(check_task_running());
	g_assert_null(__last_write);

	__connman_builtin_clat.exit();

	connman_ipaddress_free(ipv6config.ipaddress);

	g_assert_false(rtprot_ra);
	g_assert_null(n);
	g_assert_null(r);
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
	g_test_add_func(TEST_PREFIX "test2", clat_plugin_test2);

	return g_test_run();
}
