/*
 *  Connection Manager
 *
 *  Copyright (C) 2023 Jolla Ltd. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include <connman/ipconfig.h>
#include <connman/inet.h>
#include <connman/log.h>
#include <connman/network.h>
#include <connman/plugin.h>
#include <connman/service.h>
#include <connman/task.h>
#include <connman/dbus.h>
#include "../include/nat.h"
#include <connman/notifier.h>

#include <gweb/gresolv.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE

enum clat_state {
	CLAT_STATE_IDLE = 0,
	CLAT_STATE_PREFIX_QUERY,
	CLAT_STATE_PRE_CONFIGURE,
	CLAT_STATE_RUNNING,
	CLAT_STATE_POST_CONFIGURE,
	CLAT_STATE_STOPPED,
	CLAT_STATE_FAILURE,
};

struct clat_data {
	struct connman_service *service;
	struct connman_task *task;
	enum clat_state state;
	char *isp_64gateway;
	char *config_path;
	char *clat_prefix;
	char *address;
	unsigned char clat_prefixlen;
	unsigned char addr_prefixlen;

	GResolv *resolv;
	guint resolv_query_id;
	guint remove_resolv_id;
};

struct clat_data *data = NULL;

#define TAYGA_CONF "tayga.conf"
#define IPv4ADDR "192.168.255.1"
#define IPv4MAPADDR "192.0.0.4"
#define CLATSUFFIX "c1a7"

static bool is_running(enum clat_state state)
{
	switch (state) {
	case CLAT_STATE_IDLE:
	case CLAT_STATE_STOPPED:
	case CLAT_STATE_FAILURE:
		return false;
	case CLAT_STATE_PREFIX_QUERY:
	case CLAT_STATE_PRE_CONFIGURE:
	case CLAT_STATE_RUNNING:
	case CLAT_STATE_POST_CONFIGURE:
		return true;
	}

	return false;
}

static int clat_create_tayga_config(const char *prefix, unsigned char prefixlen,
							const char *address)
{
	GError *error = NULL;
	char *str;
	int err;

	g_free(data->config_path);
	data->config_path = g_build_filename(RUNSTATEDIR, TAYGA_CONF, NULL);

	DBG("config %s", data->config_path);

	str = g_strdup_printf("tun device clat\n"
				"ipv4-addr %s\n"
				"prefix %s/%u\n"
				"map %s %s%s",
				IPv4ADDR, prefix, prefixlen, IPv4MAPADDR,
				address, CLATSUFFIX);

	DBG("content: %s", str);

	g_file_set_contents(data->config_path, str, -1, &error);
	if (error) {
		connman_error("Error creating conf: %s\n", error->message);
		g_error_free(error);
		err = -EIO;
	}

	g_free(str);

	return err;
}

/*
5) set up routing and start TAYGA

$ tayga --mktun
$ ip link set dev clat up
$ ip route add 2a00:e18:8000:6cd::c1a7 dev clat
$ ip address add 192.0.0.4 dev clat
$ ip -4 route add default dev clat
$ tayga
*/

static int clat_run_task(struct clat_data *d);

static DBusMessage *clat_task_notify(struct connman_task *task,
					DBusMessage *msg, void *user_data)
{
	DBG("task %p notified", task);

	return NULL;
}

static gboolean remove_resolv(gpointer user_data)
{
	struct clat_data *d = user_data;

	if (d->remove_resolv_id)
		g_source_remove(d->remove_resolv_id);

	if (d->resolv && d->resolv_query_id)
		g_resolv_cancel_lookup(d->resolv, d->resolv_query_id);

	d->resolv_query_id = 0;
	d->remove_resolv_id = 0;

	g_resolv_unref(d->resolv);
	d->resolv = NULL;

	return G_SOURCE_REMOVE;
}

static void prefix_query_cb(GResolvResultStatus status,
					char **results, gpointer user_data)
{
	struct clat_data *d = user_data;

	DBG("status %d", status);

	if (status == G_RESOLV_RESULT_STATUS_SUCCESS && results &&
						g_strv_length(results) > 0) {

		// TODO what to get as the result?
		d->clat_prefix = "2001:67c:2b0:db32:0:1::";
		d->clat_prefixlen = 96;
	}

	/*
	 * We cannot unref the resolver here as resolv struct is manipulated
	 * by gresolv.c after we return from this callback.
	 */
	data->remove_resolv_id = g_timeout_add(0, remove_resolv, data);
	data->resolv_query_id = 0;

	clat_run_task(d);
}

static int clat_task_do_prefix_query(struct clat_data *d)
{
	DBG("");

	if (connman_inet_check_ipaddress(data->isp_64gateway) > 0)
		return -EINVAL;

	if (d->resolv_query_id > 0)
		g_source_remove(d->resolv_query_id);

	data->resolv = g_resolv_new(0);
	if (!data->resolv) {
		connman_error("CLAT cannot create resolv, stopping");
		return -ENOMEM;
	}

	DBG("Trying to resolv %s", data->isp_64gateway);

	g_resolv_set_address_family(d->resolv, AF_INET6);
	data->resolv_query_id = g_resolv_lookup_hostname(d->resolv,
					d->isp_64gateway, prefix_query_cb, d);

	return 0;
}

static int clat_task_pre_configure(struct clat_data *d)
{
	struct connman_ipconfig *ipconfig;
	struct connman_ipaddress *ipaddress;
	const char *address;
	unsigned char prefixlen;

	ipconfig = connman_service_get_ipconfig(d->service, AF_INET6);
	if (!ipconfig)
		return -ENOENT;

	ipaddress = connman_ipconfig_get_ipaddress(ipconfig);
	if (!ipaddress)
		return -ENOENT;

	connman_ipaddress_get_ip(ipaddress, &address, &prefixlen);
	
	// TODO pick random access from the range
	d->address = g_strdup("2a00:e18:8000:6cd::c1a7");

	connman_nat6_prepare(ipconfig);
	clat_create_tayga_config(d->clat_prefix, d->clat_prefixlen, d->address);

	d->task = connman_task_create("tayga", NULL, d);
	if (!d->task)
		return -ENOMEM;

	connman_task_add_argument(d->task, "--mktun", NULL);
	if (connman_task_set_notify(d->task, "tayga", clat_task_notify, d))
		return -ENOMEM;

	return 0;
}

static int clat_task_start_tayga(struct clat_data *d)
{
	struct connman_ipaddress *ipaddress;

	int index;
	//$ ip link set dev clat up
	// TODO wait for rtnl notify?
	index = connman_inet_ifindex("clat");
	if (index < 0) {
		connman_warn("CLAT tayga not up yet?");
		return -ENODEV;
	}

	connman_inet_ifup(index);

	//$ ip route add 2a00:e18:8000:6cd::c1a7 dev clat
	// TODO default route or...?
	connman_inet_add_ipv6_network_route(index, d->address, NULL,
							d->addr_prefixlen);
	//$ ip address add 192.0.0.4 dev clat
	ipaddress = connman_ipaddress_alloc(AF_INET);
	connman_ipaddress_set_ipv4(ipaddress, IPv4MAPADDR, NULL, NULL);
	connman_inet_set_address(index, ipaddress);

	//$ ip -4 route add default dev clat
	connman_inet_add_host_route(index, IPv4MAPADDR, NULL);
	connman_ipaddress_free(ipaddress);

	d->task = connman_task_create("tayga", NULL, d);
	if (!d->task)
		return -ENOMEM;

	connman_task_add_argument(d->task, "--config", d->config_path);
	connman_task_add_argument(d->task, "--nodetach", NULL);

	if (connman_task_set_notify(d->task, "tayga", clat_task_notify, d))
		return -EIO;

	return 0;
}

static int clat_task_post_configure(struct clat_data *d)
{
	struct connman_ipaddress *ipaddress;

	int index;
	//$ ip link set dev clat up
	// TODO wait for rtnl notify?
	index = connman_inet_ifindex("clat");
	if (index < 0) {
		connman_warn("CLAT tayga not up, nothing to do");
	}

	// TODO check return values
	ipaddress = connman_ipaddress_alloc(AF_INET);
	connman_inet_del_host_route(index, IPv4MAPADDR);
	connman_ipaddress_set_ipv4(ipaddress, IPv4MAPADDR, NULL, NULL);
	connman_inet_clear_address(index, ipaddress);
	connman_inet_del_ipv6_network_route(index, d->address,
							d->addr_prefixlen);
	connman_inet_ifdown(index);
	connman_ipaddress_free(ipaddress);

	d->task = connman_task_create("tayga", NULL, d);
	if (!d->task)
		return -ENOMEM;

	connman_task_add_argument(d->task, "--rmtun", NULL);

	if (connman_task_set_notify(d->task, "tayga", clat_task_notify, d))
		return -ENOMEM;

	return 0;
}

static void clat_task_exit(struct connman_task *task, int exit_code,
								void *user_data)
{
	struct clat_data *d = user_data;

	DBG("state %d", d->state);

	if (exit_code) {
		connman_warn("CLAT task failed with code %d", exit_code);
		d->state = CLAT_STATE_FAILURE;
	}

	if (d->task) {
		connman_task_destroy(d->task);
		d->task = NULL;
	}

	switch (d->state) {
	case CLAT_STATE_IDLE:
	case CLAT_STATE_STOPPED:
	case CLAT_STATE_FAILURE:
		connman_error("CLAT task exited");
		// TODO
		return;
	case CLAT_STATE_PREFIX_QUERY:
	case CLAT_STATE_PRE_CONFIGURE:
	case CLAT_STATE_RUNNING:
		DBG("run next state %d", d->state + 1);
		clat_run_task(d);
		return;
	case CLAT_STATE_POST_CONFIGURE:
		DBG("CLAT process ended");
		d->state = CLAT_STATE_STOPPED;
		break;
	}
}

static int clat_run_task(struct clat_data *d)
{
	int err = 0;

	DBG("state %d", d->state);

	switch (d->state) {
	case CLAT_STATE_IDLE:
	case CLAT_STATE_FAILURE:
		d->state = CLAT_STATE_PREFIX_QUERY;
		/* Get the prefix from the ISP NAT service */
		err = clat_task_do_prefix_query(d);
		if (err) {
			connman_error("CLAT failed to start prefix query");
			break;
		}

		return 0;

	case CLAT_STATE_PREFIX_QUERY:
		err = clat_task_pre_configure(d);
		if (err) {
			connman_error("CLAT failed create pre-configure task");
			break;
		}

		d->state = CLAT_STATE_PRE_CONFIGURE;
		break;
	case CLAT_STATE_PRE_CONFIGURE:
		err = clat_task_start_tayga(d);
		if (err) {
			connman_error("CLAT failed to create run task");
			break;
		}

		d->state = CLAT_STATE_RUNNING;
		break;
	/* If either running or stopped state and run is called do cleanup */
	case CLAT_STATE_RUNNING:
	case CLAT_STATE_STOPPED:
		err = clat_task_post_configure(d);
		if (err) {
			connman_error("CLAT failed to create post-configure task");
			break;
		}

		d->state = CLAT_STATE_POST_CONFIGURE;
		break;
	case CLAT_STATE_POST_CONFIGURE:
		connman_warn("CLAT run task called in post-configure state");
		d->state = CLAT_STATE_STOPPED;
		return 0;
	}

	if (!err) {
		DBG("CLAT run task");
		err = connman_task_run(d->task, clat_task_exit, d, NULL, NULL,
								NULL);
	}

	if (err) {
		connman_error("CLAT task failed to run, error %d/%s",
							err, strerror(-err));
		d->state = CLAT_STATE_FAILURE;
		connman_task_destroy(d->task);
		d->task = NULL;
	}

	return err;
}

static int clat_start(struct clat_data *d)
{
	DBG("");

	if (!d)
		return -EINVAL;

	if (is_running(d->state))
		return -EALREADY;

	d->state = CLAT_STATE_IDLE;
	clat_run_task(d);

	return 0;
}

static int clat_stop(struct clat_data *d)
{
	int err;

	DBG("");

	if (!d)
		return -EINVAL;

	if (!d->task)
		return 0;

	struct connman_ipconfig *ipconfig;

	err = connman_task_stop(d->task);
	if (err) {
		connman_error("CLAT failed to stop current task");
		return err;
	}

	connman_task_destroy(d->task);

	ipconfig = connman_service_get_ipconfig(d->service, AF_INET6);
	if (ipconfig)
		connman_nat6_restore(ipconfig);

	/* Run as stopped -> does cleanup */
	d->state = CLAT_STATE_STOPPED;
	err = clat_run_task(d);
	if (err) {
		connman_error("CLAT failed to start cleanup task");
		d->state = CLAT_STATE_FAILURE;
	}

	d->state = CLAT_STATE_IDLE;

	return err;
}

static void clat_ipconfig_changed(struct connman_service *service,
					struct connman_ipconfig *ipconfig)
{
	struct connman_network *network;

	DBG("service %p ipconfig %p", service, ipconfig);

	if (service != data->service || connman_service_get_type(service) !=
						CONNMAN_SERVICE_TYPE_CELLULAR) {
		DBG("Not tracking service %p/%s or not cellular", service,
				connman_service_get_identifier(service));
	}

	if (connman_ipconfig_get_config_type(ipconfig) ==
						CONNMAN_IPCONFIG_TYPE_IPV4) {
		DBG("cellular %p has IPv4 config, stop clat", service);
		clat_stop(data);
		return;
	}

	if (service != connman_service_get_default()) {
		DBG("cellular service %p is not default, stop clat", service);
		clat_stop(data);
		return;
	}

	network = connman_service_get_network(service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected", network);
		clat_stop(data);
		return;
	}

	clat_start(data);
}

static void clat_default_changed(struct connman_service *service)
{
	struct connman_network *network;

	DBG("service %p", service);

	if (!service)
		return;

	if (data->service && data->service != service) {
		DBG("Tracked cellular service %p is not default, stop clat",
							data->service);
		clat_stop(data);
		return;
	}

	network = connman_service_get_network(service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected, stop clat", network);
		clat_stop(data);
		return;
	}

	if (connman_network_is_configured(network,
						CONNMAN_IPCONFIG_TYPE_IPV4)) {
		DBG("IPv4 is configured on cellular network %p, stop clat",
							network);
		clat_stop(data);
		return;
	}
}

static void clat_service_state_changed(struct connman_service *service,
					enum connman_service_state state)
{
	struct connman_network *network;
	int index;

	DBG("");

	if (!service || connman_service_get_type(service) !=
						CONNMAN_SERVICE_TYPE_CELLULAR)
		return;

	switch (state) {
	/* Not connected */
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		/* Stop clat if the service goes offline */
		if (service == data->service) {
			clat_stop(data);
			data->service = NULL;
		}
		return;
	/* Connecting or connected */
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	}

	data->service = service;

	network = connman_service_get_network(service);
	if (!network) {
		DBG("No network yet, not starting clat");
		return;
	}

	index = connman_network_get_index(network);
	if (index < 0) {
		DBG("Interface not up, not starting clat");
		return;
	}

	clat_start(data);
}

static struct connman_notifier clat_notifier = {
	.name			= "clat",
	.ipconfig_changed	= clat_ipconfig_changed,
	.default_changed	= clat_default_changed,
	.service_state_changed	= clat_service_state_changed,
};

static void clat_free_data(struct clat_data *d)
{
	if (!d)
		return;

	if (d->task)
		connman_task_stop(d->task);

	g_free(d->config_path);
	g_free(d->clat_prefix);
	g_free(d->address);

	g_free(d);
}

static struct clat_data *clat_init_data()
{
	struct clat_data *d;
	
	d = g_new0(struct clat_data, 1);

	return d;
}

static int clat_init(void)
{
	int err;

	DBG("");

	data = clat_init_data();
	if (!data) {
		connman_error("Clat: cannot initialize data");
		return -ENOMEM;
	}

	err = connman_notifier_register(&clat_notifier);
	if (err) {
		connman_error("Clat: notifier register failed");
		return err;
	}

	return 0;
}

static void clat_exit(void)
{
	DBG("");

	connman_notifier_unregister(&clat_notifier);
	clat_free_data(data);
}

CONNMAN_PLUGIN_DEFINE(clat, "CLAT plugin", VERSION,
			CONNMAN_PLUGIN_PRIORITY_DEFAULT, clat_init, clat_exit)

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
