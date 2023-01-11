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
#include <connman/nat.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE

struct clat_data {
	struct connman_service *service;
	struct connman_task *task;
	char *clat_prefix;
	char *address;
	unsigned char clat_prefixlen;
	unsigned char addr_prefixlen
	guint dns_query_id;
	bool task_running;
};

struct clat_data *data = NULL;

#define TAYGA_CONF "tayga.conf"
#define IPv4ADDR "192.168.255.1"
#define IPv4MAPADDR "192.0.0.4"
#define CLATSUFFIX "c1a7"

static int clat_create_tayga_config(const char *prefix, unsigned char prefixlen,
							const char *address)
{
	GError *error = NULL;
	char *config;
	char *str;
	int err;

	config = g_build_filename(STATEDIR, TAYGA_CONF, NULL);

	DBG("config %s", config);

	str = g_strdup_printf("tun device clat\n",
				"ipv4-addr %s\n",
				"prefix %s/%u\n",
				"map %s %s%s",
				IPv4ADDR, prefix, prefixlen, IPv4MAPADDR,
				address, CLATSUFFIX);

	DBG("content: %s", str);

	g_file_set_contents(config, str, -1, &error);
	if (error) {
		connman_error("Error creating conf: %s\n", error->message);
		g_error_free(error);
		err = -EIO;
	}

	g_free(str);
	g_free(config);

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
static DBusMessage *clat_task_notify1(struct connman_task *task,
					DBusMessage *msg, void *user_data)
{
	struct connman_ipaddress *address;
	struct clat_data *d = user_data;

	int index;
	//$ ip link set dev clat up
	// TODO wait for rtnl notify?
	index = connman_inet_ifindex("clat");
	connman_inet_ifup(index);


	//$ ip route add 2a00:e18:8000:6cd::c1a7 dev clat
	// TODO default route or...?
	connman_inet_add_ipv6_network_route(index, d->address, NULL,
							d->addr_prefixlen);
	//$ ip address add 192.0.0.4 dev clat
	connman_ipaddress_set_ipv4(ipaddress, IPv4MAPADDR)
	connman_inet_set_address(index, address);

	//$ ip -4 route add default dev clat
	connman_inet_add_host_route(index, IPv4MAPADDR, NULL, NULL);

}

static int clat_run_task()
{
	struct connman_ipconfig *ipconfig;
	struct connman_ipaddress *ipaddress;
	struct connman_network *network;
	char *address;
	unsigned char prefix;
	int index;

	network = connman_service_get_network(service);
	if (!network)
		return -ENOENT;

	index = connman_network_get_index(network);
	if (index < 0)
		return -ENOENT;

	ipconfig = connman_service_get_ipconfig(d->service, AF_INET6);
	if (!ipconfig)
		return -ENOENT;

	ipaddress = connman_ipconfig_get_ipaddress(ipconfig);
	if (!ipaddress)
		return -ENOENT;

	connman_ipaddress_get_ip(ipaddress, &address, &prefix);
	
	// TODO pick random access from the range
	d->address = g_strdup("2a00:e18:8000:6cd::c1a7");

	connman_nat6_prepare(ipconfig);
	clat_create_tayga_config(d->prefix, d->clat_prefixlen, d->address);

	d->task = connman_task_create("tayga", NULL, d);
	connman_task_add_argument(d->task, "--mktun", NULL);
	if (connman_task_set_notify(d->task, "tayga", clat_task_notify1, d)) {
		// TODO
	}
}


static void clat_do_prefix_query_cb()
{
	// TODO succesful return -> prefix known
	d->clat_prefix = "2001:67c:2b0:db32:0:1::"
	d->clat_prefixlen = 96;

	clat_run_task();
}

static int clat_do_prefix_query()
{
	// TODO
	return 0;
}

static int clat_start(struct clat_data *d)
{
	DBG("");

	if (!d)
		return -EINVAL;

	if (d->task_running)
		return -EALREADY;

	/* Get the prefix from the ISP NAT service */
	clat_do_prefix_query();

	d->task_running = true;

	return 0;
}

static int clat_stop(struct clat_data *d)
{
	int err;

	DBG("");

	if (!d)
		return -EINVAL;

	if (d->task && d->task_running) {
		struct connman_ipconfig *ipconfig;

		err = connman_task_stop(d->task);
		
		ipconfig = connman_service_get_ipconfig(d->service, AF_INET6);
		if (ipconfig)
			connman_nat6_restore(ipconfig);

		d->task = NULL;
		d->task_running = false;
	}

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
		clat_stop();
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
		clat_stop();
		return;
	}

	network = connman_service_get_network(service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected, stop clat", network);
		clat_stop();
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
		if (service == data->service)
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

	clat_start();
}

static struct connman_notifier clat_notifier = {
	.name			= "clat",
	.ipconfig_changed	= clat_ipconfig_changed,
	.default_changed	= clat_default_changed,
	.service_state_changed	= clat_service_state_changed
};

static int clat_init_data()
{
	data = g_new0(struct clat_data, 1);
	if (!data)
		return -ENOMEM;

	return 0;
}

static void clat_free_data()
{
	if (data->task)
		connman_task_stop(data->task);

	g_free(data);
}

static int clat_init(void)
{
	int err;

	DBG("");

	err = clat_init_data();
	if (err) {
		connman_error("Clat: cannot initialize data");
		return err;
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
	clat_free_data();
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
