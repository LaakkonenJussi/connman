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
#include <connman/rtnl.h>

#include <gweb/gresolv.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE

enum clat_state {
	CLAT_STATE_IDLE = 0,
	CLAT_STATE_PREFIX_QUERY,
	CLAT_STATE_PRE_CONFIGURE,
	CLAT_STATE_RUNNING,
	CLAT_STATE_POST_CONFIGURE,
	CLAT_STATE_STOPPED, // TODO: killed?
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
	int ifindex;

	GResolv *resolv;
	guint resolv_query_id;
	guint remove_resolv_id;

	guint dad_id;
};

#define TAYGA_CONF "tayga.conf"
#define IPv4ADDR "192.168.255.1"
#define IPv4MAPADDR "192.0.0.4"
#define CLATSUFFIX "c1a7"

struct clat_data *__data = NULL;

static struct clat_data *get_data()
{
	return __data;
}

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

static int clat_create_tayga_config(struct clat_data *data)
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
				IPv4ADDR, data->clat_prefix,
				data->clat_prefixlen, IPv4MAPADDR,
				data->address, CLATSUFFIX);

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

static int clat_run_task(struct clat_data *data);

static DBusMessage *clat_task_notify(struct connman_task *task,
					DBusMessage *msg, void *user_data)
{
	DBG("task %p notified", task);

	return NULL;
}

static gboolean remove_resolv(gpointer user_data)
{
	struct clat_data *data = user_data;

	if (data->remove_resolv_id)
		g_source_remove(data->remove_resolv_id);

	if (data->resolv && data->resolv_query_id)
		g_resolv_cancel_lookup(data->resolv, data->resolv_query_id);

	data->resolv_query_id = 0;
	data->remove_resolv_id = 0;

	g_resolv_unref(data->resolv);
	data->resolv = NULL;

	return G_SOURCE_REMOVE;
}

static void prefix_query_cb(GResolvResultStatus status,
					char **results, gpointer user_data)
{
	struct clat_data *data = user_data;

	DBG("status %d", status);

	if (status == G_RESOLV_RESULT_STATUS_SUCCESS && results &&
						g_strv_length(results) > 0) {

		// TODO what to get as the result?
		data->clat_prefix = "2001:67c:2b0:db32:0:1::";
		data->clat_prefixlen = 96;
	}

	/*
	 * We cannot unref the resolver here as resolv struct is manipulated
	 * by gresolv.c after we return from this callback.
	 */
	data->remove_resolv_id = g_timeout_add(0, remove_resolv, data);
	data->resolv_query_id = 0;

	clat_run_task(data);
}

static int clat_task_do_prefix_query(struct clat_data *data)
{
	DBG("");

	if (connman_inet_check_ipaddress(data->isp_64gateway) > 0)
		return -EINVAL;

	if (data->resolv_query_id > 0)
		g_source_remove(data->resolv_query_id);

	data->resolv = g_resolv_new(0);
	if (!data->resolv) {
		connman_error("CLAT cannot create resolv, stopping");
		return -ENOMEM;
	}

	DBG("Trying to resolv %s", data->isp_64gateway);

	g_resolv_set_address_family(data->resolv, AF_INET6);
	data->resolv_query_id = g_resolv_lookup_hostname(data->resolv,
					data->isp_64gateway, prefix_query_cb,
					data);

	return 0;
}

static int clat_task_pre_configure(struct clat_data *data)
{
	struct connman_ipconfig *ipconfig;
	struct connman_ipaddress *ipaddress;
	char** tokens;
	char ipv6prefix[135] = { 0 };
	const char *address;
	unsigned char prefixlen;
	int left;
	int pos;
	int i;
	

	DBG("");

	ipconfig = connman_service_get_ipconfig(data->service, AF_INET6);
	if (!ipconfig) {
		DBG("No IPv6 ipconfig");
		return -ENOENT;
	}

	ipaddress = connman_ipconfig_get_ipaddress(ipconfig);
	if (!ipaddress) {
		DBG("No IPv6 ipaddress in ipconfig %p", ipconfig);
		return -ENOENT;
	}

	connman_ipaddress_get_ip(ipaddress, &address, &prefixlen);
	DBG("IPv6 %s", address);

	tokens = g_strsplit(address, ":", 8);
	if (!tokens) {
		connman_error("CLAT: failed to tokenize IPv6 address");
		return -ENOMEM;
	}

	left = 8 - (128 - (int)prefixlen) / 16;
	pos = 0;

	for (i = 0; tokens[i] && i < left; i++) {
		strncpy(ipv6prefix, tokens[i], 4);
		pos += strlen(tokens[i]) + 1; // + ':'

		if (i + 1 < left)
			ipv6prefix[pos-1] = ':';
	}

	g_strfreev(tokens);

	DBG("Address IPv6 prefix %s/%d", ipv6prefix, prefixlen);

	data->address = g_strconcat(ipv6prefix,"::c1a7", NULL);

	connman_nat6_prepare(ipconfig);
	clat_create_tayga_config(data);

	data->task = connman_task_create("tayga", NULL, data);
	if (!data->task)
		return -ENOMEM;

	connman_task_add_argument(data->task, "--mktun", NULL);
	if (connman_task_set_notify(data->task, "tayga", clat_task_notify,
									data))
		return -ENOMEM;

	return 0;
}

static int clat_task_start_tayga(struct clat_data *data)
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
	connman_inet_add_ipv6_network_route(index, data->address, NULL,
							data->addr_prefixlen);
	//$ ip address add 192.0.0.4 dev clat
	ipaddress = connman_ipaddress_alloc(AF_INET);
	connman_ipaddress_set_ipv4(ipaddress, IPv4MAPADDR, NULL, NULL);
	connman_inet_set_address(index, ipaddress);

	//$ ip -4 route add default dev clat
	connman_inet_add_host_route(index, IPv4MAPADDR, NULL);
	connman_ipaddress_free(ipaddress);

	data->task = connman_task_create("tayga", NULL, data);
	if (!data->task)
		return -ENOMEM;

	connman_task_add_argument(data->task, "--config", data->config_path);
	connman_task_add_argument(data->task, "--nodetach", NULL);

	if (connman_task_set_notify(data->task, "tayga", clat_task_notify,
									data))
		return -EIO;

	return 0;
}

struct nd_neighbor_advert *hdr;

void clat_dad_cb(struct nd_neighbor_advert *reply, unsigned int length,
					struct in6_addr *addr,
					void *user_data)
{
	// This reply can be ignored
	DBG("got reply %p", reply);
	return;
}

static gboolean clat_task_run_dad(gpointer user_data)
{
	//struct clat_data *data = user_data;
	//struct in6_addr *addr = NULL;
	int err = 0;

	// TODO get in6_addr of current ifconfig
	// TODO allow use of ipv6_do_dad

	/*err =  __connman_inet_ipv6_do_dad(data->ifindex, 100, addr,
							clat_dad_cb, data);*/
	if (err) {
		connman_error("CLAT failed to send dad: %d", err);
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static int clat_task_start_dad(struct clat_data *data)
{
	DBG("");

	data->dad_id = g_timeout_add(100, clat_task_run_dad, data);

	if (data->dad_id <= 0) {
		connman_error("CLAT failed to start DAD timeout");
		return -EINVAL;
	}

	return 0;
}

static int clat_task_stop_dad(struct clat_data *data)
{
	DBG("");

	if (data->dad_id)
		g_source_remove(data->dad_id);

	data->dad_id = 0;

	return 0;
}

static int clat_task_post_configure(struct clat_data *data)
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
	connman_inet_del_ipv6_network_route(index, data->address,
							data->addr_prefixlen);
	connman_inet_ifdown(index);
	connman_ipaddress_free(ipaddress);

	data->task = connman_task_create("tayga", NULL, data);
	if (!data->task)
		return -ENOMEM;

	connman_task_add_argument(data->task, "--rmtun", NULL);

	if (connman_task_set_notify(data->task, "tayga", clat_task_notify,
									data))
		return -ENOMEM;

	return 0;
}

static void clat_task_exit(struct connman_task *task, int exit_code,
								void *user_data)
{
	struct clat_data *data = user_data;

	DBG("state %d", data->state);

	if (exit_code) {
		connman_warn("CLAT task failed with code %d", exit_code);
		data->state = CLAT_STATE_FAILURE;
	}

	if (data->task) {
		connman_task_destroy(data->task);
		data->task = NULL;
	}

	switch (data->state) {
	case CLAT_STATE_IDLE:
	case CLAT_STATE_STOPPED:
	case CLAT_STATE_FAILURE:
		connman_error("CLAT task exited");
		// TODO
		return;
	case CLAT_STATE_PREFIX_QUERY:
	case CLAT_STATE_PRE_CONFIGURE:
	case CLAT_STATE_RUNNING:
		DBG("run next state %d", data->state + 1);
		clat_run_task(data);
		return;
	case CLAT_STATE_POST_CONFIGURE:
		DBG("CLAT process ended");
		data->state = CLAT_STATE_STOPPED;
		break;
	}
}

static int clat_run_task(struct clat_data *data)
{
	int err = 0;

	DBG("state %d", data->state);

	switch (data->state) {
	case CLAT_STATE_IDLE:
	case CLAT_STATE_FAILURE:
		data->state = CLAT_STATE_PREFIX_QUERY;
		/* Get the prefix from the ISP NAT service */
		err = clat_task_do_prefix_query(data);
		if (err) {
			connman_error("CLAT failed to start prefix query");
			break;
		}

		return 0;

	case CLAT_STATE_PREFIX_QUERY:
		err = clat_task_pre_configure(data);
		if (err) {
			connman_error("CLAT failed create pre-configure task");
			break;
		}

		data->state = CLAT_STATE_PRE_CONFIGURE;
		break;
	case CLAT_STATE_PRE_CONFIGURE:
		err = clat_task_start_tayga(data);
		if (err) {
			connman_error("CLAT failed to create run task");
			break;
		}

		data->state = CLAT_STATE_RUNNING;
		err = clat_task_start_dad(data);
		if (err)
			connman_warn("CLAT failed to start periodid DAD");

		break;
	/* If either running or stopped state and run is called do cleanup */
	case CLAT_STATE_RUNNING:
	case CLAT_STATE_STOPPED:
		err = clat_task_post_configure(data);
		if (err) {
			connman_error("CLAT failed to create post-configure task");
			break;
		}

		data->state = CLAT_STATE_POST_CONFIGURE;
		clat_task_stop_dad(data);
		break;
	case CLAT_STATE_POST_CONFIGURE:
		connman_warn("CLAT run task called in post-configure state");
		data->state = CLAT_STATE_STOPPED;
		return 0;
	}

	if (!err) {
		DBG("CLAT run task");
		err = connman_task_run(data->task, clat_task_exit, data, NULL,
								NULL, NULL);
	}

	if (err) {
		connman_error("CLAT task failed to run, error %d/%s",
							err, strerror(-err));
		data->state = CLAT_STATE_FAILURE;
		connman_task_destroy(data->task);
		data->task = NULL;
	}

	return err;
}

static int clat_start(struct clat_data *data)
{
	DBG("");

	if (!data)
		return -EINVAL;

	if (is_running(data->state))
		return -EALREADY;

	data->state = CLAT_STATE_IDLE;
	clat_run_task(data);

	return 0;
}

static int clat_stop(struct clat_data *data)
{
	int err;

	DBG("");

	if (!data)
		return -EINVAL;

	if (!data->task)
		return 0;

	struct connman_ipconfig *ipconfig;

	err = connman_task_stop(data->task);
	if (err) {
		connman_error("CLAT failed to stop current task");
		return err;
	}

	connman_task_destroy(data->task);

	ipconfig = connman_service_get_ipconfig(data->service, AF_INET6);
	if (ipconfig)
		connman_nat6_restore(ipconfig);

	/* Run as stopped -> does cleanup */
	data->state = CLAT_STATE_STOPPED;
	err = clat_run_task(data);
	if (err) {
		connman_error("CLAT failed to start cleanup task");
		data->state = CLAT_STATE_FAILURE;
	}

	data->state = CLAT_STATE_IDLE;

	g_free(data->isp_64gateway);
	data->isp_64gateway = NULL;
	data->ifindex = -1;

	return err;
}

static void clat_new_rtnl_gateway(int index, const char *dst,
						const char *gateway, int metric,
						unsigned char rtm_protocol)
{
	struct clat_data *data = get_data();

	DBG("%d dst %s gateway %s metric %d", index, dst, gateway, metric);

	/* Not the cellular device we are monitoring. */
	if (index != data->ifindex)
		return;

	if (rtm_protocol != RTPROT_RA && rtm_protocol != RTPROT_DHCP) {
		DBG("rtm_protocol not RA|DHCP");
		return;
	}

	/*if (!connman_inet_is_any_addr(dst, AF_INET6)) {
		DBG("dst %s != IPv6 ANY: %s", dst, IPV6_ANY);
		return;
	}*/

	g_free(data->isp_64gateway);
	data->isp_64gateway = g_strdup(gateway);

	// TODO: perhaps store also dst and metric?
}

static void clat_del_rtnl_gateway(int index, const char *dst,
						const char *gateway, int metric,
						unsigned char rtm_protocol)
{
	struct clat_data *data = get_data();
	
	DBG("%d dst %s gateway %s metric %d", index, dst, gateway, metric);

	if (index != data->ifindex)
		return;

	if (rtm_protocol != RTPROT_RA && rtm_protocol != RTPROT_DHCP) {
		DBG("rtm_protocol not RA|DHCP");
		return;
	}

	/* We lost our gateway, shut down clat */
	if (!g_strcmp0(data->isp_64gateway, gateway)) {
		DBG("CLAT gateway %s gone", data->isp_64gateway);
		clat_stop(data);
	}
}

static struct connman_rtnl clat_rtnl = {
	.name			= "clat",
	.newgateway6		= clat_new_rtnl_gateway,
	.delgateway6		= clat_del_rtnl_gateway,
};

static void clat_ipconfig_changed(struct connman_service *service,
					struct connman_ipconfig *ipconfig)
{
	struct connman_network *network;
	struct clat_data *data = get_data();

	DBG("service %p ipconfig %p", service, ipconfig);

	if (service != data->service || connman_service_get_type(service) !=
						CONNMAN_SERVICE_TYPE_CELLULAR) {
		DBG("Not tracking service %p/%s or not cellular", service,
				connman_service_get_identifier(service));
		return;
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
	struct clat_data *data = get_data();

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
	struct clat_data *data = get_data();
	char *ifname;

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
	/* Connecting does not need yet clat as there is no network.*/
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return;
	/* Connected, start clat. */
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

	
	if (data->ifindex < 0)
		data->ifindex = connman_network_get_index(network);

	if (data->ifindex < 0) {
		DBG("Interface not up, not starting clat");
		return;
	}

	ifname = connman_inet_ifname(data->ifindex);
	if (!ifname) {
		DBG("Interface %d not up, not starting clat", data->ifindex);
		return;
	}

	g_free(ifname);

	clat_start(data);
}

static struct connman_notifier clat_notifier = {
	.name			= "clat",
	.ipconfig_changed	= clat_ipconfig_changed,
	.default_changed	= clat_default_changed,
	.service_state_changed	= clat_service_state_changed,
};

static void clat_free_data(struct clat_data *data)
{
	if (!data)
		return;

	if (data->task)
		connman_task_stop(data->task);

	g_free(data->config_path);
	g_free(data->clat_prefix);
	g_free(data->address);

	g_free(data);
}

static struct clat_data *clat_init_data()
{
	struct clat_data *data;
	
	data = g_new0(struct clat_data, 1);
	if (!data)
		return NULL;

	data->ifindex = -1;

	return data;
}

static int clat_init(void)
{
	int err;

	DBG("");

	__data = clat_init_data();
	if (!__data) {
		connman_error("CLAT: cannot initialize data");
		return -ENOMEM;
	}

	err = connman_notifier_register(&clat_notifier);
	if (err) {
		connman_error("CLAT: notifier register failed");
		return err;
	}

	err = connman_rtnl_register(&clat_rtnl);
	if (err) {
		connman_error("CLAT: rtnl notifier register failed");
		return err;
	}

	connman_rtnl_handle_rtprot_ra(true);

	return 0;
}

static void clat_exit(void)
{
	DBG("");

	connman_notifier_unregister(&clat_notifier);
	connman_rtnl_handle_rtprot_ra(false);
	connman_rtnl_unregister(&clat_rtnl);
	clat_free_data(__data);
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
