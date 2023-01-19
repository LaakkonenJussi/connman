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

#define WKN_ADDRESS "ipv4only.arpa"

enum clat_state {
	CLAT_STATE_IDLE = 0,
	CLAT_STATE_PREFIX_QUERY,
	CLAT_STATE_PRE_CONFIGURE,
	CLAT_STATE_RUNNING,
	CLAT_STATE_POST_CONFIGURE,
	CLAT_STATE_STOPPED, // TODO: killed?
	CLAT_STATE_FAILURE,
	CLAT_STATE_RESTART,
};

struct clat_data {
	struct connman_service *service;
	struct connman_task *task;
	enum clat_state state;
	char *isp_64gateway;

	char *config_path;
	char *clat_prefix;
	char *address;
	char *ipv6address;
	unsigned char clat_prefixlen;
	unsigned char addr_prefixlen;
	unsigned char ipv6_prefixlen;
	int ifindex;

	GResolv *resolv;
	guint resolv_query_id;
	guint remove_resolv_id;

	guint dad_id;
	guint prefix_query_id;

	int out_ch_id;
	int err_ch_id;
	GIOChannel *out_ch;
	GIOChannel *err_ch;
};

#define TAYGA_BIN "/usr/local/bin/tayga"
#define TAYGA_CONF "tayga.conf"
#define IPv4ADDR "192.168.255.1"
#define IPv4MAPADDR "192.0.0.4"
#define CLATSUFFIX "c1a7"
#define CLAT_DEVICE "clat"
#define PREFIX_QUERY_TIMEOUT 10000 /* 10 seconds */
#define DAD_TIMEOUT 600000 /* 10 minutes */

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
	case CLAT_STATE_RESTART:
		return true;
	}

	return false;
}

static const char* state2string(enum clat_state state)
{
	switch (state) {
	case CLAT_STATE_IDLE:
		return "idle";
	case CLAT_STATE_STOPPED:
		return "stopped";
	case CLAT_STATE_FAILURE:
		return "failure";
	case CLAT_STATE_PREFIX_QUERY:
		return "prefix query";
	case CLAT_STATE_PRE_CONFIGURE:
		return "pre configure";
	case CLAT_STATE_RUNNING:
		return "running";
	case CLAT_STATE_POST_CONFIGURE:
		return "post configure";
	case CLAT_STATE_RESTART:
		return "restart";
	}

	return "invalid state";
}

static void close_io_channel(struct clat_data *data, GIOChannel *channel)
{
	if (!data || !channel)
		return;

	if (data->out_ch == channel) {
		DBG("closing stderr");

		if (data->out_ch_id) {
			g_source_remove(data->out_ch_id);
			data->out_ch_id = 0;
		}

		if (!data->out_ch)
			return;

		g_io_channel_shutdown(data->out_ch, FALSE, NULL);
		g_io_channel_unref(data->out_ch);

		data->out_ch = NULL;
		return;
	}

	if (data->err_ch == channel) {
		DBG("closing stderr");

		if (data->err_ch_id) {
			g_source_remove(data->err_ch_id);
			data->err_ch_id = 0;
		}

		if (!data->err_ch)
			return;

		g_io_channel_shutdown(data->err_ch, FALSE, NULL);
		g_io_channel_unref(data->err_ch);

		data->err_ch = NULL;
		return;
	}
}

static gboolean io_channel_cb(GIOChannel *source, GIOCondition condition,
			gpointer user_data)
{
	struct clat_data *data = user_data;
	char *str;
	const char *type = source == data->out_ch ? "STDOUT" : "STDERR";

	if ((condition & G_IO_IN) &&
		g_io_channel_read_line(source, &str, NULL, NULL, NULL) ==
							G_IO_STATUS_NORMAL) {
		str[strlen(str) - 1] = '\0';

		DBG("%s: %s", type, str);

		g_free(str);
	} else if (condition & (G_IO_ERR | G_IO_HUP)) {
		DBG("%s Channel termination", type);
		close_io_channel(data, source);
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static int create_task(struct clat_data *data)
{
	if (!data)
		return -ENOENT;

	data->task = connman_task_create(TAYGA_BIN, NULL, data);
	if (!data->task)
		return -ENOMEM;

	return 0;
}


static int destroy_task(struct clat_data *data)
{
	int err;

	if (!data || !data->task)
		return -ENOENT;

	if (data->out_ch)
		close_io_channel(data, data->out_ch);

	if (data->err_ch)
		close_io_channel(data, data->err_ch);

	err = connman_task_stop(data->task);
	if (err) {
		connman_error("CLAT failed to stop current task");
		return err;
	}

	connman_task_destroy(data->task);
	data->task = NULL;
	return 0;
}

static int clat_create_tayga_config(struct clat_data *data)
{
	GError *error = NULL;
	char *str;
	int err;

	g_free(data->config_path);
	data->config_path = g_build_filename(RUNSTATEDIR, "connman", TAYGA_CONF, NULL);

	DBG("config %s", data->config_path);

	str = g_strdup_printf("tun-device %s\n"
				"ipv4-addr %s\n"
				"ipv6-addr %s\n"
				"prefix %s/%u\n"
				"map %s %s\n",
				CLAT_DEVICE,
				IPv4ADDR,
				data->ipv6address,
				data->clat_prefix, data->clat_prefixlen,
				IPv4MAPADDR, data->address);

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

	DBG("");

	if (data->remove_resolv_id)
		g_source_remove(data->remove_resolv_id);

	if (data->resolv && data->resolv_query_id) {
		DBG("cancel resolv lookup");
		g_resolv_cancel_lookup(data->resolv, data->resolv_query_id);
	}

	data->resolv_query_id = 0;
	data->remove_resolv_id = 0;

	g_resolv_unref(data->resolv);
	data->resolv = NULL;

	return G_SOURCE_REMOVE;
}

struct prefix_entry {
	char *prefix;
	unsigned char prefixlen;
};

static struct prefix_entry *new_prefix_entry(char *address)
{
	struct prefix_entry *entry;
	gchar **tokens;

	DBG("address %s", address);

	if (!address)
		return NULL;

	tokens = g_strsplit(address, "/", 2);
	if (!tokens) {
		DBG("cannot create tokens from address %s", address);
		return NULL;
	}

	entry = g_new0(struct prefix_entry, 1);
	if (!entry)
		return NULL;

	DBG("entry %p", entry);

	if (g_strv_length(tokens) == 2) {
		entry->prefix = g_strdup(tokens[0]);
		entry->prefixlen = (unsigned char)g_ascii_strtoull(tokens[1],
								NULL, 10);
	} else {
		DBG("Cannot split with \"/\"");
	}

	g_strfreev(tokens);

	if (entry->prefixlen > 128 || entry->prefixlen < 16) {
		DBG("Invalid prefixlen %u", entry->prefixlen);
		g_free(entry);
		return NULL;
	}

	DBG("prefix %s/%u", entry->prefix, entry->prefixlen);

	return entry;
}

static void free_prefix_entry(gpointer user_data)
{
	struct prefix_entry *entry = user_data;

	DBG("entry %p", entry);

	if (!entry)
		return;

	g_free(entry->prefix);
	g_free(entry);
}

static gint prefix_comp(gconstpointer a, gconstpointer b)
{
	const struct prefix_entry *entry_a = a;
	const struct prefix_entry *entry_b = b;

	/* Largest on top */
	if (entry_a->prefixlen > entry_b->prefixlen)
		return -1;

	if (entry_a->prefixlen < entry_b->prefixlen)
		return 1;

	return 0;
}

static int assign_clat_prefix(struct clat_data *data, char **results)
{
	GList *prefixes = NULL;
	GList *first;
	struct prefix_entry *entry;
	int err = 0;
	int len;
	int i;

	DBG("");

	if (!results) {
		DBG("no results");
		return -ENOENT;
	}

	len = g_strv_length(results);

	for (i = 0; i < len; i++) {
		entry = new_prefix_entry(results[i]);
		if (!entry)
			continue;

		prefixes = g_list_insert_sorted(prefixes, entry, prefix_comp);
	}

	if (!prefixes) {
		DBG("no prefixes found");
		return -ENOENT;
	}

	first = g_list_first(prefixes);
	entry = first->data;
	if (!entry) {
		DBG("no entry is set");
		g_list_free_full(prefixes, free_prefix_entry);
		return -ENOENT;
	}

	/* A prefix exists already */
	if (data->clat_prefix) {
		if (g_strcmp0(data->clat_prefix, entry->prefix) &&
				data->clat_prefixlen != entry->prefixlen) {
			DBG("changing existing prefix %s/%u -> %s/%u",
						data->clat_prefix,
						data->clat_prefixlen,
						entry->prefix,
						entry->prefixlen);
			err = -ERESTART;
		}

		if (!g_strcmp0(data->clat_prefix, entry->prefix) &&
				data->clat_prefixlen == entry->prefixlen) {
			DBG("no change to existing prefix %s/%u",
						data->clat_prefix,
						data->clat_prefixlen);
			err = -EALREADY;
		}
	}


	g_free(data->clat_prefix);
	data->clat_prefix = g_strdup(entry->prefix);
	data->clat_prefixlen = entry->prefixlen;

	g_list_free_full(prefixes, free_prefix_entry);

	return err;
}

// TODO: use conf/define
bool fallback_to_global_prefix = true;

static void prefix_query_cb(GResolvResultStatus status,
					char **results, gpointer user_data)
{
	struct clat_data *data = user_data;
	enum clat_state new_state = data->state;
	int err;

	DBG("status %d", status);

	/*
	 * We cannot unref the resolver here as resolv struct is manipulated
	 * by gresolv.c after we return from this callback.
	 */
	data->remove_resolv_id = g_timeout_add(0, remove_resolv, data);
	data->resolv_query_id = 0;

	if (status != G_RESOLV_RESULT_STATUS_SUCCESS) {
		char **global_prefix = g_new0(char*, 1);

		DBG("failed to resolv %s", WKN_ADDRESS);

		if (fallback_to_global_prefix) {

			DBG("using global 64:ff9b::/96");
			global_prefix[0] = g_strdup("64:ff9b::/96");
			err = assign_clat_prefix(data, global_prefix);
			g_strfreev(global_prefix);
			DBG("freed");
		} else {
			err = -ENOENT;
		}

	} else {
		err = assign_clat_prefix(data, results);
	}

	switch (err) {
	case 0:
		DBG("new prefix %s/%u", data->clat_prefix,
						data->clat_prefixlen);
		break;
	case -EALREADY:
		/* No state change with same prefix */
		DBG("no change in prefix");
		return;
	case -ERESTART:
		DBG("prefix changed to %s/%u, do restart",
						data->clat_prefix,
						data->clat_prefixlen);
		new_state = CLAT_STATE_RESTART;
		break;
	default:
		DBG("failed to assign prefix, error %d", err);
		new_state = CLAT_STATE_FAILURE;
		break;
	}

	/*
	 * Do state transition only when doing initial query or when changing
	 * state.
	 */
	if (data->state == CLAT_STATE_PREFIX_QUERY ||
						data->state != new_state) {
		DBG("State progress or state change -> run CLAT");
		err = clat_run_task(data);
		if (err && err != -EALREADY)
			connman_error("failed to run CLAT, error %d", err);
	}
}

static int clat_task_do_prefix_query(struct clat_data *data)
{
	DBG("");

	/*if (connman_inet_check_ipaddress(data->isp_64gateway) > 0) {
		
		return -EINVAL;
	}*/

	if (data->resolv_query_id > 0) {
		DBG("previous query was running, abort it");
		remove_resolv(data);
	}

	data->resolv = g_resolv_new(0);
	if (!data->resolv) {
		connman_error("CLAT cannot create resolv, stopping");
		return -ENOMEM;
	}

	DBG("Trying to resolv %s gateway %s", WKN_ADDRESS, data->isp_64gateway);

	g_resolv_set_address_family(data->resolv, AF_INET6);
	data->resolv_query_id = g_resolv_lookup_hostname(data->resolv,
					WKN_ADDRESS, prefix_query_cb, data);
	if (data->resolv_query_id <= 0) {
		DBG("failed to start hostname lookup for %s", WKN_ADDRESS);
		return -ENOENT;
	}

	return 0;
}

static gboolean run_prefix_query(gpointer user_data)
{
	struct clat_data *data = user_data;

	DBG("");

	if (!data)
		return G_SOURCE_REMOVE;

	if (clat_task_do_prefix_query(data)) {
		DBG("failed to run prefix query");
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static int clat_task_start_periodic_query(struct clat_data *data)
{
	DBG("");

	if (data->prefix_query_id > 0) {
		DBG("Already running");
		return -EALREADY;
	}

	data->prefix_query_id = g_timeout_add(PREFIX_QUERY_TIMEOUT,
							run_prefix_query, data);
	if (data->prefix_query_id <= 0) {
		connman_error("CLAT failed to start periodic prefix query");
		return -EINVAL;
	}

	return 0;
}

static void clat_task_stop_periodic_query(struct clat_data *data)
{
	DBG("");

	if (data->prefix_query_id)
		g_source_remove(data->prefix_query_id);

	data->prefix_query_id = 0;

	/* Cancel also ongoing resolv */
	if (data->resolv_query_id)
		remove_resolv(data);
}

static gboolean do_online_check(gpointer user_data)
{
	return G_SOURCE_REMOVE;
}

static int clat_task_start_online_check(struct clat_data *data)
{
	// TODO run this via wispr ?
	do_online_check(data);
	return 0;
}

static void clat_task_stop_online_check(struct clat_data *data)
{
	return;
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
	DBG("IPv6 %s prefixlen %u", address, prefixlen);
	data->ipv6address = g_strdup(address);
	data->ipv6_prefixlen = prefixlen;

	tokens = g_strsplit(address, ":", 8);
	if (!tokens) {
		connman_error("CLAT: failed to tokenize IPv6 address");
		return -ENOMEM;
	}

	left = 8 - (128 - (int)prefixlen) / 16;
	pos = 0;

	for (i = 0; tokens[i] && i < left; i++) {
		strncpy(&ipv6prefix[pos], tokens[i], 4);
		pos += strlen(tokens[i]) + 1; // + ':'

		if (i + 1 < left)
			ipv6prefix[pos-1] = ':';
	}

	g_strfreev(tokens);

	data->address = g_strconcat(ipv6prefix,"::c1a7", NULL);
	DBG("Address IPv6 prefix %s/%u -> address %s", data->ipv6address,
					data->ipv6_prefixlen, data->address);

	connman_nat6_prepare(ipconfig);
	clat_create_tayga_config(data);

	if (create_task(data))
		return -ENOMEM;

	connman_task_add_argument(data->task, "--config", data->config_path);
	connman_task_add_argument(data->task, "--mktun", NULL);
	if (connman_task_set_notify(data->task, "tayga", clat_task_notify,
									data))
		return -ENOMEM;

	return 0;
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

static int clat_task_start_tayga(struct clat_data *data)
{
	struct connman_ipaddress *ipaddress;
	int err;
	int index;
	//$ ip link set dev clat up
	// TODO wait for rtnl notify?
	index = connman_inet_ifindex(CLAT_DEVICE);
	if (index < 0) {
		connman_warn("CLAT tayga not up yet?");
		return -ENODEV;
	}

	DBG("");

	err = connman_inet_ifup(index);
	if (err && err != -EALREADY) {
		connman_error("CLAT failed to bring interface %s up",
								CLAT_DEVICE);
		return err;
	}

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

	if (create_task(data))
		return -ENOMEM;

	connman_task_add_argument(data->task, "--config", data->config_path);
	connman_task_add_argument(data->task, "--nodetach", NULL);
	connman_task_add_argument(data->task, "-d", NULL);

	if (connman_task_set_notify(data->task, "tayga", clat_task_notify,
									data))
		return -EIO;

	return 0;
}

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
	struct clat_data *data = user_data;
	unsigned char addr[sizeof(struct in6_addr)];
	int err = 0;

	DBG("");

	if (inet_pton(AF_INET6, data->address, addr) != 1) {
		connman_error("failed to pton address %s", data->address);
		return G_SOURCE_REMOVE;
	}

	err = connman_inet_ipv6_do_dad(data->ifindex, 100,
						(struct in6_addr *)addr,
						clat_dad_cb, data);
	if (err) {
		connman_error("CLAT failed to send dad: %d", err);
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static int clat_task_start_dad(struct clat_data *data)
{
	DBG("");

	data->dad_id = g_timeout_add(DAD_TIMEOUT, clat_task_run_dad, data);

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

	DBG("");

	// TODO check return values
	ipaddress = connman_ipaddress_alloc(AF_INET);
	connman_inet_del_host_route(index, IPv4MAPADDR);
	connman_ipaddress_set_ipv4(ipaddress, IPv4MAPADDR, NULL, NULL);
	connman_inet_clear_address(index, ipaddress);
	connman_inet_del_ipv6_network_route(index, data->address,
							data->addr_prefixlen);
	connman_inet_ifdown(index);
	connman_ipaddress_free(ipaddress);

	if (create_task(data))
		return -ENOMEM;

	connman_task_add_argument(data->task, "--config", data->config_path);
	connman_task_add_argument(data->task, "--rmtun", NULL);

	if (connman_task_set_notify(data->task, "tayga",clat_task_notify,
									data))
		return -ENOMEM;

	return 0;
}

static void clat_task_exit(struct connman_task *task, int exit_code,
								void *user_data)
{
	struct clat_data *data = user_data;

	DBG("state %d/%s", data->state, state2string(data->state));

	if (exit_code) {
		connman_warn("CLAT task failed with code %d", exit_code);
		data->state = CLAT_STATE_FAILURE;
	}

	if (task != data->task) {
		connman_warn("CLAT task differs, nothing done");
		return;
	}

	if (data->task) {
		connman_task_destroy(data->task);
		data->task = NULL;
	}

	switch (data->state) {
	case CLAT_STATE_IDLE:
	case CLAT_STATE_STOPPED:
	case CLAT_STATE_FAILURE:
		DBG("CLAT task exited in state %d/%s", data->state,
						state2string(data->state));
		return;
	case CLAT_STATE_PREFIX_QUERY:
	case CLAT_STATE_PRE_CONFIGURE:
	case CLAT_STATE_RUNNING:
		DBG("run next state %d/%s", data->state + 1 ,
						state2string(data->state + 1));
		clat_run_task(data);
		return;
	case CLAT_STATE_POST_CONFIGURE:
		DBG("CLAT process ended");
		data->state = CLAT_STATE_STOPPED;
		break;
	case CLAT_STATE_RESTART:
		DBG("CLAT task return when restarting");
		break;
	}
}

static int clat_run_task(struct clat_data *data)
{
	int fd_out;
	int fd_err;
	int err = 0;

	DBG("state %d/%s", data->state, state2string(data->state));

	switch (data->state) {
	case CLAT_STATE_IDLE:
		data->state = CLAT_STATE_PREFIX_QUERY;
		/* Get the prefix from the ISP NAT service */
		err = clat_task_do_prefix_query(data);
		if (err && err != -EALREADY) {
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

		err = clat_task_start_periodic_query(data);
		if (err && err != -EALREADY)
			connman_warn("CLAT failed to start periodic prefix "
								"query");

		err = clat_task_start_dad(data);
		if (err && err != -EALREADY)
			connman_warn("CLAT failed to start periodic DAD");

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
		clat_task_stop_periodic_query(data);
		clat_task_stop_dad(data);
		clat_task_stop_online_check(data);
		break;
	case CLAT_STATE_POST_CONFIGURE:
		connman_warn("CLAT run task called in post-configure state");
		data->state = CLAT_STATE_STOPPED;
		return 0;
	case CLAT_STATE_FAILURE:
		DBG("CLAT entered failure state, stop all that is running");

		destroy_task(data);
		clat_task_stop_periodic_query(data);
		clat_task_stop_dad(data);
		clat_task_stop_online_check(data);

		/* Remain in failure state, can be started via clat_start(). */
		data->state = CLAT_STATE_FAILURE;
		return 0;
	case CLAT_STATE_RESTART:
		destroy_task(data);

		/* Run as stopped -> does cleanup */
		data->state = CLAT_STATE_STOPPED;
		err = clat_run_task(data);
		if (err && err != -EALREADY) {
			connman_error("CLAT failed to start cleanup task");
			data->state = CLAT_STATE_FAILURE;
		}

		data->state = CLAT_STATE_IDLE;
	}

	if (!err) {
		DBG("CLAT run task %p", data->task);
		err = connman_task_run(data->task, clat_task_exit, data, NULL,
							&fd_out, &fd_err);
	}

	if (err) {
		connman_error("CLAT task failed to run, error %d/%s",
							err, strerror(-err));
		data->state = CLAT_STATE_FAILURE;

		if (data->task)
			connman_task_destroy(data->task);
		data->task = NULL;
	} else {
		data->out_ch = g_io_channel_unix_new(fd_out);
		data->out_ch_id = g_io_add_watch(data->out_ch,
						G_IO_IN | G_IO_ERR | G_IO_HUP,
						(GIOFunc)io_channel_cb, data);
		data->err_ch = g_io_channel_unix_new(fd_err);
		data->err_ch_id = g_io_add_watch(data->err_ch,
						G_IO_IN | G_IO_ERR | G_IO_HUP,
						(GIOFunc)io_channel_cb, data);
	}

	DBG("in state %d/%s", data->state, state2string(data->state));

	return err;
}

static int clat_start(struct clat_data *data)
{
	DBG("state %d/%s", data->state, state2string(data->state));

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

	DBG("state %d/%s", data->state, state2string(data->state));

	if (!data)
		return -EINVAL;

	if (!data->task)
		return 0;

	struct connman_ipconfig *ipconfig;

	destroy_task(data);

	ipconfig = connman_service_get_ipconfig(data->service, AF_INET6);
	if (ipconfig)
		connman_nat6_restore(ipconfig);

	/* Run as stopped -> does cleanup */
	data->state = CLAT_STATE_STOPPED;
	err = clat_run_task(data);
	if (err && err != -EALREADY) {
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
	enum connman_service_state state;
	int err;

	if (service || !data->service)
		return;

	DBG("service %p ipconfig %p", service, ipconfig);

	if (service != data->service || connman_service_get_type(service) !=
						CONNMAN_SERVICE_TYPE_CELLULAR) {
		DBG("Not tracking service %p/%s or not cellular", service,
				connman_service_get_identifier(service));
		return;
	}

	if (connman_ipconfig_get_config_type(ipconfig) ==
						CONNMAN_IPCONFIG_TYPE_IPV4) {
		DBG("cellular %p has IPv4 config, stop CLAT", service);
		clat_stop(data);
		return;
	}

	if (service != connman_service_get_default()) {
		DBG("cellular service %p is not default, stop CLAT", service);
		clat_stop(data);
		return;
	}

	network = connman_service_get_network(service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected, stop CLAT", network);
		clat_stop(data);
		return;
	}

	state = connman_service_get_state(service);

	if (state == CONNMAN_SERVICE_STATE_READY ||
				state == CONNMAN_SERVICE_STATE_ONLINE) {
		DBG("service %p ready|online, start CLAT", service);
		err = clat_start(data);
		if (err && err != -EALREADY)
			connman_error("CLAT failed to start, error %d", err);
	}
}

static bool has_ipv4_address(struct connman_service *service)
{
	struct connman_ipconfig *ipconfig;
	struct connman_ipaddress *ipaddress;
	enum connman_ipconfig_method method;
	const char *address;
	unsigned char prefixlen;
	int err;

	ipconfig = connman_service_get_ipconfig(service, AF_INET);
	DBG("IPv4 ipconfig %p", ipconfig);

	ipaddress = connman_ipconfig_get_ipaddress(ipconfig);
	DBG("IPv4 ipaddress %p", ipaddress);

	err = connman_ipaddress_get_ip(ipaddress, &address, &prefixlen);
	if (err) {
		DBG("IPv4 is not configured on cellular service %p", service);
		return false;
	}

	if (!address) {
		DBG("no IPv4 address on cellular service %p", service);
		return false;
	}

	method = connman_service_get_ipconfig_method(service,
						CONNMAN_IPCONFIG_TYPE_IPV4);
	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		DBG("IPv4 method unknown/off, address is old");
		return false;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		break;
	}

	DBG("IPv4 address %s set for service %p", address, service);
	return true;
}

static void clat_default_changed(struct connman_service *service)
{
	struct connman_network *network;
	struct clat_data *data = get_data();

	if (!service || !data->service)
		return;

	DBG("service %p", service);

	if (!is_running(data->state)) {
		DBG("CLAT not running, default change not affected");
		return;
	}

	if (data->service && data->service != service) {
		DBG("Tracked cellular service %p is not default, stop CLAT",
							data->service);
		clat_stop(data);
		return;
	}

	network = connman_service_get_network(service);
	if (!network || !connman_network_get_connected(network)) {
		DBG("network %p not connected, stop CLAT", network);
		clat_stop(data);
		return;
	}

	if (connman_network_is_configured(network,
					CONNMAN_IPCONFIG_TYPE_IPV4) &&
					has_ipv4_address(data->service)) {
		DBG("IPv4 is configured on cellular network %p, stop CLAT",
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
	int err;

	if (!service || connman_service_get_type(service) !=
						CONNMAN_SERVICE_TYPE_CELLULAR)
		return;

	DBG("cellular service %p", service);

	switch (state) {
	/* Not connected */
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		/* Stop clat if the service goes offline */
		if (service == data->service) {
			DBG("offline state, stop CLAT");
			clat_stop(data);
			data->service = NULL;
		}
		return;
	/* Connecting does not need yet clat as there is no network.*/
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		DBG("association|configuration, assign service %p", service);
		data->service = service;
		return;
	/* Connected, start clat. */
	case CONNMAN_SERVICE_STATE_READY:
		if (service != data->service)
			return;

		if (is_running(data->state)) {
			DBG("CLAT is already running in state %d/%s",
						data->state,
						state2string(data->state));
			return;
		}

		DBG("ready, initialize CLAT");
		break;
	case CONNMAN_SERVICE_STATE_ONLINE:
		if (service != data->service)
			return;

		if (!is_running(data->state)) {
			DBG("CLAT is not running yet, start it first");
			break;
		}

		goto onlinecheck;
	}

	network = connman_service_get_network(service);
	if (!network) {
		DBG("No network yet, not starting clat");
		return;
	}

	if (data->ifindex < 0) {
		DBG("ifindex not set, get it from network");
		data->ifindex = connman_network_get_index(network);
	}

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

	/* Network may have DHCP/AUTO set without address */
	if (connman_network_is_configured(network,
					CONNMAN_IPCONFIG_TYPE_IPV4) &&
					has_ipv4_address(data->service)) {
		DBG("Service %p has IPv4 address on interface %d, not "
						"starting CLAT", data->service,
						data->ifindex);
		return;
	}

	err = clat_start(data);
	if (err && err != -EALREADY)
		connman_error("failed to start CLAT, error %d", err);

onlinecheck:
	if (state == CONNMAN_SERVICE_STATE_ONLINE) {
		DBG("online, do online check");

		err = clat_task_start_online_check(data);
		if (err && err != -EALREADY)
			connman_error("CLAT failed to do online check");
	}
}

static struct connman_notifier clat_notifier = {
	.name			= "clat",
	.ipconfig_changed	= clat_ipconfig_changed,
	.default_changed	= clat_default_changed,
	.service_state_changed	= clat_service_state_changed,
};

static void clat_free_data(struct clat_data *data)
{
	DBG("");

	if (!data)
		return;

	destroy_task(data);
	g_free(data->config_path);
	g_free(data->clat_prefix);
	g_free(data->address);
	g_free(data->ipv6address);

	g_free(data);
}

static struct clat_data *clat_init_data()
{
	struct clat_data *data;

	DBG("");

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

	if (is_running(__data->state))
		clat_stop(__data);

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
