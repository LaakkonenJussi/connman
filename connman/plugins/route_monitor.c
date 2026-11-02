/*
 * Connection Manager
 *
 * Generic routing rule monitor
 *
 * Copyright (C) 2026 Jolla Mobile Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <net/if.h>
#include <string.h>

#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>

#include <connman/inet.h>
#include <connman/log.h>
#include <connman/plugin.h>
#include <connman/rtnl.h>

#include "src/connman.h"

/* TODO: make these configurable */
#define MONITOR_ROUTE_IFNAME_PREFIX	"ccmni"
/* The type from linux/rtnetlink.h */
#define MONITOR_RTN_TYPE		RTN_UNICAST
/* 0 for both, AF_INET / AF_INET6 to be specific */
#define MONITOR_AF_TYPE			0
/*
 * The destination prefix len, 0 for gateway route
 * 32 for host route in IPv4, 128 for IPv6
 */
#define MONITOR_DST_LEN			0

#define MONITOR_ROUTE_RULE_PRIORITY	990U

struct route_rule {
	int family;
	unsigned int table;
	int metric;
	int index;
	char ifname[IF_NAMESIZE];
	uint32_t seq;
	bool pending;
	bool requested_del;
};

static GSList *rule_list;
static bool running = false;

static bool is_network_table(unsigned int table)
{
	switch (table) {
	case RT_TABLE_UNSPEC:
	case RT_TABLE_COMPAT:
	case RT_TABLE_DEFAULT:
	case RT_TABLE_MAIN:
	case RT_TABLE_LOCAL:
		return false;
	}

	return true;
}

static struct route_rule *find_rule(int family, unsigned int table, int index,
								int metric)
{
	GSList *list;

	for (list = rule_list; list; list = list->next) {
		struct route_rule *rule = list->data;

		if (rule->family == family && rule->table == table &&
				rule->index == index &&
				rule->metric == metric)
			return rule;
	}

	return NULL;
}

static void free_rule(struct route_rule *rule)
{
	DBG("%p", rule);

	if (!rule)
		return;

	if (rule_list)
		rule_list = g_slist_remove(rule_list, rule);

	g_free(rule);
}

static void remove_rule(struct route_rule *rule);

static void rule_send_callback(uint32_t seq, int err)
{
	GSList *list;

	for (list = rule_list; list; list = list->next) {
		struct route_rule *rule = list->data;

		if (rule->seq != seq)
			continue;

		if (!rule->pending) {
			DBG("Rule seq %u not waiting for ack", seq);
			break;
		}

		rule->pending = false;

		if (!err) {
			DBG("Adding rule seq %u success", seq);

			if (rule->requested_del) {
				DBG("Do pending remove for rule seq %u ", seq);
				rule->requested_del = false;
				remove_rule(rule);
			}
		} else {
			DBG("Cannot add rule seq %u: %d/%s -> remove",
						seq, err, strerror(-err));
			free_rule(rule);
		}

		break;
	}
}

static void add_rule(int family, unsigned int table, int index,
					const char *ifname, int metric)
{
	struct route_rule *rule;
	int err;

	if (find_rule(family, table, index, metric))
		return;

	rule = g_try_new0(struct route_rule, 1);
	if (!rule)
		return;

	rule->family = family;
	rule->table = table;
	rule->index = index;
	rule->metric = metric;
	g_strlcpy(rule->ifname, ifname, sizeof(rule->ifname));

	err = connman_rtnl_add_rule(rule->family, rule->table,
					MONITOR_ROUTE_RULE_PRIORITY,
					rule->ifname, rule_send_callback,
					&rule->seq);
	if (!err || err > 0) {
		DBG("%s lookup %u priority %u index %d metric %d", ifname,
					table, MONITOR_ROUTE_RULE_PRIORITY,
					index, metric);

		if (!err && rule->seq)
			DBG("Rule queued with seq %u", rule->seq);

		rule->pending = true;
		rule_list = g_slist_prepend(rule_list, rule);
		return;
	}

	/*
	 * An identical rule may have been installed by another
	 * component. Do not claim ownership of that rule.
	 */
	if (err != -EEXIST)
		connman_warn("Failed to add rule for %s: %s",
					ifname, strerror(-err));

	g_free(rule);
}

static void remove_rule(struct route_rule *rule)
{
	int err;

	if (!rule->pending) {
		err = connman_rtnl_del_rule(rule->family, rule->table,
					MONITOR_ROUTE_RULE_PRIORITY,
					rule->ifname, NULL, &rule->seq);

		if (err < 0 && err != -ENOENT)
			connman_warn("Failed to request remove rule for %s: %s",
				rule->ifname, strerror(-err));
		else
			DBG("Remove rule queued with seq %u", rule->seq);
	} else if (running) {
		/*
		 * Don't delete a rule that is pending still while the plugin
		 * is active.
		 */
		DBG("set rule for %s pending deletion", rule->ifname);
		rule->requested_del = true;
		return;
	}

	DBG("%s lookup %u priority %u index %d metric %d", rule->ifname,
					rule->table,
					MONITOR_ROUTE_RULE_PRIORITY,
					rule->index, rule->metric);

	free_rule(rule);
}

static void remove_link_rules(int index)
{
	GSList *list = rule_list;

	while (list) {
		struct route_rule *rule = list->data;
		list = list->next;

		if (rule->index == index)
			remove_rule(rule);
	}
}

static void monitor_route(int family, unsigned int table, int index,
					unsigned char dst_len,
					unsigned char type,
					unsigned char protocol,
					int metric,
					bool add)
{
	struct route_rule *rule;
	struct connman_service *service;
	struct connman_network *network;
	char *ifname;

	if (index < 0)
		return;

	DBG("family %d table %u dst_len %u type %u index %d metric %d",
						family, table, dst_len, type,
						index, metric);

	if ((MONITOR_AF_TYPE && family != MONITOR_AF_TYPE) ||
				(family != AF_INET && family != AF_INET6)) {
		DBG("ignore IP family %d", family);
		return;
	}

	if (type != MONITOR_RTN_TYPE) {
		DBG("ignore type %d, expect %d", type, MONITOR_RTN_TYPE);
		return;
	}

	if (dst_len != MONITOR_DST_LEN) {
		DBG("ignore dst_len %d, expect %d", dst_len, MONITOR_DST_LEN);
		return;
	}

	if (!is_network_table(table)) {
		DBG("ignore, route is in normal table");
		return;
	}

	switch (protocol) {
	case RTPROT_UNSPEC:
		DBG("RTPROT unspec");
		break;
	case RTPROT_KERNEL:
		DBG("RTPROT kernel");
		break;
	case RTPROT_BOOT:
		DBG("RTPROT boot");
		break;
	case RTPROT_STATIC:
		DBG("RTPROT static");
		break;
	default:
		DBG("RTPROT: %u", protocol);
		break;
	}

	ifname = connman_inet_ifname(index);
	if (!ifname || !connman_device_isfiltered(ifname)) {
		DBG("%s is not a filtered interface ", ifname);
		goto out;
	}

	if (!g_str_has_prefix(ifname, MONITOR_ROUTE_IFNAME_PREFIX)) {
		DBG("ignore %s", ifname);
		goto out;
	}

	service = connman_service_lookup_from_index(index);
	if (service) {
		DBG("found service %p with index %d", service,index);
		network = connman_service_get_network(service);
		if (network && (connman_network_get_connected(network) ||
				connman_network_get_connecting(network))) {
			DBG("connected/connecting service");
		}

		DBG("-> ignoring");
		goto out;
	}

	DBG("%s route %s table %u index %d metric %d",
						add ? "New" : "Deleted",
						ifname, table, index, metric);

	rule = find_rule(family, table, index, metric);

	if (add) {
		if (!rule) {
			add_rule(family, table, index, ifname, metric);
		} else {
			rule->requested_del = false;
			DBG("rule already exists");
		}
	} else {
		if (rule)
			remove_rule(rule);
		else
			DBG("rule already removed/does not exist");
	}

out:
	g_free(ifname);
}

static void monitor_new_route(int family, unsigned int table, int index,
					unsigned char dst_len,
					unsigned char type,
					unsigned char protocol,
					int metric)
{
	monitor_route(family, table, index, dst_len, type, protocol, metric,
								true);
}

static void monitor_del_route(int family, unsigned int table, int index,
					unsigned char dst_len,
					unsigned char type,
					unsigned char protocol,
					int metric)
{
	monitor_route(family, table, index, dst_len, type, protocol, metric,
								false);
}

static void monitor_newlink(unsigned short type, int index, unsigned flags,
					unsigned change)
{
	/*
	 * RTM_NEWLINK is also sent when an interface goes down.
	 * Remove rules associated with that interface.
	 */
	if (!(flags & IFF_UP))
		remove_link_rules(index);
}

static void monitor_dellink(unsigned short type, int index, unsigned flags,
					unsigned change)
{
	remove_link_rules(index);
}

static struct connman_rtnl monitor_rtnl = {
	.name		= "route_monitor",
	.newlink	= monitor_newlink,
	.dellink	= monitor_dellink,
	.newroute	= monitor_new_route,
	.delroute	= monitor_del_route,
};

static int route_monitor_init(void)
{
	int err;

	DBG("");

	err = connman_rtnl_register(&monitor_rtnl);
	if (err) {
		connman_error("Route monitor: RTNL registration failed");
		return err;
	}

	/*
	 * Re-read existing routes. This is necessary because the
	 * plugin may be loaded after the modem has already created
	 * its PDNs.
	 */
	err = connman_rtnl_request_route_update(AF_INET);
	if (err < 0)
		connman_warn("Failed to request IPv4 route update: %s",
					strerror(-err));

	err = connman_rtnl_request_route_update(AF_INET6);
	if (err < 0)
		connman_warn("Failed to request IPv6 route update: %s",
					strerror(-err));

	running = true;

	return 0;
}

static void route_monitor_exit(void)
{
	DBG("");

	running = false;
	connman_rtnl_unregister(&monitor_rtnl);

	while (rule_list)
		remove_rule(rule_list->data);
}

CONNMAN_PLUGIN_DEFINE(route_monitor,
			"Routing rule monitor",
			VERSION, CONNMAN_PLUGIN_PRIORITY_DEFAULT,
			route_monitor_init, route_monitor_exit)