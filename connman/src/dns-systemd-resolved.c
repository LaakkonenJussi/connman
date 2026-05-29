/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2017  Intel Corporation. All rights reserved.
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <gdbus.h>
#include <glib.h>
#include <connman/dbus.h>

#include "shared/dns.h"
#include "connman.h"

#define SYSTEMD_RESOLVED_SERVICE "org.freedesktop.resolve1"
#define SYSTEMD_RESOLVED_PATH "/org/freedesktop/resolve1"
#define SYSTEMD_RESOLVED_SERVER "127.0.0.53"

struct resolved_dbus_data {
	int index;
	bool enabled;
};

static GHashTable *interface_hash;
static DBusConnection *connection;
static GDBusClient *client;
static GDBusProxy *resolved_proxy;

/* update after a full set of instructions has been received */
static guint update_interfaces_source;
static gint current_default_index = -1;

struct dns_interface {
	GList *domains;
	GList *servers;
	int index;
	bool needs_domain_update;
	bool needs_server_update;
	bool enabled;
};

static gboolean compare_index(gconstpointer a, gconstpointer b)
{
	gint ai = GPOINTER_TO_UINT(a);
	gint bi = GPOINTER_TO_UINT(b);

	return ai == bi;
}

static void free_dns_interface(gpointer data)
{
	struct dns_interface *iface = data;

	if (!iface)
		return;

	g_list_free_full(iface->domains, g_free);
	g_list_free_full(iface->servers, g_free);

	g_free(iface);
}

static void setlinkdns_append(DBusMessageIter *iter, void *user_data)
{
	struct dns_interface *iface = user_data;
	int result;
	unsigned int i;
	int type;
	char ipv4_bytes[4];
	char ipv6_bytes[16];
	GList *list;
	DBusMessageIter address_array, struct_array, byte_array;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &iface->index);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "(iay)",
			&address_array);

	for (list = iface->servers; list; list = g_list_next(list)) {
		char *server = list->data;

		DBG("index: %d, server: %s", iface->index, server);

		dbus_message_iter_open_container(&address_array,
				DBUS_TYPE_STRUCT, NULL, &struct_array);

		type = connman_inet_check_ipaddress(server);

		if (type == AF_INET) {
			result = inet_pton(type, server, ipv4_bytes);
			if (!result) {
				DBG("Failed to parse IPv4 address: %s",
						server);
				return;
			}

			dbus_message_iter_append_basic(&struct_array,
					DBUS_TYPE_INT32, &type);

			dbus_message_iter_open_container(&struct_array,
					DBUS_TYPE_ARRAY, "y", &byte_array);

			for (i = 0; i < sizeof(ipv4_bytes); i++) {
				dbus_message_iter_append_basic(&byte_array,
						DBUS_TYPE_BYTE,
						&(ipv4_bytes[i]));
			}

			dbus_message_iter_close_container(&struct_array,
					&byte_array);
		} else if (type == AF_INET6) {
			result = inet_pton(type, server, ipv6_bytes);
			if (!result) {
				DBG("Failed to parse IPv6 address: %s", server);
				return;
			}

			dbus_message_iter_append_basic(&struct_array,
					DBUS_TYPE_INT32, &type);

			dbus_message_iter_open_container(&struct_array,
					DBUS_TYPE_ARRAY, "y", &byte_array);

			for (i = 0; i < sizeof(ipv6_bytes); i++) {
				dbus_message_iter_append_basic(&byte_array,
						DBUS_TYPE_BYTE,
						&(ipv6_bytes[i]));
			}

			dbus_message_iter_close_container(&struct_array,
					&byte_array);
		}

		dbus_message_iter_close_container(&address_array,
				&struct_array);
	}

	dbus_message_iter_close_container(iter, &address_array);
}

static void setlinkdomains_append(DBusMessageIter *iter, void *user_data)
{
	struct dns_interface *iface = user_data;
	GList *list;
	DBusMessageIter domain_array, struct_array;
	gboolean only_routing = FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &iface->index);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "(sb)",
						&domain_array);

	for (list = iface->domains; list; list = g_list_next(list)) {
		char *domain = list->data;

		DBG("index: %d, domain: %s", iface->index, domain);

		dbus_message_iter_open_container(&domain_array,
				DBUS_TYPE_STRUCT, NULL, &struct_array);

		dbus_message_iter_append_basic(&struct_array, DBUS_TYPE_STRING,
				&domain);

		dbus_message_iter_append_basic(&struct_array, DBUS_TYPE_BOOLEAN,
				&only_routing);

		dbus_message_iter_close_container(&domain_array, &struct_array);
	}

	dbus_message_iter_close_container(iter, &domain_array);
}

static int set_systemd_resolved_values(struct dns_interface *iface)
{
	if (!resolved_proxy || !iface)
		return -ENOENT;

	/* No async error processing -- just fire and forget */

	if (iface->needs_server_update) {
		if (!g_dbus_proxy_method_call(resolved_proxy, "SetLinkDNS",
				setlinkdns_append, NULL, iface, NULL))
			return -EINVAL;

		iface->needs_server_update = FALSE;
	}

	if (iface->needs_domain_update) {
		if (!g_dbus_proxy_method_call(resolved_proxy, "SetLinkDomains",
				setlinkdomains_append, NULL, iface, NULL))
			return -EINVAL;

		iface->needs_domain_update = FALSE;
	}

	return 0;
}

static bool is_empty(struct dns_interface *iface)
{
	if (!iface)
		return FALSE;

	return (!iface->domains && !iface->servers);
}

/*
 * If the default service exists and it is different do not allow to update this
 * service. Only the default service's DNS should be used. The services may be
 * updated after the service was disabled but that would then block use of the
 * service at startup as DNSs and domains are updated before the service is
 * enabled. This makes it possible to handle both cases, when the service is
 * just initializing or when a service gets updates while not being as default
 * service, which is the case when using VPN as default service. With split
 * routed VPNs the transport service's IPv4 and IPv6 should be checked if the
 * VPN is using either of them. In such case the DNS servers of the split-routed
 * VPN must be kept in order to access resources behind the VPN as well.
 */
static bool skip_iface_update(int index)
{
	struct connman_service *default_service = connman_service_get_default();
	struct connman_ipconfig *ipconfig;
	int service_index;
	int vpn_index;

	if (!default_service)
		return false;

	ipconfig = __connman_service_get_ip4config(default_service);
	service_index = __connman_ipconfig_get_index(ipconfig);
	if (service_index == index)
		return false;

	vpn_index = __connman_connection_get_vpn_index(service_index);

	DBG("index4 %d vpn_index %d index %d", service_index, vpn_index, index);

	/* Split routed VPN -> DNSs must be added */
	if (vpn_index == index) {
		DBG("IPv4 split routed VPN, keep DNS");
		return false;
	}

	ipconfig = __connman_service_get_ip6config(default_service);
	service_index = __connman_ipconfig_get_index(ipconfig);
	if (service_index == index)
		return false;

	vpn_index = __connman_connection_get_vpn_index(service_index);

	DBG("index6 %d vpn_index %d index %d", service_index, vpn_index, index);

	if (vpn_index == index) {
		DBG("IPv6 split routed VPN, keep DNS");
		return false;
	}

	DBG("skip DNS of %d", index);

	return true;
}

static void update_interface(gpointer key, gpointer value, gpointer data)
{
	struct dns_interface *iface = value;
	GList **removed_items = data;

	if (skip_iface_update(iface->index))
		DBG("default service exists and is not %d, skip", iface->index);
	else {
		DBG("set systemd resolved values, force updates");
		iface->needs_server_update = true;
		iface->needs_domain_update = true;
		set_systemd_resolved_values(iface);
	}

	if (is_empty(iface))
		*removed_items = g_list_prepend(*removed_items, iface);
}

static int update_systemd_resolved(gpointer data)
{
	GList *removed_items = NULL, *list;

	if (!interface_hash) {
		DBG("no interface hash when updating");

		return G_SOURCE_REMOVE;
	}

	g_hash_table_foreach(interface_hash, update_interface, &removed_items);

	for (list = removed_items; list; list = g_list_next(list)) {
		struct dns_interface *iface = list->data;

		g_hash_table_remove(interface_hash,
				GUINT_TO_POINTER(iface->index));
	}

	g_list_free(removed_items);

	update_interfaces_source = 0;

	return G_SOURCE_REMOVE;
}

static GList *remove_string(GList *str_list, const char *str)
{
	GList *match = NULL;

	match = g_list_find_custom(str_list, str,
			(GCompareFunc) g_strcmp0);
	if (match) {
		g_free(match->data);
			return g_list_delete_link(str_list, match);
	}

	return str_list;
}

static void remove_values(struct dns_interface *iface, const char *domain,
							const char *server)
{
	if (!iface)
		return;

	if (domain) {
		iface->domains = remove_string(iface->domains, domain);
		iface->needs_domain_update = TRUE;
	}

	if (server) {
		iface->servers = remove_string(iface->servers, server);
		iface->needs_server_update = TRUE;
	}
}

int __connman_dnsproxy_remove(int index, const char *domain,
							const char *server)
{
	struct dns_interface *iface;

	DBG("%d, %s, %s", index, domain ? domain : "no domain",
			server ? server : "no server");

	if (!interface_hash || index < 0)
		return -EINVAL;

	iface = g_hash_table_lookup(interface_hash, GUINT_TO_POINTER(index));

	if (!iface)
		return -EINVAL;

	remove_values(iface, domain, server);

	if (!update_interfaces_source)
		update_interfaces_source = g_idle_add(update_systemd_resolved,
				NULL);

	return 0;
}

static GList *replace_to_end(GList *str_list, const char *str)
{
	GList *list;

	for (list = str_list; list; list = g_list_next(list)) {
		char *orig = list->data;

		if (g_strcmp0(orig, str) == 0) {
			str_list = g_list_remove(str_list, orig);
			g_free(orig);
			break;
		}
	}

	return g_list_append(str_list, g_strdup(str));
}

static void update_interface_dns_and_domain(struct dns_interface *iface)
{
	DBG("index %d", iface->index);

	iface->needs_domain_update = TRUE;
	iface->needs_server_update = TRUE;

	if (!update_interfaces_source) {
		DBG("add new update_systemd_resolved call");
		update_interfaces_source = g_idle_add(update_systemd_resolved,
				NULL);
	}
}

int __connman_dnsproxy_append(int index, const char *domain,
							const char *server)
{
	struct dns_interface *iface;
	bool skip_update = false;

	DBG("%d, %s, %s", index, domain ? domain : "no domain",
			server ? server : "no server");

	if (!interface_hash || index < 0)
		return -EINVAL;

	iface = g_hash_table_lookup(interface_hash, GUINT_TO_POINTER(index));

	if (!iface) {
		iface = g_new0(struct dns_interface, 1);
		if (!iface)
			return -ENOMEM;

		iface->index = index;
		g_hash_table_replace(interface_hash, GUINT_TO_POINTER(index), iface);
	}

	skip_update = skip_iface_update(index);
	if (skip_update)
		DBG("skip adding DNS and domains for non-default %d", index);

	if (domain) {
		iface->domains = replace_to_end(iface->domains, domain);
		iface->needs_domain_update = !skip_update;
	}

	if (server) {
		iface->servers = replace_to_end(iface->servers, server);
		iface->needs_server_update = !skip_update;
	}

	if (!update_interfaces_source)
		update_interfaces_source = g_idle_add(update_systemd_resolved,
				NULL);

	return 0;
}

int __connman_dnsproxy_add_listener(int index)
{
	int lo_index;
	int err;

	DBG("index %d", index);

	err = dns_add_listener(index, DNS_IPPROTO_UDP, true);
	if (err)
		return err;

	lo_index = connman_inet_ifindex("lo");
	err = dns_create_server(lo_index, "local", SYSTEMD_RESOLVED_SERVER,
								IPPROTO_UDP);
	if (err)
		return err;

	err = dns_enable_server(lo_index, SYSTEMD_RESOLVED_SERVER, IPPROTO_UDP,
								true);
	if (err)
		return err;

	return 0;
}

void __connman_dnsproxy_remove_listener(int index)
{
	DBG("");

	dns_remove_listener(index);
}

static int setup_resolved(void)
{
	connection = connman_dbus_get_connection();
	if (!connection)
		return -ENXIO;

	client = g_dbus_client_new(connection, SYSTEMD_RESOLVED_SERVICE,
			SYSTEMD_RESOLVED_PATH);

	if (!client)
		return -EINVAL;

	resolved_proxy = g_dbus_proxy_new(client, SYSTEMD_RESOLVED_PATH,
			"org.freedesktop.resolve1.Manager");

	if (!resolved_proxy)
		return -EINVAL;

	return 0;
}

static void setlinkmulticastdns_append(DBusMessageIter *iter, void *user_data) {
	struct resolved_dbus_data *data = user_data;
	char *val = "no";

	if (data->enabled)
		val = "yes";

	DBG("SetLinkMulticastDNS: %d/%s", data->index, val);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &data->index);
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &val);
}

int __connman_dnsproxy_set_mdns(int index, bool enabled)
{
	struct resolved_dbus_data data = { .index = index, .enabled = enabled };

	if (!resolved_proxy)
		return -ENOENT;

	if (index < 0)
		return -EINVAL;

	if (!g_dbus_proxy_method_call(resolved_proxy, "SetLinkMulticastDNS",
			setlinkmulticastdns_append, NULL, &data, NULL))
		return -EINVAL;

	return 0;
}

static void setlinkdefaultroute_append(DBusMessageIter *iter, void *user_data)
{
	struct resolved_dbus_data *data = user_data;
	dbus_bool_t val = data->enabled;

	DBG("SetLinkDefaultRoute: %d/%s", data->index, val ? "yes" : "no");

	dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &data->index);
	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &val);
}

static int resolved_set_default_route(int index, bool enabled)
{
	struct resolved_dbus_data data = { .index = index, .enabled = enabled };

	if (!resolved_proxy)
		return -ENOENT;

	if (index < 0)
		return -ENODEV;

	if (!g_dbus_proxy_method_call(resolved_proxy, "SetLinkDefaultRoute",
			setlinkdefaultroute_append, NULL, &data, NULL))
		return -EINVAL;

	return 0;
}

static int resolved_flush_cache()
{
	DBG("");

	if (!resolved_proxy)
		return -ENOENT;

	if (!g_dbus_proxy_method_call(resolved_proxy, "FlushCaches",
			NULL, NULL, NULL, NULL))
		return -EINVAL;

	return 0;
}

static void setrevertlink_append(DBusMessageIter *iter, void *user_data)
{
	int index = GPOINTER_TO_INT(user_data);

	DBG("RevertLink: %d", index);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &index);
}

static int resolved_disable_interface(int index)
{
	if (!resolved_proxy)
		return -ENOENT;

	if (index < 0)
		return -ENODEV;

	if (!g_dbus_proxy_method_call(resolved_proxy, "RevertLink",
			setrevertlink_append, NULL, GINT_TO_POINTER(index),
			NULL))
		return -EINVAL;

	return 0;
}

struct interface_search_data {
	bool enable;
	bool forced;
	bool disconnected;
	int index4;
	int index6;
	int vpn_index;
};

static bool interface_index_match(int index,
				struct interface_search_data *search_data)
{
	if (search_data->forced)
		return true;

	if (index == search_data->index4 || index == search_data->index6) {
		DBG("interface %d match", index);
		return true;
	}

	if (index == search_data->vpn_index) {
		DBG("VPN interface %d match", index);
		return true;
	}

	return false;
}

static void toggle_interface_dns(struct dns_interface *iface, bool enable)
{
	DBG("%s interface %p/%d", enable ? "enable" : "disable", iface,
								iface->index);

	if (iface->enabled && enable) {
		DBG("already enabled");
		return;
	}

	iface->enabled = enable;

	if (!enable) {
		DBG("disabling interface %d", iface->index);
		resolved_disable_interface(iface->index);
	} else {
		DBG("re-enabling interface %d", iface->index);
		set_systemd_resolved_values(iface);
		update_interface_dns_and_domain(iface);
	}

	if (is_empty(iface)) {
		DBG("removing interface %d", iface->index);
		g_hash_table_remove(interface_hash,
					GUINT_TO_POINTER(iface->index));
	}
}

static void check_interface(gpointer key, gpointer value, gpointer user_data)
{
	struct dns_interface *iface = value;
	struct interface_search_data *search_data = user_data;

	if (interface_index_match(iface->index, search_data)) {
		/*
		 * Clear domains and servers before updating the status to
		 * resolved when interface is disconnected.
		 */
		if (!search_data->enable && search_data->disconnected) {
			DBG("clear domains and servers of %d", iface->index);

			g_list_free_full(iface->domains, g_free);
			iface->domains = NULL;

			g_list_free_full(iface->servers, g_free);
			iface->servers = NULL;
		}

		toggle_interface_dns(iface, search_data->enable);
	/* If DNSs of an interface are to be enabled disable the others */
	} else if (search_data->enable) {
		DBG("disable %d", iface->index);
		toggle_interface_dns(iface, false);
	} else {
		DBG("no-op on %d", iface->index);
		return;
	}

	if (!update_interfaces_source)
		update_interfaces_source = g_idle_add(update_systemd_resolved,
									NULL);
}

static void resolved_offline_mode(bool enabled)
{
	struct interface_search_data search_data = { 0 };
	int err;

	DBG("enabled %d", enabled);

	search_data.enable = !enabled;
	search_data.forced = true;

	g_hash_table_foreach(interface_hash, check_interface, &search_data);

	/* Offline mode is not on, skip default unset and flushing of cache */
	if (!enabled)
		return;

	err = resolved_set_default_route(current_default_index, false);
	if (err && err != -ENODEV)
		DBG("failed to unset interface %d as default route",
							current_default_index);

	current_default_index = -1;

	resolved_flush_cache();
}

static void resolved_default_changed(struct connman_service *service)
{
	struct connman_ipconfig *ipconfig;
	struct interface_search_data search_data = { 0 };
	int index;
	int err;

	DBG("service %p interface %d", service,
					__connman_service_get_index(service));

	if (!service) {
		/* When no services are active, then disable DNSs */
		resolved_offline_mode(true);
		return;
	}

	if (connman_service_get_type(service) == CONNMAN_SERVICE_TYPE_VPN) {
		/* VPN is either or take both to be sure */
		search_data.index4 = search_data.index6 = -1;
		search_data.vpn_index = __connman_service_get_index(service);

		if (search_data.vpn_index < 0)
			return;

		index = search_data.vpn_index;
	} else {
		ipconfig = __connman_service_get_ip4config(service);
		search_data.index4 = __connman_ipconfig_get_index(ipconfig);

		ipconfig = __connman_service_get_ip6config(service);
		search_data.index6 = __connman_ipconfig_get_index(ipconfig);

		if (search_data.index4 < 0 && search_data.index6 < 0)
			return;

		/*
		 * In case non-split-routed VPN is set as split routed the DNS
		 * servers the VPN must be enabled as well, when the transport
		 * becomes the default service. Try first with IPv4 and then
		 * attempt using IPv6 if not set. VPN can be either or.
		 */
		search_data.vpn_index = __connman_connection_get_vpn_index(
							search_data.index4);
		if (search_data.vpn_index < 0)
			search_data.vpn_index =
					__connman_connection_get_vpn_index(
							search_data.index6);

		if (search_data.index4 == search_data.index6)
			index = search_data.index4;
		else
			index = search_data.index6; // Prefer IPv6, as usual.
	}

	if (current_default_index != index) {
		err = resolved_set_default_route(current_default_index, false);
		if (err && err != -ENODEV)
			DBG("failed to unset %d as default",
							current_default_index);

		current_default_index = -1;

		err = resolved_set_default_route(index, true);
		if (err && err != -ENODEV)
			DBG("failed to set %d as default", index);
		else
			current_default_index = index;
	}

	search_data.enable = true;
	g_hash_table_foreach(interface_hash, check_interface, &search_data);

	resolved_flush_cache();
}

static void resolved_service_state_changed(struct connman_service *service,
			enum connman_service_state state)
{
	struct connman_ipconfig *ipconfig;
	struct interface_search_data search_data = { 0 };
	int index;
	int err;

	index = __connman_service_get_index(service);
	if (index < 0)
		return;

	DBG("service %p interface %d state %d", service, index, state);

	switch (state) {
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_UNKNOWN:
		DBG("disable interface %d", index);
		break;
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_ONLINE:
	case CONNMAN_SERVICE_STATE_READY:
		DBG("connecting/connected mode, skip interface %d", index);
		return;
	}

	ipconfig = __connman_service_get_ip4config(service);
	search_data.index4 = __connman_ipconfig_get_index(ipconfig);

	ipconfig = __connman_service_get_ip6config(service);
	search_data.index6 = __connman_ipconfig_get_index(ipconfig);

	if (current_default_index == search_data.index4)
		index = search_data.index4;
	else if (current_default_index == search_data.index6)
		index = search_data.index6;
	else
		index = -1;

	if (index != -1) {
		err = resolved_set_default_route(index, false);
		if (err && err != -ENODEV)
			DBG("failed to unset %d as default route", index);

		current_default_index = -1;
		resolved_flush_cache(); // Do when index is unset
	}

	/*
	 * Disable DNS servers when the service is not connected and clear the
	 * domains and servers. Use both indexes as service can have two
	 * separate interfaces, both of which can be registered to resolved.
	 */
	search_data.enable = false;
	search_data.disconnected = true;

	g_hash_table_foreach(interface_hash, check_interface, &search_data);

	if (!update_interfaces_source)
		update_interfaces_source = g_idle_add(update_systemd_resolved,
									NULL);
}

static struct connman_notifier resolved_notifier = {
	.name			= "systemd-resolved",
	.default_changed	= resolved_default_changed,
	.offline_mode		= resolved_offline_mode,
	.service_state_changed	= resolved_service_state_changed,
};

int __connman_dnsproxy_init(void)
{
	int ret;

	DBG("");

	ret = setup_resolved();
	if (ret)
		return ret;

	interface_hash = g_hash_table_new_full(g_direct_hash,
						compare_index,
						NULL,
						free_dns_interface);
	if (!interface_hash)
		return -ENOMEM;

	ret = dns_init(NULL);
	if (ret)
		return ret;

	ret = connman_notifier_register(&resolved_notifier);
	if (ret < 0)
		DBG("cannot register notifier");

	return 0;
}

void __connman_dnsproxy_cleanup(void)
{
	DBG("");

	connman_notifier_unregister(&resolved_notifier);

	if (update_interfaces_source) {
		/*
		 * It might be that we don't get to an idle loop anymore, so
		 * run the update function once more to clean up.
		 */
		 g_source_remove(update_interfaces_source);
		 update_systemd_resolved(NULL);
		 update_interfaces_source = 0;
	}

	if (interface_hash) {
		g_hash_table_destroy(interface_hash);
		interface_hash = NULL;
	}

	if (resolved_proxy) {
		g_dbus_proxy_unref(resolved_proxy);
		resolved_proxy = NULL;
	}

	if (client) {
		g_dbus_client_unref(client);
		client = NULL;
	}

	if (connection) {
		dbus_connection_unref(connection);
		connection = NULL;
	}

	dns_cleanup();
}
