/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2025  Jolla Mobile Ltd
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
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_link.h>
#include <string.h>
#include <stdlib.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

#include <gdbus.h>
#include <connman/ipaddress.h>

#include "connman.h"

struct connman_ipconfig {
	int refcount;
	int index;
	enum connman_ipconfig_type type;

	const struct connman_ipconfig_ops *ops;
	void *ops_data;

	enum connman_ipconfig_method method;
	enum connman_ipconfig_method saved_method;
	struct connman_ipaddress *address;
	struct connman_ipaddress *system;

	int ipv6_privacy_config;
	char *last_dhcp_address;
	char **last_dhcpv6_prefixes;
	char *dhcpv6_duid;

	bool ipv6_force_disabled;
};

struct connman_ipdevice {
	int index;
	unsigned short type;
	unsigned int flags;
	char *address;
	uint16_t mtu;
	struct connman_stats_data stats;

	GSList *address_list;
	char *ipv4_gateway;
	char *ipv6_gateway;

	char *pac;

	struct connman_ipconfig *config_ipv4;
	struct connman_ipconfig *config_ipv6;

	bool ipv6_enabled;
	int ipv6_privacy;
};

struct ipconfig_store {
	GKeyFile *file;
	const char *group;
	const char *prefix;
};

static GHashTable *ipdevice_hash = NULL;
static GList *ipconfig_list = NULL;
static bool is_ipv6_supported = false;

static void store_set_str(struct ipconfig_store *store,
			const char *key, const char *val)

{
	char *pk;

	if (!val || strlen(val) == 0)
		return;

	pk = g_strdup_printf("%s%s", store->prefix, key);
	g_key_file_set_string(store->file, store->group, pk, val);
	g_free(pk);
}

static char *store_get_str(struct ipconfig_store *store, const char *key)
{
	char *pk, *val;

	pk = g_strdup_printf("%s%s", store->prefix, key);
	val = g_key_file_get_string(store->file, store->group, pk, NULL);
	g_free(pk);

	return val;
}

static void store_set_strs(struct ipconfig_store *store,
			const char *key, char **val)
{
	guint len;
	char *pk;

	if (!val)
		return;

	len = g_strv_length(val);
	if (len == 0)
		return;

	pk = g_strdup_printf("%s%s", store->prefix, key);
	g_key_file_set_string_list(store->file, store->group,
				pk, (const gchar **)val, len);
	g_free(pk);
}

static char **store_get_strs(struct ipconfig_store *store, const char *key)
{
	gsize len;
	char *pk, **val;

	pk = g_strdup_printf("%s%s", store->prefix, key);
	val = g_key_file_get_string_list(store->file, store->group,
					pk, &len, NULL);
	g_free(pk);

	if (val && len == 0) {
		g_free(val);
		return NULL;
	}

	return val;
}

static void store_set_int(struct ipconfig_store *store,
			const char *key, int val)
{
	char *pk;

	if (val == 0)
		return;

	pk = g_strdup_printf("%s%s", store->prefix, key);
	g_key_file_set_integer(store->file, store->group, pk, val);
	g_free(pk);
}

static int store_get_int(struct ipconfig_store *store, const char *key)
{
	int val;
	char *pk;

	pk = g_strdup_printf("%s%s", store->prefix, key);
	val = g_key_file_get_integer(store->file, store->group, pk, 0);
	g_free(pk);

	return val;
}

void __connman_ipconfig_clear_address(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return;

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		break;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		connman_ipaddress_clear(ipconfig->address);
		break;
	}
}

static void free_address_list(struct connman_ipdevice *ipdevice)
{
	GSList *list;

	for (list = ipdevice->address_list; list; list = list->next) {
		struct connman_ipaddress *ipaddress = list->data;

		connman_ipaddress_free(ipaddress);
		list->data = NULL;
	}

	g_slist_free(ipdevice->address_list);
	ipdevice->address_list = NULL;
}

static struct connman_ipaddress *find_ipaddress(struct connman_ipdevice *ipdevice,
				unsigned char prefixlen, const char *local)
{
	GSList *list;

	for (list = ipdevice->address_list; list; list = list->next) {
		struct connman_ipaddress *ipaddress = list->data;

		if (g_strcmp0(ipaddress->local, local) == 0 &&
					ipaddress->prefixlen == prefixlen)
			return ipaddress;
	}

	return NULL;
}

const char *__connman_ipconfig_type2string(enum connman_ipconfig_type type)
{
	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		return "unknown";
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		return "IPv4";
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		return "IPv6";
	case CONNMAN_IPCONFIG_TYPE_ALL:
		return "IPv4 + IPv6";
	}

	return NULL;
}

static const char *type2str(unsigned short type)
{
	switch (type) {
	case ARPHRD_ETHER:
		return "ETHER";
	case ARPHRD_LOOPBACK:
		return "LOOPBACK";
	case ARPHRD_PPP:
		return "PPP";
	case ARPHRD_NONE:
		return "NONE";
	case ARPHRD_VOID:
		return "VOID";
	}

	return "";
}

static const char *scope2str(unsigned char scope)
{
	switch (scope) {
	case 0:
		return "UNIVERSE";
	case 253:
		return "LINK";
	}

	return "";
}

#define PROC_IPV4_CONF_PREFIX "/proc/sys/net/ipv4/conf"
#define PROC_IPV6_CONF_PREFIX "/proc/sys/net/ipv6/conf"

static int read_conf_value(const char *prefix, const char *ifname,
					const char *suffix, int *value)
{
	gchar *path;
	FILE *f;
	int err;

	path = g_build_filename(prefix, ifname ? ifname : "all", suffix, NULL);
	if (!path) {
		*value = -ENOMEM;
		return -ENOMEM;
	}

	errno = 0;
	f = fopen(path, "r");
	if (!f) {
		err = -errno;
	} else {
		errno = 0; /* Avoid stale errno values with fscanf */

		err = fscanf(f, "%d", value);
		if (err <= 0 && errno)
			*value = err = -errno;

		fclose(f);
	}

	if (err <= 0)
		connman_error("failed to read %s", path);

	g_free(path);

	return err;
}

static int read_ipv4_conf_value(const char *ifname, const char *suffix,
								int *value)
{
	return read_conf_value(PROC_IPV4_CONF_PREFIX, ifname, suffix, value);
}

static int read_ipv6_conf_value(const char *ifname, const char *suffix,
								int *value)
{
	return read_conf_value(PROC_IPV6_CONF_PREFIX, ifname, suffix, value);
}

static int write_conf_value(const char *prefix, const char *ifname,
					const char *suffix, int value) {
	gchar *path;
	FILE *f;
	int rval;

	path = g_build_filename(prefix, ifname ? ifname : "all", suffix, NULL);
	if (!path)
		return -ENOMEM;

	f = fopen(path, "r+");
	if (!f) {
		rval = -errno;
	} else {
		rval = fprintf(f, "%d", value);
		fclose(f);
	}

	if (rval <= 0)
		connman_error("failed to set %s value %d", path, value);

	g_free(path);

	return rval;
}

static int write_ipv4_conf_value(const char *ifname, const char *suffix,
								int value)
{
	return write_conf_value(PROC_IPV4_CONF_PREFIX, ifname, suffix, value);
}

static int write_ipv6_conf_value(const char *ifname, const char *suffix,
								int value)
{
	return write_conf_value(PROC_IPV6_CONF_PREFIX, ifname, suffix, value);
}

static bool get_ipv6_state(gchar *ifname)
{
	int disabled = 0;
	bool enabled = false;

	if (read_ipv6_conf_value(ifname, "disable_ipv6", &disabled) > 0)
		enabled = !disabled;

	return enabled;
}

static int set_ipv6_state(gchar *ifname, bool enable)
{
	int disabled = enable ? 0 : 1;

	DBG("%s %d", ifname, disabled);

	return write_ipv6_conf_value(ifname, "disable_ipv6", disabled);
}

static int get_ipv6_privacy(gchar *ifname)
{
	int value = 0;

	if (!ifname)
		return 0;

	if (read_ipv6_conf_value(ifname, "use_tempaddr", &value) < 0)
		value = 0;

	return value;
}

/* Enable the IPv6 privacy extension for stateless address autoconfiguration.
 * The privacy extension is described in RFC 3041 and RFC 4941
 */
static int set_ipv6_privacy(gchar *ifname, int value)
{
	if (!ifname)
		return -EINVAL;

	if (value < 0)
		value = 0;

	return write_ipv6_conf_value(ifname, "use_tempaddr", value);
}

static int set_ipv6_autoconf(gchar *ifname, bool enable)
{
	int value = enable ? 1 : 0;

	DBG("%s %d", ifname, enable);

	return write_ipv6_conf_value(ifname, "autoconf", value);
}

static int get_rp_filter(void)
{
	int value = 0;

	if (read_ipv4_conf_value(NULL, "rp_filter", &value) < 0)
		value = -EINVAL;

	return value;
}

static int set_rp_filter(int value)
{
	/* 0 = no validation, 1 = strict mode, 2 = loose mode */
	switch (value) {
	case -1:
		value = 0;
		/* fall through */
	case 0:
	case 1:
	case 2:
		break;
	default:
		return -EINVAL;
	}

	return write_ipv4_conf_value(NULL, "rp_filter", value);
}

static int set_ipv6_accept_ra(gchar *ifname, int value)
{
	switch (value) {
	case -1:
		value = 0;
		/* fall through */
	case 0:
	case 1:
	case 2:
		break;
	default:
		return -EINVAL;
	}

	return write_ipv6_conf_value(ifname, "accept_ra", value);
}

static int get_ipv6_accept_ra(gchar *ifname)
{
	int value = 0;

	if (read_ipv6_conf_value(ifname, "accept_ra", &value) < 0)
		value = -EINVAL;

	return value;
}

static int set_ipv6_ndproxy(gchar *ifname, bool enable)
{
	int value = enable ? 1 : 0;

	DBG("%s %d", ifname, value);

	return write_ipv6_conf_value(ifname, "proxy_ndp", value);
}

static int get_ipv6_ndproxy(gchar *ifname)
{
	int value = 0;

	if (read_ipv6_conf_value(ifname, "proxy_ndp", &value) < 0)
		value = -EINVAL;

	return value;
}

int __connman_ipconfig_set_rp_filter()
{
	int value;

	value = get_rp_filter();

	if (value < 0)
		return value;

	set_rp_filter(2);

	DBG("rp_filter set to 2 (loose mode routing), "
			"old value was %d", value);

	return value;
}

void __connman_ipconfig_unset_rp_filter(int old_value)
{
	set_rp_filter(old_value);

	DBG("rp_filter restored to %d", old_value);
}

bool __connman_ipconfig_ipv6_privacy_enabled(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return false;

	return ipconfig->ipv6_privacy_config == 0 ? FALSE : TRUE;
}

bool __connman_ipconfig_ipv6_is_enabled(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;
	char *ifname;
	bool ret;

	if (!ipconfig)
		return false;

	/*
	 * Return forced value since kernel can enable LL address for IPv6
	 * for handling ICMPv6.
	 */
	if (ipconfig->ipv6_force_disabled)
		return false;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (!ipdevice)
		return false;

	ifname = connman_inet_ifname(ipconfig->index);
	ret = get_ipv6_state(ifname);
	g_free(ifname);

	return ret;
}

void __connman_ipconfig_ipv6_set_force_disabled(
					struct connman_ipconfig *ipconfig,
					bool force_disabled)
{
	if (!ipconfig || ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV6)
		return;

	ipconfig->ipv6_force_disabled = force_disabled;
}

bool __connman_ipconfig_ipv6_get_force_disabled(
					struct connman_ipconfig *ipconfig)
{
	if (!ipconfig || ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV6)
		return false;

	return ipconfig->ipv6_force_disabled;
}

static void free_ipdevice(gpointer data)
{
	struct connman_ipdevice *ipdevice = data;
	char *ifname = connman_inet_ifname(ipdevice->index);

	DBG("%s {remove} index %d", ifname, ipdevice->index);

	if (ipdevice->config_ipv4) {
		__connman_ipconfig_unref(ipdevice->config_ipv4);
		ipdevice->config_ipv4 = NULL;
	}

	if (ipdevice->config_ipv6) {
		__connman_ipconfig_unref(ipdevice->config_ipv6);
		ipdevice->config_ipv6 = NULL;
	}

	free_address_list(ipdevice);
	g_free(ipdevice->ipv4_gateway);
	g_free(ipdevice->ipv6_gateway);
	g_free(ipdevice->pac);

	g_free(ipdevice->address);

	if (ifname) {
		set_ipv6_state(ifname, ipdevice->ipv6_enabled);
		set_ipv6_privacy(ifname, ipdevice->ipv6_privacy);
	}

	g_free(ifname);
	g_free(ipdevice);
}

static void update_stats(struct connman_ipdevice *ipdevice,
            const char *ifname, struct rtnl_link_stats64 *stats)
{
	struct connman_service *service;
        struct connman_network *network;
        int network_index;

	ipdevice->stats.rx_packets = stats->rx_packets;
	ipdevice->stats.tx_packets = stats->tx_packets;
	ipdevice->stats.rx_bytes = stats->rx_bytes;
	ipdevice->stats.tx_bytes = stats->tx_bytes;
	ipdevice->stats.rx_errors = stats->rx_errors;
	ipdevice->stats.tx_errors = stats->tx_errors;
	ipdevice->stats.rx_dropped = stats->rx_dropped;
	ipdevice->stats.tx_dropped = stats->tx_dropped;

	if (stats->rx_packets == 0 && stats->tx_packets == 0)
		return;

	DBG("%s {RX} %llu packets %llu bytes", ifname,
					stats->rx_packets, stats->rx_bytes);
	DBG("%s {TX} %llu packets %llu bytes", ifname,
					stats->tx_packets, stats->tx_bytes);

	if (!ipdevice->config_ipv4 && !ipdevice->config_ipv6)
		return;

	service = __connman_service_lookup_from_index(ipdevice->index);

	DBG("service %p", service);

	if (!service)
		return;

        network = __connman_service_get_network(service);
        if (!network)
            return;

        network_index = connman_network_get_index(network);
        if (network_index != ipdevice->index) {
		DBG("ignoring interface %d (%s), expecting %d",
			ipdevice->index, ifname, network_index);
		return;
        }

	__connman_service_notify(service, &ipdevice->stats);
}

gboolean __connman_ipconfig_get_stats(struct connman_ipconfig *ipconfig,
				struct connman_stats_data *stats)
{
	struct connman_ipdevice *ipdevice;

	if (!ipconfig || ipconfig->index < 0)
		return false;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (!ipdevice)
		return false;

	*stats = ipdevice->stats;
	return true;
}

void __connman_ipconfig_newlink(int index, unsigned short type,
				unsigned int flags, const char *address,
							unsigned short mtu,
						struct rtnl_link_stats64 *stats)
{
	struct connman_ipdevice *ipdevice;
	GList *list, *ipconfig_copy;
	GString *str;
	bool up = false, down = false;
	bool lower_up = false, lower_down = false;
	char *ifname;

	DBG("index %d", index);

	if (type == ARPHRD_LOOPBACK)
		return;

	ifname = connman_inet_ifname(index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice)
		goto update;

	ipdevice = g_try_new0(struct connman_ipdevice, 1);
	if (!ipdevice)
		goto out;

	ipdevice->index = index;
	ipdevice->type = type;

	ipdevice->ipv6_enabled = get_ipv6_state(ifname);
	ipdevice->ipv6_privacy = get_ipv6_privacy(ifname);

	ipdevice->address = g_strdup(address);

	g_hash_table_insert(ipdevice_hash, GINT_TO_POINTER(index), ipdevice);

	DBG("%s {create} index %d type %d <%s>", ifname,
						index, type, type2str(type));

update:
	ipdevice->mtu = mtu;

	update_stats(ipdevice, ifname, stats);

	if (flags == ipdevice->flags)
		goto out;

	if ((ipdevice->flags & IFF_UP) != (flags & IFF_UP)) {
		if (flags & IFF_UP)
			up = true;
		else
			down = true;
	}

	if ((ipdevice->flags & (IFF_RUNNING | IFF_LOWER_UP)) !=
				(flags & (IFF_RUNNING | IFF_LOWER_UP))) {
		if ((flags & (IFF_RUNNING | IFF_LOWER_UP)) ==
					(IFF_RUNNING | IFF_LOWER_UP))
			lower_up = true;
		else if ((flags & (IFF_RUNNING | IFF_LOWER_UP)) == 0)
			lower_down = true;
	}

	ipdevice->flags = flags;

	str = g_string_new(NULL);
	if (!str)
		goto out;

	if (flags & IFF_UP)
		g_string_append(str, "UP");
	else
		g_string_append(str, "DOWN");

	if (flags & IFF_RUNNING)
		g_string_append(str, ",RUNNING");

	if (flags & IFF_LOWER_UP)
		g_string_append(str, ",LOWER_UP");

	DBG("%s {update} flags %u <%s>", ifname, flags, str->str);

	g_string_free(str, TRUE);

	ipconfig_copy = g_list_copy(ipconfig_list);
	for (list = g_list_first(ipconfig_copy); list;
						list = g_list_next(list)) {
		struct connman_ipconfig *ipconfig = list->data;

		if (index != ipconfig->index)
			continue;

		if (!ipconfig->ops)
			continue;

		if (up && ipconfig->ops->up)
			ipconfig->ops->up(ipconfig, ifname);
		if (lower_up && ipconfig->ops->lower_up)
			ipconfig->ops->lower_up(ipconfig, ifname);

		if (lower_down && ipconfig->ops->lower_down)
			ipconfig->ops->lower_down(ipconfig, ifname);
		if (down && ipconfig->ops->down)
			ipconfig->ops->down(ipconfig, ifname);
	}
	g_list_free(ipconfig_copy);

out:
	g_free(ifname);
}

void __connman_ipconfig_dellink(int index, struct rtnl_link_stats64 *stats)
{
	struct connman_ipdevice *ipdevice;
	GList *list;
	char *ifname;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (!ipdevice)
		return;

	ifname = connman_inet_ifname(index);

	update_stats(ipdevice, ifname, stats);

	for (list = g_list_first(ipconfig_list); list;
						list = g_list_next(list)) {
		struct connman_ipconfig *ipconfig = list->data;

		if (index != ipconfig->index)
			continue;

		ipconfig->index = -1;

		if (!ipconfig->ops)
			continue;

		if (ipconfig->ops->lower_down)
			ipconfig->ops->lower_down(ipconfig, ifname);
		if (ipconfig->ops->down)
			ipconfig->ops->down(ipconfig, ifname);
	}

	g_free(ifname);

	g_hash_table_remove(ipdevice_hash, GINT_TO_POINTER(index));
}

static inline gint check_duplicate_address(gconstpointer a, gconstpointer b)
{
	const struct connman_ipaddress *addr1 = a;
	const struct connman_ipaddress *addr2 = b;

	if (addr1->prefixlen != addr2->prefixlen)
		return addr2->prefixlen - addr1->prefixlen;

	return g_strcmp0(addr1->local, addr2->local);
}


static bool is_index_p2p_service(int index)
{
	struct connman_service *service;
	enum connman_service_type type;

	service = __connman_service_lookup_from_index(index);
	if (!service)
		return false;

	type = connman_service_get_type(service);
	switch (type) {
	case CONNMAN_SERVICE_TYPE_P2P:
	case CONNMAN_SERVICE_TYPE_VPN:
		return true;
	default:
		return false;
	}
}

int __connman_ipconfig_newaddr(int index, int family, const char *label,
				unsigned char prefixlen, const char *address)
{
	struct connman_ipdevice *ipdevice;
	struct connman_ipaddress *ipaddress;
	enum connman_ipconfig_type type;
	GList *list;
	char *ifname;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (!ipdevice)
		return -ENXIO;

	ipaddress = connman_ipaddress_alloc(family);
	if (!ipaddress)
		return -ENOMEM;

	ipaddress->prefixlen = prefixlen;
	ipaddress->local = g_strdup(address);

	if (is_index_p2p_service(index))
		connman_ipaddress_set_p2p(ipaddress, true);

	if (g_slist_find_custom(ipdevice->address_list, ipaddress,
					check_duplicate_address)) {
		connman_ipaddress_free(ipaddress);
		return -EALREADY;
	}

	if (family == AF_INET)
		type = CONNMAN_IPCONFIG_TYPE_IPV4;
	else if (family == AF_INET6)
		type = CONNMAN_IPCONFIG_TYPE_IPV6;
	else
		return -EINVAL;

	ipdevice->address_list = g_slist_prepend(ipdevice->address_list,
								ipaddress);

	ifname = connman_inet_ifname(index);
	DBG("%s {add} address %s/%u label %s family %d",
		ifname, address, prefixlen, label, family);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		__connman_ippool_newaddr(index, address, prefixlen);

	if (ipdevice->config_ipv4 && family == AF_INET)
		connman_ipaddress_copy_address(ipdevice->config_ipv4->system,
					ipaddress);

	else if (ipdevice->config_ipv6 && family == AF_INET6)
		connman_ipaddress_copy_address(ipdevice->config_ipv6->system,
					ipaddress);
	else
		goto out;

	if ((ipdevice->flags & (IFF_RUNNING | IFF_LOWER_UP)) != (IFF_RUNNING | IFF_LOWER_UP))
		goto out;

	for (list = g_list_first(ipconfig_list); list;
						list = g_list_next(list)) {
		struct connman_ipconfig *ipconfig = list->data;

		if (index != ipconfig->index)
			continue;

		if (type != ipconfig->type)
			continue;

		if (!ipconfig->ops)
			continue;

		if (ipconfig->ops->ip_bound)
			ipconfig->ops->ip_bound(ipconfig, ifname);
	}

out:
	g_free(ifname);
	return 0;
}

void __connman_ipconfig_deladdr(int index, int family, const char *label,
				unsigned char prefixlen, const char *address)
{
	struct connman_ipdevice *ipdevice;
	struct connman_ipaddress *ipaddress;
	enum connman_ipconfig_type type;
	GList *list;
	char *ifname;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (!ipdevice)
		return;

	ipaddress = find_ipaddress(ipdevice, prefixlen, address);
	if (!ipaddress)
		return;

	if (family == AF_INET)
		type = CONNMAN_IPCONFIG_TYPE_IPV4;
	else if (family == AF_INET6)
		type = CONNMAN_IPCONFIG_TYPE_IPV6;
	else
		return;

	ipdevice->address_list = g_slist_remove(ipdevice->address_list,
								ipaddress);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		__connman_ippool_deladdr(index, address, prefixlen);

	connman_ipaddress_clear(ipaddress);
	g_free(ipaddress);

	ifname = connman_inet_ifname(index);
	DBG("%s {del} address %s/%u label %s", ifname,
						address, prefixlen, label);

	if ((ipdevice->flags & (IFF_RUNNING | IFF_LOWER_UP)) != (IFF_RUNNING | IFF_LOWER_UP))
		goto out;

	if (g_slist_length(ipdevice->address_list) > 0)
		goto out;

	for (list = g_list_first(ipconfig_list); list;
						list = g_list_next(list)) {
		struct connman_ipconfig *ipconfig = list->data;

		if (index != ipconfig->index)
			continue;

		if (type != ipconfig->type)
			continue;

		if (!ipconfig->ops)
			continue;

		if (ipconfig->ops->ip_release)
			ipconfig->ops->ip_release(ipconfig, ifname);
	}

out:
	g_free(ifname);
}

void __connman_ipconfig_newroute(int index, int family, unsigned char scope,
					const char *dst, const char *gateway)
{
	struct connman_ipdevice *ipdevice;
	char *ifname;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (!ipdevice)
		return;

	ifname = connman_inet_ifname(index);

	if (scope == 0 && (g_strcmp0(dst, "0.0.0.0") == 0 ||
						g_strcmp0(dst, "::") == 0)) {
		GList *config_list;
		enum connman_ipconfig_type type;

		if (family == AF_INET6) {
			type = CONNMAN_IPCONFIG_TYPE_IPV6;
			g_free(ipdevice->ipv6_gateway);
			ipdevice->ipv6_gateway = g_strdup(gateway);

			if (ipdevice->config_ipv6 &&
				ipdevice->config_ipv6->system) {
				g_free(ipdevice->config_ipv6->system->gateway);
				ipdevice->config_ipv6->system->gateway =
					g_strdup(gateway);
			}
		} else if (family == AF_INET) {
			type = CONNMAN_IPCONFIG_TYPE_IPV4;
			g_free(ipdevice->ipv4_gateway);
			ipdevice->ipv4_gateway = g_strdup(gateway);

			if (ipdevice->config_ipv4 &&
				ipdevice->config_ipv4->system) {
				g_free(ipdevice->config_ipv4->system->gateway);
				ipdevice->config_ipv4->system->gateway =
					g_strdup(gateway);
			}
		} else
			goto out;

		for (config_list = g_list_first(ipconfig_list); config_list;
					config_list = g_list_next(config_list)) {
			struct connman_ipconfig *ipconfig = config_list->data;

			if (index != ipconfig->index)
				continue;

			if (type != ipconfig->type)
				continue;

			if (!ipconfig->ops)
				continue;

			if (ipconfig->ops->route_set)
				ipconfig->ops->route_set(ipconfig, ifname);
		}
	}

	DBG("%s {add} route %s gw %s scope %u <%s>",
		ifname, dst, gateway, scope, scope2str(scope));

out:
	g_free(ifname);
}

void __connman_ipconfig_delroute(int index, int family, unsigned char scope,
					const char *dst, const char *gateway)
{
	struct connman_ipdevice *ipdevice;
	char *ifname;

	DBG("index %d", index);

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (!ipdevice)
		return;

	ifname = connman_inet_ifname(index);

	if (scope == 0 && (g_strcmp0(dst, "0.0.0.0") == 0 ||
						g_strcmp0(dst, "::") == 0)) {
		GList *config_list;
		enum connman_ipconfig_type type;

		if (family == AF_INET6) {
			type = CONNMAN_IPCONFIG_TYPE_IPV6;
			g_free(ipdevice->ipv6_gateway);
			ipdevice->ipv6_gateway = NULL;

			if (ipdevice->config_ipv6 &&
				ipdevice->config_ipv6->system) {
				g_free(ipdevice->config_ipv6->system->gateway);
				ipdevice->config_ipv6->system->gateway = NULL;
			}
		} else if (family == AF_INET) {
			type = CONNMAN_IPCONFIG_TYPE_IPV4;
			g_free(ipdevice->ipv4_gateway);
			ipdevice->ipv4_gateway = NULL;

			if (ipdevice->config_ipv4 &&
				ipdevice->config_ipv4->system) {
				g_free(ipdevice->config_ipv4->system->gateway);
				ipdevice->config_ipv4->system->gateway = NULL;
			}
		} else
			goto out;

		for (config_list = g_list_first(ipconfig_list); config_list;
					config_list = g_list_next(config_list)) {
			struct connman_ipconfig *ipconfig = config_list->data;

			if (index != ipconfig->index)
				continue;

			if (type != ipconfig->type)
				continue;

			if (!ipconfig->ops)
				continue;

			if (ipconfig->ops->route_unset)
				ipconfig->ops->route_unset(ipconfig, ifname);
		}
	}

	DBG("%s {del} route %s gw %s scope %u <%s>",
		ifname, dst, gateway, scope, scope2str(scope));

out:
	g_free(ifname);
}

void __connman_ipconfig_foreach(void (*function) (int index, void *user_data),
							void *user_data)
{
	GList *list, *keys;

	keys = g_hash_table_get_keys(ipdevice_hash);
	if (!keys)
		return;

	for (list = g_list_first(keys); list; list = g_list_next(list)) {
		int index = GPOINTER_TO_INT(list->data);

		function(index, user_data);
	}

	g_list_free(keys);
}

enum connman_ipconfig_type __connman_ipconfig_get_config_type(
					struct connman_ipconfig *ipconfig)
{
	return ipconfig ? ipconfig->type : CONNMAN_IPCONFIG_TYPE_UNKNOWN;
}

enum connman_ipconfig_type connman_ipconfig_get_config_type(
					struct connman_ipconfig *ipconfig)
{
	return __connman_ipconfig_get_config_type(ipconfig);
}

unsigned short __connman_ipconfig_get_type_from_index(int index)
{
	struct connman_ipdevice *ipdevice;

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (!ipdevice)
		return ARPHRD_VOID;

	return ipdevice->type;
}

unsigned int __connman_ipconfig_get_flags_from_index(int index)
{
	struct connman_ipdevice *ipdevice;

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (!ipdevice)
		return 0;

	return ipdevice->flags;
}

const char *__connman_ipconfig_get_gateway_from_index(int index,
					enum connman_ipconfig_type type)
{
	struct connman_ipdevice *ipdevice;

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (!ipdevice)
		return NULL;

	if (type != CONNMAN_IPCONFIG_TYPE_IPV6) {
		if (ipdevice->ipv4_gateway)
			return ipdevice->ipv4_gateway;

		if (ipdevice->config_ipv4 &&
				ipdevice->config_ipv4->address)
			return ipdevice->config_ipv4->address->gateway;
	}

	if (type != CONNMAN_IPCONFIG_TYPE_IPV4) {
		if (ipdevice->ipv6_gateway)
			return ipdevice->ipv6_gateway;

		if (ipdevice->config_ipv6 &&
				ipdevice->config_ipv6->address)
			return ipdevice->config_ipv6->address->gateway;
	}

	return NULL;
}

const char *connman_ipconfig_get_gateway_from_index(int index,
					enum connman_ipconfig_type type)
{
	return __connman_ipconfig_get_gateway_from_index(index, type);
}

struct connman_ipaddress *connman_ipconfig_get_ipaddress(
					struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return NULL;
	
	return ipconfig->address;
}

bool connman_ipconfig_has_ipaddress_set(struct connman_ipconfig *ipconfig)
{
	struct connman_ipaddress *ipaddress;
	const char *address;
	unsigned char prefixlen;
	int err;

	DBG("ipconfig %p", ipconfig);

	/* Returns NULL if ipconfig is NULL */
	ipaddress = connman_ipconfig_get_ipaddress(ipconfig);

	/* Returns error only when ipaddress is NULL, i.e., NULL safe */
	err = connman_ipaddress_get_ip(ipaddress, &address, &prefixlen);
	if (err)
		return false;

	if (!address)
		return false;

	switch (ipconfig->method) {
	/* The address may still be there but the method dictates here */
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		return false;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		break;
	}

	DBG("IP address %s set", address);

	return true;
}

void __connman_ipconfig_set_index(struct connman_ipconfig *ipconfig, int index)
{
	ipconfig->index = index;
}

const char *__connman_ipconfig_get_local(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig->address)
		return NULL;

	return ipconfig->address->local;
}

void __connman_ipconfig_set_local(struct connman_ipconfig *ipconfig,
					const char *address)
{
	if (!ipconfig->address)
		return;

	g_free(ipconfig->address->local);
	ipconfig->address->local = g_strdup(address);
}

const char *__connman_ipconfig_get_peer(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig->address)
		return NULL;

	return ipconfig->address->peer;
}

void __connman_ipconfig_set_peer(struct connman_ipconfig *ipconfig,
					const char *address)
{
	if (!ipconfig->address)
		return;

	g_free(ipconfig->address->peer);
	ipconfig->address->peer = g_strdup(address);
}

const char *__connman_ipconfig_get_broadcast(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig->address)
		return NULL;

	return ipconfig->address->broadcast;
}

void __connman_ipconfig_set_broadcast(struct connman_ipconfig *ipconfig,
					const char *broadcast)
{
	if (!ipconfig->address)
		return;

	g_free(ipconfig->address->broadcast);
	ipconfig->address->broadcast = g_strdup(broadcast);
}

const char *__connman_ipconfig_get_gateway(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig->address)
		return NULL;

	return ipconfig->address->gateway;
}

void __connman_ipconfig_set_gateway(struct connman_ipconfig *ipconfig,
					const char *gateway)
{
	DBG("");

	if (!ipconfig->address)
		return;
	g_free(ipconfig->address->gateway);
	ipconfig->address->gateway = g_strdup(gateway);
}

int __connman_ipconfig_gateway_add(struct connman_ipconfig *ipconfig)
{
	struct connman_service *service;

	DBG("");

	if (!ipconfig->address)
		return -EINVAL;

	service = __connman_service_lookup_from_index(ipconfig->index);
	if (!service)
		return -EINVAL;

	DBG("type %d gw %s peer %s", ipconfig->type,
		ipconfig->address->gateway, ipconfig->address->peer);

	if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6 ||
				ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV4)
		return __connman_connection_gateway_add(service,
						ipconfig->address->gateway,
						ipconfig->type,
						ipconfig->address->peer);

	return 0;
}

void __connman_ipconfig_gateway_remove(struct connman_ipconfig *ipconfig)
{
	struct connman_service *service;

	DBG("");

	service = __connman_service_lookup_from_index(ipconfig->index);
	if (service)
		__connman_connection_gateway_remove(service, ipconfig->type);
}

unsigned char __connman_ipconfig_get_prefixlen(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig->address)
		return 0;

	return ipconfig->address->prefixlen;
}

void __connman_ipconfig_set_prefixlen(struct connman_ipconfig *ipconfig,
					unsigned char prefixlen)
{
	if (!ipconfig->address)
		return;

	ipconfig->address->prefixlen = prefixlen;
}

static void ipconfig_set_p2p(int index, struct connman_ipconfig *ipconfig)
{
	if (!is_index_p2p_service(index))
		return;

	connman_ipaddress_set_p2p(ipconfig->address, true);
	connman_ipaddress_set_p2p(ipconfig->system, true);
}

static struct connman_ipconfig *create_ipv6config(int index)
{
	struct connman_ipconfig *ipv6config;
	struct connman_ipdevice *ipdevice;

	ipv6config = g_try_new0(struct connman_ipconfig, 1);
	if (!ipv6config)
		return NULL;

	ipv6config->refcount = 1;

	ipv6config->index = index;
	ipv6config->type = CONNMAN_IPCONFIG_TYPE_IPV6;

	if (!is_ipv6_supported)
		ipv6config->method = CONNMAN_IPCONFIG_METHOD_OFF;
	else
		ipv6config->method = CONNMAN_IPCONFIG_METHOD_AUTO;

	ipv6config->saved_method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;

	ipdevice = g_hash_table_lookup(ipdevice_hash, GINT_TO_POINTER(index));
	if (ipdevice)
		ipv6config->ipv6_privacy_config = ipdevice->ipv6_privacy;

	ipv6config->address = connman_ipaddress_alloc(AF_INET6);
	if (!ipv6config->address) {
		g_free(ipv6config);
		return NULL;
	}

	ipv6config->system = connman_ipaddress_alloc(AF_INET6);

	ipconfig_set_p2p(index, ipv6config);

	DBG("ipconfig %p method %s", ipv6config,
		__connman_ipconfig_method2string(ipv6config->method));

	return ipv6config;
}

/**
 * connman_ipconfig_create:
 *
 * Allocate a new ipconfig structure.
 *
 * Returns: a newly-allocated #connman_ipconfig structure
 */
struct connman_ipconfig *__connman_ipconfig_create(int index,
					enum connman_ipconfig_type type)
{
	struct connman_ipconfig *ipconfig;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		return create_ipv6config(index);

	ipconfig = g_try_new0(struct connman_ipconfig, 1);
	if (!ipconfig)
		return NULL;

	ipconfig->refcount = 1;

	ipconfig->index = index;
	ipconfig->type = CONNMAN_IPCONFIG_TYPE_IPV4;

	ipconfig->address = connman_ipaddress_alloc(AF_INET);
	if (!ipconfig->address) {
		g_free(ipconfig);
		return NULL;
	}

	ipconfig->system = connman_ipaddress_alloc(AF_INET);

	ipconfig_set_p2p(index, ipconfig);

	DBG("ipconfig %p", ipconfig);

	return ipconfig;
}


/**
 * connman_ipconfig_ref:
 * @ipconfig: ipconfig structure
 *
 * Increase reference counter of ipconfig
 */
struct connman_ipconfig *
__connman_ipconfig_ref_debug(struct connman_ipconfig *ipconfig,
				const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", ipconfig, ipconfig->refcount + 1,
		file, line, caller);

	__sync_fetch_and_add(&ipconfig->refcount, 1);

	return ipconfig;
}

/**
 * connman_ipconfig_unref:
 * @ipconfig: ipconfig structure
 *
 * Decrease reference counter of ipconfig
 */
void __connman_ipconfig_unref_debug(struct connman_ipconfig *ipconfig,
				const char *file, int line, const char *caller)
{
	if (!ipconfig)
		return;

	DBG("%p ref %d by %s:%d:%s()", ipconfig, ipconfig->refcount - 1,
		file, line, caller);

	if (__sync_fetch_and_sub(&ipconfig->refcount, 1) != 1)
		return;

	if (__connman_ipconfig_disable(ipconfig) < 0)
		ipconfig_list = g_list_remove(ipconfig_list, ipconfig);

	__connman_ipconfig_set_ops(ipconfig, NULL);

	connman_ipaddress_free(ipconfig->system);
	connman_ipaddress_free(ipconfig->address);
	g_free(ipconfig->last_dhcp_address);
	g_strfreev(ipconfig->last_dhcpv6_prefixes);
	g_free(ipconfig->dhcpv6_duid);
	g_free(ipconfig);
}

/**
 * connman_ipconfig_get_data:
 * @ipconfig: ipconfig structure
 *
 * Get private data pointer
 */
void *__connman_ipconfig_get_data(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return NULL;

	return ipconfig->ops_data;
}

/**
 * connman_ipconfig_set_data:
 * @ipconfig: ipconfig structure
 * @data: data pointer
 *
 * Set private data pointer
 */
void __connman_ipconfig_set_data(struct connman_ipconfig *ipconfig, void *data)
{
	ipconfig->ops_data = data;
}

/**
 * connman_ipconfig_get_index:
 * @ipconfig: ipconfig structure
 *
 * Get interface index
 */
int __connman_ipconfig_get_index(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return -1;

	return ipconfig->index;
}

int connman_ipconfig_get_index(struct connman_ipconfig *ipconfig)
{
	return __connman_ipconfig_get_index(ipconfig);
}

/**
 * connman_ipconfig_set_ops:
 * @ipconfig: ipconfig structure
 * @ops: operation callbacks
 *
 * Set the operation callbacks
 */
void __connman_ipconfig_set_ops(struct connman_ipconfig *ipconfig,
				const struct connman_ipconfig_ops *ops)
{
	ipconfig->ops = ops;
}

/**
 * connman_ipconfig_set_method:
 * @ipconfig: ipconfig structure
 * @method: configuration method
 *
 * Set the configuration method
 */
int __connman_ipconfig_set_method(struct connman_ipconfig *ipconfig,
					enum connman_ipconfig_method method)
{
	ipconfig->method = method;

	return 0;
}

enum connman_ipconfig_method __connman_ipconfig_get_method(
				struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return CONNMAN_IPCONFIG_METHOD_UNKNOWN;

	return ipconfig->method;
}

void __connman_ipconfig_ipv6_method_save(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig || ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV6)
		return;

	DBG("%p method %d", ipconfig, ipconfig->method);

	ipconfig->saved_method = ipconfig->method;
}

void __connman_ipconfig_ipv6_method_restore(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig || ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV6)
		return;

	/* If not previously set, default to AUTO */
	if (ipconfig->saved_method == CONNMAN_IPCONFIG_METHOD_UNKNOWN)
		ipconfig->method = CONNMAN_IPCONFIG_METHOD_AUTO;
	else
		ipconfig->method = ipconfig->saved_method;

	DBG("%p saved method %d set method %d", ipconfig,
				ipconfig->saved_method, ipconfig->method);

	ipconfig->saved_method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
}

int __connman_ipconfig_address_add(struct connman_ipconfig *ipconfig)
{
	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		break;
	case CONNMAN_IPCONFIG_METHOD_AUTO:
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV4)
			return connman_inet_set_address(ipconfig->index,
							ipconfig->address);
		else if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6)
			return connman_inet_set_ipv6_address(
					ipconfig->index, ipconfig->address);
	}

	return 0;
}

int __connman_ipconfig_address_remove(struct connman_ipconfig *ipconfig)
{
	int err;

	if (!ipconfig)
		return 0;

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		break;
	case CONNMAN_IPCONFIG_METHOD_AUTO:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		err = __connman_ipconfig_address_unset(ipconfig);
		connman_ipaddress_clear(ipconfig->address);

		return err;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		return __connman_ipconfig_address_unset(ipconfig);
	}

	return 0;
}

int __connman_ipconfig_address_unset(struct connman_ipconfig *ipconfig)
{
	int err;

	if (!ipconfig)
		return 0;

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		break;
	case CONNMAN_IPCONFIG_METHOD_AUTO:
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV4)
			err = connman_inet_clear_address(ipconfig->index,
							ipconfig->address);
		else if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6)
			err = connman_inet_clear_ipv6_address(ipconfig->index,
							ipconfig->address);
		else
			err = -EINVAL;

		return err;
	}

	return 0;
}

int __connman_ipconfig_set_proxy_autoconfig(struct connman_ipconfig *ipconfig,
                                                        const char *url)
{
	struct connman_ipdevice *ipdevice;

	if (!ipconfig || ipconfig->index < 0)
		return -ENODEV;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (!ipdevice)
		return -ENXIO;

	g_free(ipdevice->pac);
	ipdevice->pac = g_strdup(url);

	return 0;
}

const char *__connman_ipconfig_get_proxy_autoconfig(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;

	if (!ipconfig || ipconfig->index < 0)
		return NULL;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (!ipdevice)
		return NULL;

	return ipdevice->pac;
}

void __connman_ipconfig_set_dhcp_address(struct connman_ipconfig *ipconfig,
					const char *address)
{
	if (!ipconfig)
		return;

	g_free(ipconfig->last_dhcp_address);
	ipconfig->last_dhcp_address = g_strdup(address);
}

char *__connman_ipconfig_get_dhcp_address(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return NULL;

	return ipconfig->last_dhcp_address;
}

void __connman_ipconfig_set_dhcpv6_prefixes(struct connman_ipconfig *ipconfig,
					char **prefixes)
{
	if (!ipconfig)
		return;

	g_strfreev(ipconfig->last_dhcpv6_prefixes);
	ipconfig->last_dhcpv6_prefixes = prefixes;
}

char **__connman_ipconfig_get_dhcpv6_prefixes(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return NULL;

	return ipconfig->last_dhcpv6_prefixes;
}

void __connman_ipconfig_set_dhcpv6_duid(struct connman_ipconfig *ipconfig,
						const char *dhcpv6_duid)
{
	if (!ipconfig)
		return;

	g_free(ipconfig->dhcpv6_duid);
	ipconfig->dhcpv6_duid = g_strdup(dhcpv6_duid);
}

char *__connman_ipconfig_get_dhcpv6_duid(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return NULL;

	return ipconfig->dhcpv6_duid;
}

static int disable_ipv6(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;
	char *ifname;

	DBG("");

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (!ipdevice)
		return -EINVAL;

	DBG("%p force_disabled %s", ipconfig,
				ipconfig->ipv6_force_disabled ? "yes" : "no");

	ifname = connman_inet_ifname(ipconfig->index);

	if (!ifname)
		return -ENOENT;

	set_ipv6_state(ifname, false);
	set_ipv6_autoconf(ifname, false);

	g_free(ifname);

	return 0;
}

static int enable_ipv6(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;
	char *ifname;

	DBG("");

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (!ipdevice)
		return -EINVAL;

	DBG("IPv6 %s %p force_disabled %s", is_ipv6_supported ? "on" : "off",
				ipconfig,
				ipconfig->ipv6_force_disabled ? "yes" : "no");

	if (!is_ipv6_supported || ipconfig->ipv6_force_disabled)
		return -EOPNOTSUPP;

	ifname = connman_inet_ifname(ipconfig->index);

	if (!ifname)
		return -ENOENT;

	if (ipconfig->method == CONNMAN_IPCONFIG_METHOD_AUTO)
		set_ipv6_privacy(ifname, ipconfig->ipv6_privacy_config);

	set_ipv6_state(ifname, true);
	set_ipv6_autoconf(ifname, true);

	g_free(ifname);

	return 0;
}

int __connman_ipconfig_enable_ipv6(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig || ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV6)
		return -EINVAL;

	return enable_ipv6(ipconfig);
}

void __connman_ipconfig_disable_ipv6(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig || ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV6)
		return;

	disable_ipv6(ipconfig);
}

int __connman_ipconfig_set_ipv6_support(bool enable)
{
	is_ipv6_supported = enable ? connman_inet_is_ipv6_supported() : false;

	return 0;
}

bool __connman_ipconfig_get_ipv6_support()
{
	return is_ipv6_supported;
}

int __connman_ipconfig_ipv6_get_accept_ra(struct connman_ipconfig *ipconfig)
{
	char *ifname;
	int value;

	if (!ipconfig || ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV6)
		return -EINVAL;

	ifname = connman_inet_ifname(ipconfig->index);
	if (!ifname)
		return -ENOENT;

	value = get_ipv6_accept_ra(ifname);
	g_free(ifname);

	return value;
}

int __connman_ipconfig_ipv6_set_accept_ra(struct connman_ipconfig *ipconfig,
								int value)
{
	char *ifname;
	int err = 0;

	if (!ipconfig || ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV6)
		return -EINVAL;

	ifname = connman_inet_ifname(ipconfig->index);
	if (!ifname)
		return -ENOENT;

	/* Returns the amount of chars written */
	if (set_ipv6_accept_ra(ifname, value) != 1)
		err = -EPERM;

	g_free(ifname);

	return err;
}

bool __connman_ipconfig_ipv6_get_ndproxy(struct connman_ipconfig *ipconfig)
{
	char *ifname;
	int value;

	if (!ipconfig)
		return false;

	ifname = connman_inet_ifname(ipconfig->index);
	if (!ifname)
		return false;

	value = get_ipv6_ndproxy(ifname);
	g_free(ifname);

	return value == 1 ? true : false;
}

int __connman_ipconfig_ipv6_set_ndproxy(struct connman_ipconfig *ipconfig,
								bool enable)
{
	char *ifname;
	int err = 0;

	if (!ipconfig)
		return -EINVAL;

	ifname = connman_inet_ifname(ipconfig->index);
	if (!ifname)
		return -ENOENT;

	if (set_ipv6_ndproxy(ifname, enable) != 1)
		err = -EPERM;

	g_free(ifname);

	return err;
}


bool __connman_ipconfig_is_usable(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return false;

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		return false;
	case CONNMAN_IPCONFIG_METHOD_AUTO:
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		break;
	}

	return true;
}

bool __connman_ipconfig_is_configured(struct connman_ipconfig *ipconfig)
{
	if (!ipconfig)
		return false;

	DBG("%p", ipconfig);

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		return false;
	case CONNMAN_IPCONFIG_METHOD_AUTO:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		break;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		if (!__connman_ipconfig_get_local(ipconfig))
			return false;

		break;
	}

	return true;
}

int __connman_ipconfig_enable(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;
	bool up = false, down = false;
	bool lower_up = false, lower_down = false;
	enum connman_ipconfig_type type;
	char *ifname;
	int err;

	DBG("ipconfig %p", ipconfig);

	if (!ipconfig || ipconfig->index < 0)
		return -ENODEV;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (!ipdevice)
		return -ENXIO;

	if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		if (ipdevice->config_ipv4 == ipconfig)
			return -EALREADY;
		type = CONNMAN_IPCONFIG_TYPE_IPV4;
	} else if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		if (ipdevice->config_ipv6 == ipconfig)
			return -EALREADY;
		type = CONNMAN_IPCONFIG_TYPE_IPV6;
	} else
		return -EINVAL;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
					ipdevice->config_ipv4) {
		ipconfig_list = g_list_remove(ipconfig_list,
							ipdevice->config_ipv4);

		connman_ipaddress_clear(ipdevice->config_ipv4->system);

		__connman_ipconfig_unref(ipdevice->config_ipv4);

		g_free(ipdevice->ipv4_gateway);
		ipdevice->ipv4_gateway = NULL;
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
					ipdevice->config_ipv6) {
		ipconfig_list = g_list_remove(ipconfig_list,
							ipdevice->config_ipv6);

		connman_ipaddress_clear(ipdevice->config_ipv6->system);

		__connman_ipconfig_unref(ipdevice->config_ipv6);

		g_free(ipdevice->ipv6_gateway);
		ipdevice->ipv6_gateway = NULL;
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		ipdevice->config_ipv4 = __connman_ipconfig_ref(ipconfig);
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		ipdevice->config_ipv6 = __connman_ipconfig_ref(ipconfig);

		err = enable_ipv6(ipdevice->config_ipv6);
		if (err)
			return err;
	}
	ipconfig_list = g_list_append(ipconfig_list, ipconfig);

	if (ipdevice->flags & IFF_UP)
		up = true;
	else
		down = true;

	if ((ipdevice->flags & (IFF_RUNNING | IFF_LOWER_UP)) ==
			(IFF_RUNNING | IFF_LOWER_UP))
		lower_up = true;
	else if ((ipdevice->flags & (IFF_RUNNING | IFF_LOWER_UP)) == 0)
		lower_down = true;

	ifname = connman_inet_ifname(ipconfig->index);

	if (up && ipconfig->ops->up)
		ipconfig->ops->up(ipconfig, ifname);
	if (lower_up && ipconfig->ops->lower_up)
		ipconfig->ops->lower_up(ipconfig, ifname);

	if (lower_down && ipconfig->ops->lower_down)
		ipconfig->ops->lower_down(ipconfig, ifname);
	if (down && ipconfig->ops->down)
		ipconfig->ops->down(ipconfig, ifname);

	g_free(ifname);

	return 0;
}

int __connman_ipconfig_disable(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;

	DBG("ipconfig %p", ipconfig);

	if (!ipconfig || ipconfig->index < 0)
		return -ENODEV;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (!ipdevice)
		return -ENXIO;

	if (!ipdevice->config_ipv4 && !ipdevice->config_ipv6)
		return -EINVAL;

	if (ipdevice->config_ipv4 == ipconfig) {
		ipconfig_list = g_list_remove(ipconfig_list, ipconfig);

		connman_ipaddress_clear(ipdevice->config_ipv4->system);
		__connman_ipconfig_unref(ipdevice->config_ipv4);
		ipdevice->config_ipv4 = NULL;

		g_free(ipdevice->ipv4_gateway);
		ipdevice->ipv4_gateway = NULL;

		return 0;
	}

	if (ipdevice->config_ipv6 == ipconfig) {
		ipconfig_list = g_list_remove(ipconfig_list, ipconfig);

		connman_ipaddress_clear(ipdevice->config_ipv6->system);
		__connman_ipconfig_unref(ipdevice->config_ipv6);
		ipdevice->config_ipv6 = NULL;

		g_free(ipdevice->ipv6_gateway);
		ipdevice->ipv6_gateway = NULL;

		return 0;
	}

	return -EINVAL;
}

const char *__connman_ipconfig_method2string(enum connman_ipconfig_method method)
{
	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		break;
	case CONNMAN_IPCONFIG_METHOD_OFF:
		return "off";
	case CONNMAN_IPCONFIG_METHOD_FIXED:
		return "fixed";
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		return "manual";
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		return "dhcp";
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		return "auto";
	}

	return NULL;
}

enum connman_ipconfig_method __connman_ipconfig_string2method(const char *method)
{
	if (g_strcmp0(method, "off") == 0)
		return CONNMAN_IPCONFIG_METHOD_OFF;
	else if (g_strcmp0(method, "fixed") == 0)
		return CONNMAN_IPCONFIG_METHOD_FIXED;
	else if (g_strcmp0(method, "manual") == 0)
		return CONNMAN_IPCONFIG_METHOD_MANUAL;
	else if (g_strcmp0(method, "dhcp") == 0)
		return CONNMAN_IPCONFIG_METHOD_DHCP;
	else if (g_strcmp0(method, "auto") == 0)
		return CONNMAN_IPCONFIG_METHOD_AUTO;
	else
		return CONNMAN_IPCONFIG_METHOD_UNKNOWN;
}

static const char *privacy2string(int privacy)
{
	if (privacy <= 0)
		return "disabled";
	else if (privacy == 1)
		return "enabled";
	else
		return "prefered";
}

static int string2privacy(const char *privacy)
{
	if (g_strcmp0(privacy, "disabled") == 0)
		return 0;
	else if (g_strcmp0(privacy, "enabled") == 0)
		return 1;
	else if (g_strcmp0(privacy, "preferred") == 0)
		return 2;
	else if (g_strcmp0(privacy, "prefered") == 0)
		return 2;
	else
		return 0;
}

int __connman_ipconfig_ipv6_reset_privacy(struct connman_ipconfig *ipconfig)
{
	struct connman_ipdevice *ipdevice;
	int err;

	if (!ipconfig)
		return -EINVAL;

	ipdevice = g_hash_table_lookup(ipdevice_hash,
						GINT_TO_POINTER(ipconfig->index));
	if (!ipdevice)
		return -ENODEV;

	err = __connman_ipconfig_ipv6_set_privacy(ipconfig, privacy2string(ipdevice->ipv6_privacy));

	return err;
}

int __connman_ipconfig_ipv6_set_privacy(struct connman_ipconfig *ipconfig,
					const char *value)
{
	int privacy;

	if (!ipconfig)
		return -EINVAL;

	privacy = string2privacy(value);

	ipconfig->ipv6_privacy_config = privacy;

	return enable_ipv6(ipconfig);
}

void __connman_ipconfig_append_ipv4(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter)
{
	struct connman_ipaddress *append_addr = NULL;
	const char *str;

	if (ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV4)
		return;

	str = __connman_ipconfig_method2string(ipconfig->method);
	if (!str)
		return;

	connman_dbus_dict_append_basic(iter, "Method", DBUS_TYPE_STRING, &str);

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		return;

	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		append_addr = ipconfig->address;
		break;

	case CONNMAN_IPCONFIG_METHOD_AUTO:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		append_addr = ipconfig->system;
		break;
	}

	if (!append_addr)
		return;

	if (append_addr->local) {
		in_addr_t addr;
		struct in_addr netmask;
		char *mask;

		connman_dbus_dict_append_basic(iter, "Address",
				DBUS_TYPE_STRING, &append_addr->local);

		addr = 0xffffffff << (32 - append_addr->prefixlen);
		netmask.s_addr = htonl(addr);
		mask = inet_ntoa(netmask);
		connman_dbus_dict_append_basic(iter, "Netmask",
						DBUS_TYPE_STRING, &mask);
	}

	if (append_addr->gateway)
		connman_dbus_dict_append_basic(iter, "Gateway",
				DBUS_TYPE_STRING, &append_addr->gateway);
}

void __connman_ipconfig_append_ipv6(struct connman_ipconfig *ipconfig,
					DBusMessageIter *iter,
					struct connman_ipconfig *ipconfig_ipv4)
{
	struct connman_ipaddress *append_addr = NULL;
	const char *str, *privacy;

	if (ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV6)
		return;

	str = __connman_ipconfig_method2string(ipconfig->method);
	if (!str)
		return;

	if (ipconfig_ipv4 &&
			ipconfig->method == CONNMAN_IPCONFIG_METHOD_AUTO) {
		if (__connman_6to4_check(ipconfig_ipv4) == 1)
			str = "6to4";
	}

	connman_dbus_dict_append_basic(iter, "Method", DBUS_TYPE_STRING, &str);

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		return;

	case CONNMAN_IPCONFIG_METHOD_FIXED:
		append_addr = ipconfig->address;
		break;

	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		append_addr = ipconfig->system;
		break;
	}

	if (!append_addr)
		return;

	if (append_addr->local) {
		connman_dbus_dict_append_basic(iter, "Address",
				DBUS_TYPE_STRING, &append_addr->local);
		connman_dbus_dict_append_basic(iter, "PrefixLength",
						DBUS_TYPE_BYTE,
						&append_addr->prefixlen);
	}

	if (append_addr->gateway)
		connman_dbus_dict_append_basic(iter, "Gateway",
				DBUS_TYPE_STRING, &append_addr->gateway);

	privacy = privacy2string(ipconfig->ipv6_privacy_config);
	connman_dbus_dict_append_basic(iter, "Privacy",
				DBUS_TYPE_STRING, &privacy);
}

void __connman_ipconfig_append_ipv6config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter)
{
	const char *str, *privacy;

	str = __connman_ipconfig_method2string(ipconfig->method);
	if (!str)
		return;

	connman_dbus_dict_append_basic(iter, "Method", DBUS_TYPE_STRING, &str);

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		return;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		break;
	}

	if (!ipconfig->address)
		return;

	if (ipconfig->address->local) {
		connman_dbus_dict_append_basic(iter, "Address",
				DBUS_TYPE_STRING, &ipconfig->address->local);
		connman_dbus_dict_append_basic(iter, "PrefixLength",
						DBUS_TYPE_BYTE,
						&ipconfig->address->prefixlen);
	}

	if (ipconfig->address->gateway)
		connman_dbus_dict_append_basic(iter, "Gateway",
				DBUS_TYPE_STRING, &ipconfig->address->gateway);

	privacy = privacy2string(ipconfig->ipv6_privacy_config);
	connman_dbus_dict_append_basic(iter, "Privacy",
				DBUS_TYPE_STRING, &privacy);
}

void __connman_ipconfig_append_ipv4config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter)
{
	const char *str;

	str = __connman_ipconfig_method2string(ipconfig->method);
	if (!str)
		return;

	connman_dbus_dict_append_basic(iter, "Method", DBUS_TYPE_STRING, &str);

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		return;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		break;
	}

	if (!ipconfig->address)
		return;

	if (ipconfig->address->local) {
		in_addr_t addr;
		struct in_addr netmask;
		char *mask;

		connman_dbus_dict_append_basic(iter, "Address",
				DBUS_TYPE_STRING, &ipconfig->address->local);

		addr = 0xffffffff << (32 - ipconfig->address->prefixlen);
		netmask.s_addr = htonl(addr);
		mask = inet_ntoa(netmask);
		connman_dbus_dict_append_basic(iter, "Netmask",
						DBUS_TYPE_STRING, &mask);
	}

	if (ipconfig->address->gateway)
		connman_dbus_dict_append_basic(iter, "Gateway",
				DBUS_TYPE_STRING, &ipconfig->address->gateway);
}

static int set_config(struct connman_ipconfig *ipconfig,
					enum connman_ipconfig_method method,
					const char *address,
					const char *netmask,
					const char *gateway,
					unsigned char prefix_length,
					const char *privacy_string,
					int privacy)
{
	int type = -1;

	if (!ipconfig)
		return -EINVAL;

	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_FIXED:
		return -EINVAL;

	case CONNMAN_IPCONFIG_METHOD_OFF:
		ipconfig->method = method;

		break;

	case CONNMAN_IPCONFIG_METHOD_AUTO:
		if (ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV6)
			return -EOPNOTSUPP;

		ipconfig->method = method;
		if (privacy_string)
			ipconfig->ipv6_privacy_config = privacy;

		break;

	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		switch (ipconfig->type) {
		case CONNMAN_IPCONFIG_TYPE_IPV4:
			type = AF_INET;
			break;
		case CONNMAN_IPCONFIG_TYPE_IPV6:
			type = AF_INET6;
			break;
		case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		case CONNMAN_IPCONFIG_TYPE_ALL:
			type = -1;
			break;
		}

		if ((address && connman_inet_check_ipaddress(address)
						!= type) ||
				(netmask &&
				connman_inet_check_ipaddress(netmask)
						!= type) ||
				(gateway &&
				connman_inet_check_ipaddress(gateway)
						!= type))
			return -EINVAL;

		ipconfig->method = method;

		if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV4)
			connman_ipaddress_set_ipv4(ipconfig->address,
						address, netmask, gateway);
		else
			return connman_ipaddress_set_ipv6(
					ipconfig->address, address,
						prefix_length, gateway);

		break;

	case CONNMAN_IPCONFIG_METHOD_DHCP:
		if (ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV4)
			return -EOPNOTSUPP;

		ipconfig->method = method;
		break;
	}

	return 0;
}

int __connman_ipconfig_set_config(struct connman_ipconfig *ipconfig,
							DBusMessageIter *array)
{
	enum connman_ipconfig_method method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
	const char *address = NULL, *netmask = NULL, *gateway = NULL,
		*privacy_string = NULL;
	int prefix_length = 0, privacy = 0;
	DBusMessageIter dict;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return -EINVAL;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;
		int type;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return -EINVAL;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return -EINVAL;

		dbus_message_iter_recurse(&entry, &value);

		type = dbus_message_iter_get_arg_type(&value);

		if (g_str_equal(key, "Method")) {
			const char *str;

			if (type != DBUS_TYPE_STRING)
				return -EINVAL;

			dbus_message_iter_get_basic(&value, &str);
			method = __connman_ipconfig_string2method(str);
		} else if (g_str_equal(key, "Address")) {
			if (type != DBUS_TYPE_STRING)
				return -EINVAL;

			dbus_message_iter_get_basic(&value, &address);
		} else if (g_str_equal(key, "PrefixLength")) {
			if (type != DBUS_TYPE_BYTE)
				return -EINVAL;

			dbus_message_iter_get_basic(&value, &prefix_length);

			if (prefix_length < 0 || prefix_length > 128)
				return -EINVAL;
		} else if (g_str_equal(key, "Netmask")) {
			if (type != DBUS_TYPE_STRING)
				return -EINVAL;

			dbus_message_iter_get_basic(&value, &netmask);
		} else if (g_str_equal(key, "Gateway")) {
			if (type != DBUS_TYPE_STRING)
				return -EINVAL;

			dbus_message_iter_get_basic(&value, &gateway);
		} else if (g_str_equal(key, "Privacy")) {
			if (type != DBUS_TYPE_STRING)
				return -EINVAL;

			dbus_message_iter_get_basic(&value, &privacy_string);
			privacy = string2privacy(privacy_string);
		}

		dbus_message_iter_next(&dict);
	}

	DBG("method %d address %s netmask %s gateway %s prefix_length %d "
		"privacy %s",
		method, address, netmask, gateway, prefix_length,
		privacy_string);

	return set_config(ipconfig, method, address, netmask, gateway,
				prefix_length, privacy_string, privacy);
}

int __connman_ipconfig_set_config_from_address(
					struct connman_ipconfig *ipconfig,
					enum connman_ipconfig_method method,
					const char *address,
					const char *netmask,
					const char *gateway,
					unsigned char prefix_length)
{
	return set_config(ipconfig, method, address, netmask, gateway,
							prefix_length, NULL, 0);
}

void __connman_ipconfig_append_ethernet(struct connman_ipconfig *ipconfig,
							DBusMessageIter *iter)
{
	struct connman_ipdevice *ipdevice;
	const char *method = "auto";

	connman_dbus_dict_append_basic(iter, "Method",
						DBUS_TYPE_STRING, &method);

	ipdevice = g_hash_table_lookup(ipdevice_hash,
					GINT_TO_POINTER(ipconfig->index));
	if (!ipdevice)
		return;

	if (ipconfig->index >= 0) {
		char *ifname = connman_inet_ifname(ipconfig->index);
		if (ifname) {
			connman_dbus_dict_append_basic(iter, "Interface",
						DBUS_TYPE_STRING, &ifname);
			g_free(ifname);
		}
	}

	if (ipdevice->address)
		connman_dbus_dict_append_basic(iter, "Address",
					DBUS_TYPE_STRING, &ipdevice->address);

	if (ipdevice->mtu > 0)
		connman_dbus_dict_append_basic(iter, "MTU",
					DBUS_TYPE_UINT16, &ipdevice->mtu);
}

void __connman_ipconfig_load(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix)
{
	char *method;
	char *str;
	struct ipconfig_store is = { .file = keyfile,
				     .group = identifier,
				     .prefix = prefix };

	DBG("ipconfig %p identifier %s", ipconfig, identifier);

	method = store_get_str(&is, "method");
	if (!method) {
		switch (ipconfig->type) {
		case CONNMAN_IPCONFIG_TYPE_IPV4:
			ipconfig->method = CONNMAN_IPCONFIG_METHOD_DHCP;
			break;

		case CONNMAN_IPCONFIG_TYPE_IPV6:
			ipconfig->method = CONNMAN_IPCONFIG_METHOD_AUTO;
			break;

		case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		case CONNMAN_IPCONFIG_TYPE_ALL:
			ipconfig->method = CONNMAN_IPCONFIG_METHOD_OFF;
			break;
		}
	} else {
		ipconfig->method = __connman_ipconfig_string2method(method);
		g_free(method);
	}

	if (ipconfig->method == CONNMAN_IPCONFIG_METHOD_UNKNOWN)
		ipconfig->method = CONNMAN_IPCONFIG_METHOD_OFF;

	if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		if (ipconfig->method == CONNMAN_IPCONFIG_METHOD_AUTO ||
				ipconfig->method == CONNMAN_IPCONFIG_METHOD_MANUAL) {
			char *privacy;

			privacy = store_get_str(&is, "privacy");
			ipconfig->ipv6_privacy_config = string2privacy(privacy);
			g_free(privacy);
		}

		g_strfreev(ipconfig->last_dhcpv6_prefixes);
		ipconfig->last_dhcpv6_prefixes =
			store_get_strs(&is, "DHCP.LastPrefixes");

		ipconfig->dhcpv6_duid = store_get_str(&is, "DHCP.DUID");
	}


	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		break;

	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		ipconfig->address->prefixlen =
			store_get_int(&is, "netmask_prefixlen");

		g_free(ipconfig->address->local);
		ipconfig->address->local =
			store_get_str(&is, "local_address");

		g_free(ipconfig->address->peer);
		ipconfig->address->peer =
			store_get_str(&is, "peer_address");

		g_free(ipconfig->address->broadcast);
		ipconfig->address->broadcast =
			store_get_str(&is, "broadcast_address");

		g_free(ipconfig->address->gateway);
		ipconfig->address->gateway =
			store_get_str(&is, "gateway");
		break;

	case CONNMAN_IPCONFIG_METHOD_AUTO:
		if (ipconfig->type != CONNMAN_IPCONFIG_TYPE_IPV4)
			break;

		/*
		 * If the last used method for IPv4 was AUTO then we
		 * try first DHCP. We will try also to use the last
		 * used DHCP address, if exits.
		 */
		__connman_ipconfig_set_method(ipconfig,
					CONNMAN_IPCONFIG_METHOD_DHCP);
		/* fall through */

	case CONNMAN_IPCONFIG_METHOD_DHCP:
		str = store_get_str(&is, "DHCP.LastAddress");
		if (str) {
			g_free(ipconfig->last_dhcp_address);
			ipconfig->last_dhcp_address = str;
		}

		break;
	}
}

void __connman_ipconfig_save(struct connman_ipconfig *ipconfig,
		GKeyFile *keyfile, const char *identifier, const char *prefix)
{
	enum connman_ipconfig_method ipconfig_method;
	const char *method;
	struct ipconfig_store is = { .file = keyfile,
				     .group = identifier,
				     .prefix = prefix };

	/* Use the original method if IPv6 is force disabled */
	if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
				ipconfig->ipv6_force_disabled)
		ipconfig_method = ipconfig->saved_method;
	else
		ipconfig_method = ipconfig->method;

	method = __connman_ipconfig_method2string(ipconfig_method);

	DBG("ipconfig %p identifier %s method %s", ipconfig, identifier,
								method);
	store_set_str(&is, "method", method);

	if (ipconfig->type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		store_set_str(&is, "privacy",
				privacy2string(ipconfig->ipv6_privacy_config));

		store_set_str(&is, "DHCP.LastAddress",
				ipconfig->last_dhcp_address);

		store_set_strs(&is, "DHCP.LastPrefixes",
				ipconfig->last_dhcpv6_prefixes);

		store_set_str(&is, "DHCP.DUID", ipconfig->dhcpv6_duid);
	}

	switch (ipconfig->method) {
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
		break;

	case CONNMAN_IPCONFIG_METHOD_DHCP:
		store_set_str(&is, "DHCP.LastAddress",
				ipconfig->last_dhcp_address);
		/* fall through */

	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		return;
	}

	store_set_int(&is, "netmask_prefixlen", ipconfig->address->prefixlen);
	store_set_str(&is, "local_address", ipconfig->address->local);
	store_set_str(&is, "peer_address", ipconfig->address->peer);
	store_set_str(&is, "broadcast_address", ipconfig->address->broadcast);
	store_set_str(&is, "gateway", ipconfig->address->gateway);
}

int __connman_ipconfig_init(void)
{
	DBG("");

	ipdevice_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_ipdevice);

	is_ipv6_supported = connman_inet_is_ipv6_supported();

	return 0;
}

void __connman_ipconfig_cleanup(void)
{
	DBG("");

	g_hash_table_destroy(ipdevice_hash);
	ipdevice_hash = NULL;
}
