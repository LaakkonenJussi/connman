/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
 *  Copyright (C) 2012-2014  BMW Car IT GmbH.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <connman/ipconfig.h>

#include "connman.h"

static char *default_interface = NULL;
static struct connman_service *default_service = NULL;
static GHashTable *nat_hash;

struct connman_nat {
	char *address;
	unsigned char prefixlen;
	struct firewall_context *fw;
	int ipv6_accept_ra;
	int ipv6_ndproxy;

	char *interface;
};

#define IPv4_FORWARD "/proc/sys/net/ipv4/ip_forward"
#define IPv6_FORWARD "/proc/sys/net/ipv6/conf/all/forwarding"

static int enable_ip_forward(int family, bool enable)
{
	const char *path;
	static char value = 0;
	int f, err = 0;

	switch (family) {
	case AF_INET:
		path = IPv4_FORWARD;
		break;
	case AF_INET6:
		path = IPv6_FORWARD;
		break;
	default:
		return -EINVAL;
	}

	if ((f = open(path, O_CLOEXEC | O_RDWR)) < 0)
		return -errno;

	if (!value) {
		if (read(f, &value, sizeof(value)) < 0)
			value = 0;

		if (lseek(f, 0, SEEK_SET) < 0)
			return -errno;
	}

	if (enable) {
		char allow = '1';

		if (write (f, &allow, sizeof(allow)) < 0)
			err = -errno;
	} else {
		char deny = '0';

		if (value)
			deny = value;

		if (write(f, &deny, sizeof(deny)) < 0)
			err = -errno;

		value = 0;
	}

	close(f);

	return err;
}

static bool default_interface_has_ipv4_address()
{
	struct connman_network *network;
	struct connman_ipconfig *ipconfig;
	struct connman_ipaddress *ipaddress;
	const char *address;
	unsigned char prefixlen;
	int err;

	if (!default_interface)
		return false;

	network = connman_service_get_network(default_service);
	if (!network) {
		DBG("no network for service %p interface %s", default_service,
							default_interface);
		return false;
	}

	if (!connman_network_is_configured(network, CONNMAN_IPCONFIG_TYPE_IPV4)) {
		DBG("IPv4 not is configured on network %p", network);
		return false;
	}

	/* Configured, verify that address exists */
	ipconfig = connman_service_get_ipconfig(default_service, AF_INET);
	DBG("IPv4 ipconfig %p", ipconfig);

	ipaddress = connman_ipconfig_get_ipaddress(ipconfig);
	DBG("IPv4 ipaddress %p", ipaddress);

	err = connman_ipaddress_get_ip(ipaddress, &address, &prefixlen);
	if (err || !address) {
		DBG("IPv4 is not configured on service %p interface %s",
					default_service, default_interface);
		return false;
	}

	DBG("IPv4 address %s set for service %p interface %s", address,
					default_service, default_interface);

	return true;
}

static int enable_nat(struct connman_nat *nat)
{
	char *cmd;
	int err;

	g_free(nat->interface);

	if (default_interface_has_ipv4_address())
		nat->interface = g_strdup(default_interface);
	else
		nat->interface = g_strdup("clat");

	if (!nat->interface)
		return 0;

	DBG("interface %s", nat->interface);

	/* Enable masquerading */
	cmd = g_strdup_printf("-s %s/%d -o %s -j MASQUERADE",
					nat->address,
					nat->prefixlen,
					nat->interface);

	err = __connman_firewall_add_rule(nat->fw, NULL, NULL, "nat",
				"POSTROUTING", cmd);
	g_free(cmd);
	if (err < 0)
		return err;

	return __connman_firewall_enable(nat->fw);
}

static void disable_nat(struct connman_nat *nat)
{
	if (!nat->interface)
		return;

	/* Disable masquerading */
	__connman_firewall_disable(nat->fw);
}

int __connman_nat_enable(const char *name, const char *address,
				unsigned char prefixlen)
{
	struct connman_nat *nat;
	int err;

	if (g_hash_table_size(nat_hash) == 0) {
		err = enable_ip_forward(AF_INET, true);
		if (err < 0)
			return err;
	}

	nat = g_try_new0(struct connman_nat, 1);
	if (!nat)
		goto err;

	nat->fw = __connman_firewall_create();
	if (!nat->fw)
		goto err;

	nat->address = g_strdup(address);
	nat->prefixlen = prefixlen;

	g_hash_table_replace(nat_hash, g_strdup(name), nat);

	return enable_nat(nat);

err:
	if (nat) {
		if (nat->fw)
			__connman_firewall_destroy(nat->fw);
		g_free(nat);
	}

	if (g_hash_table_size(nat_hash) == 0)
		enable_ip_forward(AF_INET, false);

	return -ENOMEM;
}

static void set_original_ipv6_values(struct connman_nat *nat,
					struct connman_ipconfig *ipconfig,
					const char *ipv6_address,
					unsigned char ipv6_prefixlen)
{
	int index;
	int err;

	if (!nat || !ipconfig)
		return;

	DBG("nat %p ipconfig %p", nat, ipconfig);

	err = enable_ip_forward(AF_INET6, false);
	if (err)
		connman_warn("Failed to disable IPv6 forwarding: %d", err);

	if (nat->ipv6_accept_ra != -1)
		__connman_ipconfig_ipv6_set_accept_ra(ipconfig,
				nat->ipv6_accept_ra);
	if (nat->ipv6_ndproxy != -1) {
		__connman_ipconfig_ipv6_set_ndproxy(ipconfig,
				nat->ipv6_ndproxy ? true : false);

		index = __connman_ipconfig_get_index(ipconfig);
		if (index < 0)
			return;

		err = __connman_inet_del_ipv6_neigbour_proxy(index,
							ipv6_address,
							ipv6_prefixlen);
		if (err) {
			connman_error("failed to delete IPv6 neighbour proxy");
			return;
		}
	}

	DBG("done");
}

int connman_nat6_prepare(struct connman_ipconfig *ipconfig,
						const char *ipv6_address,
						unsigned char ipv6_prefixlen,
						const char *ifname_in,
						bool enable_ndproxy)
{
	struct connman_nat *nat;
	char *ifname = NULL;
	char **rules = NULL;
	int index;
	int err;
	int i;

	DBG("ipconfig %p ifname_in %s enable_ndproxy %s", ipconfig, ifname_in,
						enable_ndproxy ? "yes" : "no");

	if (connman_ipconfig_get_config_type(ipconfig) !=
						CONNMAN_IPCONFIG_TYPE_IPV6) {
		DBG("ipconfig %p is not IPv6", ipconfig);
		return -EINVAL;
	}

	nat = g_try_new0(struct connman_nat, 1);
	if (!nat) {
		connman_error("cannot create NAT struct");
		return -ENOMEM;
	}

	nat->ipv6_accept_ra = -1;
	nat->ipv6_ndproxy = -1;

	nat->fw = __connman_firewall_create();
	if (!nat->fw) {
		connman_error("cannot create firewall");
		g_free(nat);
		return -ENOMEM;
	}

	nat->ipv6_accept_ra = __connman_ipconfig_ipv6_get_accept_ra(ipconfig);

	err = __connman_ipconfig_ipv6_set_accept_ra(ipconfig, 2);
	if (err) {
		connman_error("failed to set accept_ra: %d", err);
		goto err;
	}

	err = enable_ip_forward(AF_INET6, true);
	if (err) {
		connman_error("failed to set IPv6 forwarding: %d", err);
		goto err;
	}

	index = __connman_ipconfig_get_index(ipconfig);
	ifname = connman_inet_ifname(index);
	if (!ifname) {
		connman_error("no interface name for index %d",
					__connman_ipconfig_get_index(ipconfig));
		goto err;
	}

	if (enable_ndproxy) {
		DBG("Enabling ndproxy");

		nat->ipv6_ndproxy = __connman_ipconfig_ipv6_get_ndproxy(
							ipconfig) ? 1 : 0;
		err = __connman_ipconfig_ipv6_set_ndproxy(ipconfig, true);
		if (err) {
			connman_error("failed to set IPv6 ndproxy");
			goto err;
		}

		err = __connman_inet_add_ipv6_neigbour_proxy(index,
							ipv6_address,
							ipv6_prefixlen);
		if (err) {
			connman_error("failed to add IPv6 neighbour proxy");
			goto err;
		}
	}

	rules = g_new0(char*, 2);
	rules[0] = g_strdup_printf("-i %s -o %s -j ACCEPT", ifname_in, ifname);
	rules[1] = g_strdup_printf("-i %s -o %s -j ACCEPT", ifname, ifname_in);

	for (i = 0; i < 2; i++) {
		DBG("Enable firewall rule -I FORWARD %s", rules[i]);

		/* Enable forward on IPv6 */
		err = __connman_firewall_add_ipv6_rule(nat->fw, NULL, NULL,
						"filter", "FORWARD", rules[i]);
		if (err < 0) {
			connman_error("Failed to set FORWARD rule %s on "
						"ip6tables", rules[i]);
			break;
		}
	}

	g_strfreev(rules);

	err = __connman_firewall_enable(nat->fw);
	if (err < 0) {
		connman_error("Failed to enable firewall");
		goto err;
	}

	g_hash_table_replace(nat_hash, ifname, nat);

	DBG("prepare done");

	return 0;

err:
	DBG("prepare failure, revert changes");

	g_free(ifname);

	if (nat) {
		if (nat->fw)
			__connman_firewall_destroy(nat->fw);

		/* Restore original values */
		set_original_ipv6_values(nat, ipconfig, ipv6_address,
							ipv6_prefixlen);

		g_free(nat);
	}

	return err;
}

void __connman_nat_disable(const char *name)
{
	struct connman_nat *nat;

	nat = g_hash_table_lookup(nat_hash, name);
	if (!nat)
		return;

	disable_nat(nat);

	g_hash_table_remove(nat_hash, name);

	if (g_hash_table_size(nat_hash) == 0)
		enable_ip_forward(AF_INET, false);
}

void connman_nat6_restore(struct connman_ipconfig *ipconfig,
						const char *ipv6_address,
						unsigned char ipv6_prefixlen)
{
	struct connman_nat *nat;
	char *ifname;

	DBG("ipconfig %p", ipconfig);

	if (!ipconfig)
		return;

	ifname = connman_inet_ifname(__connman_ipconfig_get_index(ipconfig));
	if (!ifname) {
		DBG("no interface name, cannot be removed");
		return;
	}

	nat = g_hash_table_lookup(nat_hash, ifname);
	if (!nat) {
		DBG("no interface %s found in hash", ifname);
		g_free(ifname);
		return;
	}

	/* Restore original values */
	set_original_ipv6_values(nat, ipconfig, ipv6_address, ipv6_prefixlen);

	if (nat->fw) {
		if (__connman_firewall_disable(nat->fw))
			DBG("cannot disable firewall");
	}

	if (nat_hash)
		g_hash_table_remove(nat_hash, ifname);

	g_free(ifname);

	DBG("restore done");
}

static void update_default_interface(struct connman_service *service)
{
	GHashTableIter iter;
	gpointer key, value;
	char *interface;
	int err;

	interface = connman_service_get_interface(service);

	DBG("interface %s", interface);

	g_free(default_interface);
	default_interface = interface;

	if (default_service) {
		connman_service_unref(default_service);
		default_service = NULL;
	}

	if (service)
		default_service = connman_service_ref(service);

	g_hash_table_iter_init(&iter, nat_hash);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		const char *name = key;
		struct connman_nat *nat = value;

		disable_nat(nat);
		err = enable_nat(nat);
		if (err < 0)
			DBG("Failed to enable nat for %s", name);
	}
}

static void shutdown_nat(gpointer key, gpointer value, gpointer user_data)
{
	const char *name = key;

	__connman_nat_disable(name);
}

static void cleanup_nat(gpointer data)
{
	struct connman_nat *nat = data;

	__connman_firewall_destroy(nat->fw);
	g_free(nat->address);
	g_free(nat->interface);
	g_free(nat);
}

static struct connman_notifier nat_notifier = {
	.name			= "nat",
	.default_changed	= update_default_interface,
};

int __connman_nat_init(void)
{
	int err;

	DBG("");

	err = connman_notifier_register(&nat_notifier);
	if (err < 0)
		return err;

	nat_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, cleanup_nat);

	return 0;
}

void __connman_nat_cleanup(void)
{
	DBG("");

	g_free(default_interface);
	if (default_service)
		connman_service_unref(default_service);

	g_hash_table_foreach(nat_hash, shutdown_nat, NULL);
	g_hash_table_destroy(nat_hash);
	nat_hash = NULL;

	connman_notifier_unregister(&nat_notifier);
}
