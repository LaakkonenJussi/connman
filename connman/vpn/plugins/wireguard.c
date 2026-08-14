/*
 *  ConnMan VPN daemon
 *
 *  Copyright (C) 2019  Daniel Wagner. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/task.h>
#include <connman/ipconfig.h>
#include <connman/inet.h>
#include <connman/dbus.h>
#include <connman/setting.h>
#include <connman/vpn-dbus.h>

#include <gweb/gresolv.h>

#include "../vpn-provider.h"
#include "../vpn.h"

#include "vpn.h"
#include "wireguard.h"

#define DNS_RERESOLVE_TIMEOUT 20
#define DNS_RERESOLVE_ERROR_LIMIT 5
#define ROUTE_SETUP_TIMEOUT 200 // ms
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

struct wireguard_info {
	struct vpn_provider *provider;
	struct wg_device device;
	struct wg_peer *peer;
	struct wg_peer_resolv *resolv;
	guint dying_id;
	guint route_setup_id;
};

struct sockaddr_u {
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	};
};

struct reresolve_data {
	struct wireguard_info *info;
	struct wg_peer_resolv *resolv;
};

struct wg_peer_resolv {
	int id;
	char *endpoint_fqdn;
	char *port;
	guint reresolve_id;
	GResolv *resolv;
	guint resolv_id;
	guint remove_resolv_id;
	struct wg_peer_resolv *next;
	// While we run the resolv we pass this data
	struct reresolve_data data;
};

struct {
	const char	*opt;
	bool		save;
	bool		peer_option;
} wg_options[] = {
	{"Address", true, false},
	{"ListenPort", true, false},
	{"DNS", true, false},
	{"PrivateKey", true, false}, // TODO set false after agent support
	{"PresharedKey", true, true}, // TODO set false after agent support
	{"PublicKey", true, true},
	{"AllowedIPs", true, true},
	{"Endpoint", true, true},
	{"EndpointPort", true, true},
	{"PersistentKeepalive", true, true},
	{"DisableIPv6", true, false},
	{"PeerCount", true, false},
};

static char* get_wg_opt(const char *opt, bool peer_option, int index)
{
	if (!opt)
		return NULL;

	/* Keep backwards compatibility when single peer mode is in use. */
	if (peer_option && index >= 0)
		return g_strdup_printf("WireGuard.Peer%d.%s", index, opt);

	return g_strdup_printf("WireGuard.%s", opt);
}

static struct wireguard_info *create_private_data(struct vpn_provider *provider)
{
	struct wireguard_info *info;

	info = g_malloc0(sizeof(struct wireguard_info));
	info->device.flags = WGDEVICE_HAS_PRIVATE_KEY;
	info->provider = vpn_provider_ref(provider);

	return info;
}

static void free_private_data(struct wireguard_info *info)
{
	struct wg_peer_resolv *resolv;
	struct wg_peer *peer;
	int i = 0;

	if (vpn_provider_get_plugin_data(info->provider) == info)
		vpn_provider_set_plugin_data(info->provider, NULL);

	vpn_provider_unref(info->provider);

	resolv = info->resolv;
	while (resolv) {
		struct wg_peer_resolv *tmp_resolv = resolv;
		resolv = resolv->next;

		DBG("free resolv for peer #%d", tmp_resolv->id);
		g_free(tmp_resolv->endpoint_fqdn);
		g_free(tmp_resolv->port);
		g_free(tmp_resolv);
	}

	peer = info->peer;
	while (peer) {
		struct wg_peer *tmp_peer = peer;
		struct wg_allowedip *allowedip = peer->first_allowedip;

		while (allowedip) {
			struct wg_allowedip *tmp_allowedip = allowedip;
			allowedip = allowedip->next_allowedip;
			g_free(tmp_allowedip);
		}

		peer = peer->next_peer;

		DBG("free peer #%d", i);
		g_free(tmp_peer);
		i++;
	}

	g_free(info);
}

static int parse_key(const char *str, wg_key key)
{
	unsigned char *buf;
	size_t len;

	buf = g_base64_decode(str, &len);

	if (len != 32) {
		g_free(buf);
		return -EINVAL;
	}

	memcpy(key, buf, 32);

	g_free(buf);
	return 0;
}

static int parse_allowed_ips(const char *allowed_ips, wg_peer *peer,
							bool *do_split_routing)
{
	struct wg_allowedip *curaip, *allowedip;
	char buf[INET6_ADDRSTRLEN];
	char **tokens, **toks;
	char *send;
	int i;

	*do_split_routing = true;
	curaip = NULL;
	tokens = g_strsplit_set(allowed_ips, ", ", -1);
	for (i = 0; tokens[i]; i++) {
		toks = g_strsplit(tokens[i], "/", -1);
		if (g_strv_length(toks) != 2) {
			DBG("Ignore AllowedIPs value \"%s\", length %d",
						tokens[i], g_strv_length(toks));
			g_strfreev(toks);
			continue;
		}

		allowedip = g_malloc0(sizeof(*allowedip));

		if (inet_pton(AF_INET, toks[0], buf) == 1) {
			allowedip->family = AF_INET;
			memcpy(&allowedip->ip4, buf, sizeof(allowedip->ip4));
		} else if (inet_pton(AF_INET6, toks[0], buf) == 1) {
			allowedip->family = AF_INET6;
			memcpy(&allowedip->ip6, buf, sizeof(allowedip->ip6));
		} else {
			DBG("Ignore AllowedIPs value \"%s\" not valid v4/v6", tokens[i]);
			g_free(allowedip);
			g_strfreev(toks);
			continue;
		}

		DBG("use addr %s/%s", toks[0], toks[1]);

		allowedip->cidr = g_ascii_strtoull(toks[1], &send, 10);

		/*
		 * Force split routing off if any address is detected as using
		 * these as allowed IPs indicates that WireGuard is to be used
		 * to route all traffic.
		 */
		if (connman_inet_is_any_addr(toks[0], allowedip->family))
			*do_split_routing = false;

		g_strfreev(toks);

		if (!curaip)
			peer->first_allowedip = allowedip;
		else
			curaip->next_allowedip = allowedip;

		curaip = allowedip;
	}

	peer->last_allowedip = curaip;
	g_strfreev(tokens);

	return 0;
}

static int get_endpoint_addr(const char *host, const char *port, int flags,
							struct sockaddr_u *addr)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	int sk;
	int err;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = flags;
	hints.ai_protocol = 0;

	err = getaddrinfo(host, port, &hints, &result);
	if (err) { /* Any non-zero return from getaddrinfo is an error */
		DBG("Failed to resolve host address: %s", gai_strerror(err));

		if (result)
			freeaddrinfo(result);

		return -EINVAL;
	}

	for (rp = result; rp; rp = rp->ai_next) {
		sk = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sk < 0)
			continue;
		if (connect(sk, rp->ai_addr, rp->ai_addrlen) != -1) {
			/* success */
			close(sk);
			break;
		}

		close(sk);
	}

	if (!rp) {
		DBG("no connectable address found in results: %s",
							strerror(errno));
		freeaddrinfo(result);
		return -EHOSTUNREACH;
	}

	memcpy(addr, rp->ai_addr, rp->ai_addrlen);
	freeaddrinfo(result);

	return 0;
}

static const char *endpoint_to_str(struct wg_peer *peer, char *buf,
							socklen_t len)
{
	struct sockaddr_u *addr;
	int family;

	addr = (struct sockaddr_u *)&peer->endpoint.addr;
	family = peer->endpoint.addr.sa_family;

	switch (family) {
	case AF_INET:
		return inet_ntop(family, &addr->sin.sin_addr, buf, len);
	case AF_INET6:
		return inet_ntop(family, &addr->sin6.sin6_addr, buf, len);
	default:
		break;
	}

	return NULL;
}

static int parse_endpoint_hostname(const char *host, const char *port,
						struct wg_peer *peer,
						char **gateway4_resolved,
						char **gateway6_resolved)
{
	struct sockaddr_u *addr;
	char **tokens;
	const char *gw = NULL;
	char buf[INET6_ADDRSTRLEN] = { 0 };
	unsigned int len;
	int err;

	/*
	 * getaddrinfo() relies on inet_pton() that suggests using addresses
	 * without CIDR notation. Host should contain the address in CIDR
	 * notation to be able to pass the prefix length to ConnMan via D-Bus.
	 */
	tokens = g_strsplit(host, "/", -1);
	len = g_strv_length(tokens);
	if (len > 2 || len < 1) {
		DBG("Failure tokenizing host %s", host);
		g_strfreev(tokens);
		return -EINVAL;
	}

	DBG("using host %s", tokens[0]);

	addr = (struct sockaddr_u *)&peer->endpoint.addr;

	err = get_endpoint_addr(tokens[0], port, 0, addr);
	if (!err) {
		/* In case the endpoint is an host address use the resolved
		 * IP address as gateway for DNS over WireGuard to work.
		 */
		if (connman_inet_check_ipaddress(tokens[0]) <= 0)
			gw = endpoint_to_str(peer, buf, INET6_ADDRSTRLEN);

		DBG("success");
	}

	switch (peer->endpoint.addr.sa_family) {
	case AF_INET:
		*gateway4_resolved = gw ? g_strdup(gw) : g_strdup(tokens[0]);
		*gateway6_resolved = NULL;
		break;
	case AF_INET6:
		*gateway4_resolved = NULL;
		*gateway6_resolved = gw ? g_strdup(gw) : g_strdup(tokens[0]);
		break;
	default:
		DBG("invalid or no family set, set to both?");
		*gateway4_resolved = gw ? g_strdup(gw) : g_strdup(tokens[0]);
		*gateway6_resolved = gw ? g_strdup(gw) : g_strdup(tokens[0]);
	}

	g_strfreev(tokens);

	return err;
}

static int parse_endpoint_results(char **results, const char *port,
							struct sockaddr_u *addr)
{
	int err = 0;
	int i;

	if (!results) {
		DBG("no results");
		return -EINVAL;
	}

	for (i = 0; results[i]; i++) {
		DBG("using host %s", results[i]);

		/* Use getaddrinfo to fill in the structs after resolve */
		err = get_endpoint_addr(results[i], port, AI_NUMERICHOST, addr);
		if (!err) {
			DBG("success");
			return err;
		}
	}

	return err;
}

struct wg_ipaddresses {
	struct connman_ipaddress *ipaddress_ipv4;
	struct connman_ipaddress *ipaddress_ipv6;
};

static char *cidr_to_netmask(int family, unsigned char cidr)
{
	uint32_t mask;

	switch (family) {
	case AF_INET:
		/* Avoid undefined behavior with 32bit shifting. */
		if (cidr == 0)
			mask = 0;
		else
			mask = 0xffffffffu << (32 - cidr);

		return g_strdup_printf("%u.%u.%u.%u",
				(mask >> 24) & 0xff,
				(mask >> 16) & 0xff,
				(mask >> 8) & 0xff,
				(mask >> 0) & 0xff);

	case AF_INET6:
		return g_strdup_printf("%u", cidr);
	default:
		break;
	}

	return NULL;
}

static int parse_addresses(const char *address, const char *gateway4,
		const char *gateway6, struct wg_ipaddresses *ipaddresses)
{
	char buf[INET6_ADDRSTRLEN];
	unsigned char prefixlen;
	char **addresses;
	char **tokens;
	char *end, *netmask;
	int err;
	int i;

	addresses = g_strsplit_set(address, ", ", -1);
	if (!g_strv_length(addresses)) {
		g_strfreev(addresses);
		return -EINVAL;
	}

	for (i = 0; addresses[i]; i++) {
		struct connman_ipaddress *ipaddress = NULL;
		int family = 0;

		tokens = g_strsplit(addresses[i], "/", -1);
		if (g_strv_length(tokens) != 2) {
			g_strfreev(tokens);
			DBG("Invalid Wireguard.Address value %s", addresses[i]);
			continue;
		}

		DBG("address %s", addresses[i]);

		prefixlen = g_ascii_strtoull(tokens[1], &end, 10);

		if (inet_pton(AF_INET, tokens[0], buf) == 1) {
			if (ipaddresses->ipaddress_ipv4) {
				g_strfreev(tokens);
				DBG("IPv4 address already set");
				err = -EALREADY;
				continue;
			}

			family = AF_INET;
			netmask = cidr_to_netmask(family, prefixlen);
			ipaddress = connman_ipaddress_alloc(family);
			err = connman_ipaddress_set_ipv4(ipaddress, tokens[0],
							netmask, gateway4);
			g_free(netmask);
		} else if (inet_pton(AF_INET6, tokens[0], buf) == 1) {
			if (ipaddresses->ipaddress_ipv6) {
				g_strfreev(tokens);
				DBG("IPv6 address already set");
				err = -EALREADY;
				continue;
			}

			family = AF_INET6;
			ipaddress = connman_ipaddress_alloc(family);
			err = connman_ipaddress_set_ipv6(ipaddress, tokens[0],
							prefixlen, gateway6);
		} else {
			DBG("Invalid Wireguard.Address value");
			err = -EINVAL;
		}

		g_strfreev(tokens);
		if (err) {
			connman_ipaddress_free(ipaddress);
			continue;
		}

		connman_ipaddress_set_p2p(ipaddress, true);

		if (family == AF_INET)
			ipaddresses->ipaddress_ipv4 = ipaddress;
		else if (family == AF_INET6)
			ipaddresses->ipaddress_ipv6 = ipaddress;
	}

	g_strfreev(addresses);

	return (ipaddresses->ipaddress_ipv4 || ipaddresses->ipaddress_ipv6) ?
				0 : -EINVAL;
}

static uint16_t parse_persistent_keepalive_interval(const char *option)
{
	guint64 interval;

	if (!option)
		return 0;

	interval = g_ascii_strtoull(option, NULL, 10);
	if (interval > G_MAXUINT16) {
		connman_warn("persistent keepalive interval overflow %"PRIu64,
						interval);
		interval = 0;
	}

	return (uint16_t)interval;
}

struct ifname_data {
	char *ifname;
	bool found;
};

static void ifname_check_cb(int index, void *user_data)
{
	struct ifname_data *data = (struct ifname_data *)user_data;
	char *ifname;

	ifname = connman_inet_ifname(index);

	if (!g_strcmp0(ifname, data->ifname))
		data->found = true;
}

static char *get_ifname(void)
{
	struct ifname_data data;
	int i;

	for (i = 0; i < 256; i++) {
		data.ifname = g_strdup_printf("wg%d", i);
		data.found = false;
		vpn_ipconfig_foreach(ifname_check_cb, &data);

		if (!data.found)
			return data.ifname;

		g_free(data.ifname);
	}

	return NULL;
}

static bool sockaddr_cmp_addr(struct sockaddr_u *a, struct sockaddr_u *b)
{
	if (a->sa.sa_family != b->sa.sa_family)
		return false;

	if (a->sa.sa_family == AF_INET)
		return !memcmp(&a->sin, &b->sin, sizeof(struct sockaddr_in));
	else if (a->sa.sa_family == AF_INET6)
		return !memcmp(a->sin6.sin6_addr.s6_addr,
				b->sin6.sin6_addr.s6_addr,
				sizeof(a->sin6.sin6_addr.s6_addr));

	return false;
}

static void run_dns_reresolve(struct reresolve_data *data);
static void run_route_setup(struct wireguard_info *info, guint timeout);

static void remove_resolv(struct wg_peer_resolv *resolv)
{
	DBG("");

	if (resolv->remove_resolv_id)
		g_source_remove(resolv->remove_resolv_id);

	if (resolv->resolv && resolv->resolv_id) {
		DBG("cancel resolv lookup");
		vpn_util_cancel_resolve(resolv->resolv, resolv->resolv_id);
	}

	resolv->resolv_id = 0;
	resolv->remove_resolv_id = 0;

	vpn_util_resolve_unref(resolv->resolv);
	resolv->resolv = NULL;
}

static gboolean remove_resolv_cb(gpointer user_data)
{
	struct wg_peer_resolv *resolv = user_data;

	remove_resolv(resolv);

	return G_SOURCE_REMOVE;
}

static struct wg_peer *get_nth_peer(struct wireguard_info *info, int index)
{
	struct wg_peer *peer;
	int i = 0;

	DBG("resolv index %d", index);

	wg_for_each_peer(&info->device, peer) {
		DBG("peer %d", i);
		if (i == index) {
			DBG("return #%d peer", i);
			return peer;
		}
		i++;
	}

	return NULL;
}

static void resolve_endpoint_cb(GResolvResultStatus status,
					char **results, gpointer user_data)
{
	struct reresolve_data *data = user_data;
	struct wireguard_info *info = data->info;
	struct wg_peer_resolv *resolv = data->resolv;
	struct wg_peer *peer;
	struct sockaddr_u addr;
	int err = 0;

	DBG("");

	if (!resolv->resolv && resolv->resolv_id) {
		DBG("resolv already removed");
		return;
	}

	/*
	 * We cannot unref the resolver here as resolv struct is manipulated
	 * by gresolv.c after we return from this callback. By clearing the
	 * resolv_id no attempt to cancel the lookup that has been executed
	 * here is done.
	 */
	resolv->remove_resolv_id = g_timeout_add(0, remove_resolv_cb, resolv);
	resolv->resolv_id = 0;

	switch (status) {
	case G_RESOLV_RESULT_STATUS_SUCCESS:
		if (!results || !g_strv_length(results)) {
			DBG("no resolved results");
			if (info->provider)
				vpn_provider_add_error(info->provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);

			return;
		}

		DBG("resolv success, parse endpoint");
		break;
	/* request timeouts or an server issue is not an error, try again */
	case G_RESOLV_RESULT_STATUS_NAME_ERROR: /* NXDOMAIN, might recover? */
	case G_RESOLV_RESULT_STATUS_NO_ANSWER:
	case G_RESOLV_RESULT_STATUS_NO_RESPONSE:
	case G_RESOLV_RESULT_STATUS_SERVER_FAILURE:
		DBG("retry DNS reresolve");
		if (data->info->provider)
			vpn_provider_add_error(info->provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);

		run_dns_reresolve(data);
		return;
	/* Consider these as non-continuable errors */
	case G_RESOLV_RESULT_STATUS_ERROR:
	case G_RESOLV_RESULT_STATUS_FORMAT_ERROR:
	case G_RESOLV_RESULT_STATUS_NOT_IMPLEMENTED:
	case G_RESOLV_RESULT_STATUS_REFUSED:
		DBG("stop DNS reresolve, error %d", status);
		if (err && info->provider)
			vpn_provider_add_error(info->provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);
		return;
	}

	/*
	 * If this fails after being connected it means configuration error
	 * that results in connection errors.
	 */
	err = parse_endpoint_results(results, resolv->port, &addr);
	if (err) {
		if (info->provider)
			vpn_provider_add_error(info->provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);
		run_dns_reresolve(data);
		return;
	}

	peer = get_nth_peer(info, resolv->id);
	if (!peer) {
		DBG("cannot find peer for resolv id %d", resolv->id);
		return;
	}

	if (sockaddr_cmp_addr(&addr,
			(struct sockaddr_u *)&peer->endpoint.addr)) {
		run_dns_reresolve(data);
		return;
	}

	if (addr.sa.sa_family == AF_INET)
		memcpy(&peer->endpoint.addr, &addr.sin,
					sizeof(peer->endpoint.addr4));
	else
		memcpy(&peer->endpoint.addr, &addr.sin6,
					sizeof(peer->endpoint.addr6));

	DBG("Endpoint address has changed, udpate WireGuard device");
	err = wg_set_device(&info->device);
	if (err)
		DBG("Failed to update Endpoint address for WireGuard device %s",
			info->device.name);

	run_dns_reresolve(data);

	/*
	 * Endpoint has changed and only one peer is used -> all old routes
	 * are invalid. Redo them without delay.
	 */
	vpn_provider_delete_all_routes(info->provider);
	run_route_setup(info, 0);
}

static int disconnect(struct vpn_provider *provider, int error);

static gboolean wg_route_setup_cb(gpointer user_data)
{
	struct wireguard_info *info = user_data;
	struct wg_peer *peer;
	struct wg_allowedip *allowedip;
	char addr[INET6_ADDRSTRLEN] = { 0 };
	char *netmask;
	unsigned long idx = 0;

	info->route_setup_id = 0;

	wg_for_each_peer(&info->device, peer) {
		wg_for_each_allowedip(peer, allowedip) {
			memset(&addr, 0, INET6_ADDRSTRLEN);

			switch (allowedip->family) {
			case AF_INET:
				if (!inet_ntop(allowedip->family,
							&allowedip->ip4, addr,
							INET6_ADDRSTRLEN)) {
					DBG("ignore invalid IPv4 address");
					continue;
				}

				break;
			case AF_INET6:
				if (!inet_ntop(allowedip->family,
							&allowedip->ip6, addr,
							INET6_ADDRSTRLEN)) {
					DBG("ignore invalid IPv6 address");
					continue;
				}

				break;
			default:
				DBG("ignore invalid IP family");
				continue;
			}

			netmask = cidr_to_netmask(allowedip->family,
							allowedip->cidr);

			vpn_provider_append_route_complete(info->provider, idx,
							allowedip->family, addr,
							netmask, NULL);

			g_free(netmask);
			++idx;
		}
	}

	return G_SOURCE_REMOVE;
}

static gboolean wg_dns_reresolve_cb(gpointer user_data)
{
	struct reresolve_data *data = user_data;
	struct wg_peer_resolv *resolv = data->resolv;
	int err;

	DBG("");

	resolv->reresolve_id = 0;

	if (resolv->resolv_id > 0) {
		DBG("previous query was running, abort it");
		remove_resolv(resolv);
	}

	resolv->resolv = vpn_util_resolve_new(0);
	if (!resolv->resolv) {
		connman_error("cannot create GResolv");
		return G_SOURCE_REMOVE;
	}

	DBG("endpoint_fqdn %s", resolv->endpoint_fqdn);

	resolv->resolv_id = vpn_util_resolve_hostname(resolv->resolv,
						resolv->endpoint_fqdn,
						resolve_endpoint_cb, data);

	err = vpn_util_get_resolve_error(resolv->resolv);
	if (!resolv->resolv_id && err) {
		connman_error("failed to start hostname lookup for %s, err %d",
						resolv->endpoint_fqdn, err);
		disconnect(data->info->provider, err);
	}

	return G_SOURCE_REMOVE;
}

static void run_dns_reresolve(struct reresolve_data *data)
{
	if (data->resolv->reresolve_id)
		g_source_remove(data->resolv->reresolve_id);

	data->resolv->reresolve_id = 0;

	if (vpn_provider_get_connection_errors(data->info->provider) >=
						DNS_RERESOLVE_ERROR_LIMIT) {
		connman_warn("reresolve error limit reached");
		disconnect(data->info->provider, -ENONET);
		return;
	}

	data->resolv->reresolve_id = g_timeout_add_seconds(
						DNS_RERESOLVE_TIMEOUT,
						wg_dns_reresolve_cb, data);
}

static void run_route_setup(struct wireguard_info *info, guint timeout)
{
	if (info->route_setup_id)
		g_source_remove(info->route_setup_id);

	info->route_setup_id = g_timeout_add(timeout, wg_route_setup_cb, info);
}

static int create_multipeer(struct wireguard_info *info, int peercount,
		bool *do_split_routing, char **gateway4, char **gateway6)
{
	struct wg_peer *peer;
	struct wg_peer *prev_peer = NULL;
	struct wg_peer_resolv *resolv;
	const char *option;
	const char *endpoint;
	bool split_routing = true;
	int family;
	int err = 0;
	int peer_id;
	int i;

	if (!info || !do_split_routing)
		return -EINVAL;

	for (i = 0, peer_id = 0, peer = info->peer, resolv = info->resolv;
							i < peercount; i++) {
		enum wg_peer_flags flags;
		char *str;

		if (!peer) {
			peer = g_try_new0(struct wg_peer, 1);
			if (!peer) {
				err = -ENOMEM;
				DBG("Failed to allocate new #%d wg_peer", i);
				break;
			}
		}

		str = get_wg_opt("PublicKey", true, i);
		option = vpn_provider_get_string(info->provider, str);
		if (!option) {
			DBG("%s is missing", str);
			g_free(str);
			continue;
		}

		g_free(str);

		err = parse_key(option, peer->public_key);
		if (err) {
			DBG("Failed to parse peer #%d public key", i);
			continue;
		}

		flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS;

		str = get_wg_opt("PresharedKey", true, i);
		option = vpn_provider_get_string(info->provider, str);
		g_free(str);

		if (option) {
			err = parse_key(option, peer->preshared_key);
			if (err) {
				DBG("Failed to parse peer #%d pre-shared key",
									i);
				continue;
			}
			flags |= WGPEER_HAS_PRESHARED_KEY;
		}

		str = get_wg_opt("AllowedIPs", true, i);
		option = vpn_provider_get_string(info->provider, str);
		if (!option) {
			DBG("peer #%d %s is missing", i, str);
			g_free(str);
			continue;
		}
		g_free(str);

		err = parse_allowed_ips(option, peer, &split_routing);
		if (err) {
			DBG("Failed to parse peer #%d allowed IPs %s", i,
									option);
			continue;
		}

		str = get_wg_opt("PersistentKeepalive", true, i);
		option = vpn_provider_get_string(info->provider, str);
		peer->persistent_keepalive_interval =
				parse_persistent_keepalive_interval(option);
		if (peer->persistent_keepalive_interval)
			flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;

		g_free(str);

		str = get_wg_opt("EndpointPort", true, i);
		option = vpn_provider_get_string(info->provider, str);
		if (!option)
			option = "51820";
		g_free(str);

		str = get_wg_opt("Endpoint", true, i);
		endpoint = vpn_provider_get_string(info->provider, str);
		g_free(str);

		/*
		 * Use the resolve timeout only with re-resolve. Here the
		 * network is setup as the transport is used. In succeeding
		 * attempts resolving is needed as it is done over potentially
		 * misconfigured WireGuard connection that may end up blocking
		 * vpnd with getaddrinfo().
		 */
		err = parse_endpoint_hostname(endpoint, option, peer, gateway4,
						gateway6);
		if (err) {
			DBG("Failed to parse peer #%d endpoint %s:%s", i,
							endpoint, option);
			continue;
		}

		/*
		 * When all values are checked, set the flags and add the peer
		 * to the list.
		 */
		peer->flags = flags;

		/* Adding the first peer. */
		if (!info->peer) {
			info->peer = peer;
			info->device.first_peer = peer;
		/* Use the last_peer set previously to add next ones. */
		} else {
			prev_peer = info->device.last_peer;
			if (prev_peer)
				prev_peer->next_peer = peer;
		}

		info->device.last_peer = peer;
		peer = peer->next_peer;

		DBG("successfully added peer #%d with id %d", i, peer_id);

		/*
		 * Split routing is disabled if one of the addresses is being
		 * used as a default route. Only one should have the default
		 * route set. Do this when all peer checks have passed.
		*/
		if (!split_routing) {
			DBG("Peer #%d is set as default route", i);
			*do_split_routing = false;
		}

		family = connman_inet_check_ipaddress(endpoint);
		if (family != AF_INET && family != AF_INET6) {
			DBG("setup DNS reresolve for peer #%d id %d endpoint %s",
							i, peer_id, endpoint);

			if (!resolv) {
				resolv = info->resolv =
					g_try_new0(struct wg_peer_resolv, 1);
			} else {
				resolv = resolv->next =
					g_try_new0(struct wg_peer_resolv, 1);
			}

			if (!resolv) {
				err = -ENOMEM;
				DBG("failed to allocate new resolv for #%d", i);
			} else {
				resolv->endpoint_fqdn = g_strdup(endpoint);
				resolv->port = g_strdup(option);
				resolv->id = peer_id;
			}
		}

		peer_id++;
	}

	return 0;
}

static int create_singlepeer(struct wireguard_info *info,
		bool *do_split_routing, char **gateway4, char **gateway6)
{
	const char *option;
	const char *endpoint;
	int family;
	int err = 0;

	DBG("");

	info->peer = g_try_new0(struct wg_peer, 1);
	if (!info->peer) {
		DBG("Failed to allocate peer");
		return -ENOMEM;
	}

	info->peer->flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS;

	option = vpn_provider_get_string(info->provider, "WireGuard.PublicKey");
	if (!option) {
		DBG("WireGuard.PublicKey is missing");
		return -EINVAL;
	}

	err = parse_key(option, info->peer->public_key);
	if (err) {
		DBG("Failed to parse public key");
		return err;
	}

	option = vpn_provider_get_string(info->provider,
						"WireGuard.PresharedKey");
	if (option) {
		info->peer->flags |= WGPEER_HAS_PRESHARED_KEY;
		err = parse_key(option, info->peer->preshared_key);
		if (err) {
			DBG("Failed to parse pre-shared key");
			return err;
		}
	}

	option = vpn_provider_get_string(info->provider,
						"WireGuard.AllowedIPs");
	if (!option) {
		DBG("WireGuard.AllowedIPs is missing");
		return -EINVAL;
	}
	err = parse_allowed_ips(option, info->peer, do_split_routing);
	if (err) {
		DBG("Failed to parse allowed IPs %s", option);
		return err;
	}

	option = vpn_provider_get_string(info->provider,
					"WireGuard.PersistentKeepalive");
	info->peer->persistent_keepalive_interval =
				parse_persistent_keepalive_interval(option);
	if (info->peer->persistent_keepalive_interval)
		info->peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;

	option = vpn_provider_get_string(info->provider,
					"WireGuard.EndpointPort");
	if (!option)
		option = "51820";

	endpoint = vpn_provider_get_string(info->provider, "Host");
	/*
	 * Use the resolve timeout only with re-resolve. Here the network
	 * is setup as the transport is used. In succeeding attempts resolving
	 * is needed as it is done over potentially misconfigured WireGuard
	 * connection that may end up blocking vpnd with getaddrinfo().
	 */
	err = parse_endpoint_hostname(endpoint, option, info->peer, gateway4,
					gateway6);
	if (err) {
		DBG("Failed to parse endpoint %s:%s", endpoint, option);
		return err;
	}

	/* Set first and last peers after the checks to indicate success. */
	info->device.first_peer = info->peer;
	info->device.last_peer = info->peer;

	family = connman_inet_check_ipaddress(endpoint);
	if (family != AF_INET && family != AF_INET6) {
		DBG("start DNS reresolve for %s", endpoint);

		info->resolv = g_try_new0(struct wg_peer_resolv, 1);
		if (!info->resolv) {
			DBG("failed to allocate new resolv");
			return -ENOMEM;
		}

		info->resolv->endpoint_fqdn = g_strdup(endpoint);
		info->resolv->port = g_strdup(option);
		info->resolv->id = 0;
	}

	return 0;
}

static int wg_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb,
			const char *dbus_sender, void *user_data)
{
	struct wg_ipaddresses ipaddresses = { 0 };
	struct wireguard_info *info;
	const char *option;
	char *gateway4 = NULL;
	char *gateway6 = NULL;
	char *ifname;
	bool do_split_routing = true;
	bool disable_ipv6 = false;
	int err = -EINVAL;

	info = create_private_data(provider);

	DBG("");

	vpn_provider_set_plugin_data(provider, info);
	vpn_provider_set_auth_error_limit(provider, 1);

	option = vpn_provider_get_string(provider, "WireGuard.ListenPort");
	if (option) {
		char *end;
		info->device.listen_port = g_ascii_strtoull(option, &end, 10);
		info->device.flags |= WGDEVICE_HAS_LISTEN_PORT;
	}

	option = vpn_provider_get_string(provider, "WireGuard.DNS");
	if (option) {
		err = vpn_provider_set_nameservers(provider, option);
		if (err) {
			DBG("Cannot set nameservers %s", option);
			goto error;
		}
	}

	option = vpn_provider_get_string(provider, "WireGuard.PrivateKey");
	if (!option) {
		DBG("WireGuard.PrivateKey is missing");
		goto error;
	}
	err = parse_key(option, info->device.private_key);
	if (err) {
		DBG("Failed to parse private key");
		goto error;
	}

	/*
	 * Peer has: PublickKey, PresharedKey, AllowedIPs, PersistenKeepalive
	 * Endpoint, EndpointPort
	 */
	option = vpn_provider_get_string(provider, "WireGuard.PeerCount");
	if (!option) {
		err = create_singlepeer(info, &do_split_routing, &gateway4,
					&gateway6);
	} else {
		int peercount = g_ascii_strtoull(option, NULL, 10);
		err = create_multipeer(info, peercount, &do_split_routing,
					&gateway4, &gateway6);
	}

	/* Both are supposed to be set as an indication that peers are setup. */
	if (!err && (!info->device.first_peer || !info->device.last_peer)) {
		DBG("Failed to setup any peers, mark connection as invalid");
		err = -EHOSTUNREACH;
	}

	if (err) {
		DBG("Failed to setup peer(s)");
		goto error;
	}

	vpn_provider_set_boolean(provider, "SplitRouting", do_split_routing,
							false);

	option = vpn_provider_get_string(provider, "WireGuard.Address");
	if (!option) {
		DBG("Missing WireGuard.Address configuration");
		goto error;
	}

	err = parse_addresses(option, gateway4, gateway6, &ipaddresses);
	if (err) {
		DBG("Failed to parse addresses %s gateway v4 %s gateway v6 %s",
						option, gateway4, gateway6);
		goto error;
	}
	g_free(gateway4);
	g_free(gateway6);

	ifname = get_ifname();
	if (!ifname) {
		DBG("Failed to find an usable device name");
		err = -ENOENT;
		goto done;
	}
	stpncpy(info->device.name, ifname, sizeof(info->device.name) - 1);
	g_free(ifname);

	err = wg_add_device(info->device.name);
	if (err) {
		DBG("Failed to create WireGuard device %s", info->device.name);
		goto done;
	}

	err = wg_set_device(&info->device);
	if (err) {
		DBG("Failed to configure WireGuard device %s", info->device.name);
		wg_del_device(info->device.name);
	}

	vpn_set_ifname(provider, info->device.name);

	if (ipaddresses.ipaddress_ipv4)
		vpn_provider_set_ipaddress(provider,
						ipaddresses.ipaddress_ipv4);

	if (ipaddresses.ipaddress_ipv6)
		vpn_provider_set_ipaddress(provider,
						ipaddresses.ipaddress_ipv6);
	else
		/*
		 * No IPv6 address when using as default route with IPv6
		 * prevention enabled = do not tunnel IPv6.
		 */
		disable_ipv6 = vpn_provider_get_boolean(provider,
					"WireGuard.DisableIPv6", false) &&
					!do_split_routing;

	vpn_provider_set_supported_ip_networks(provider, true, !disable_ipv6);

done:
	if (cb)
		cb(provider, user_data, -err);

	connman_ipaddress_free(ipaddresses.ipaddress_ipv4);
	connman_ipaddress_free(ipaddresses.ipaddress_ipv6);

	if (!err) {
		/* Run DNS reresolve only for hostnames that require resolve. */
		struct wg_peer_resolv *resolv;
		for (resolv = info->resolv; resolv; resolv = resolv->next) {
			resolv->data.info = info;
			resolv->data.resolv = resolv;
			run_dns_reresolve(&resolv->data);
		}

		run_route_setup(info, ROUTE_SETUP_TIMEOUT);
	}

	return err;

error:
	/* 
	 * TODO: add own category for parameter errors. This is to avoid
	 * looping when parameters are incorrect and VPN stays in failed
	 * state.
	 */
	if (err == -EHOSTUNREACH) {
		vpn_provider_add_error(provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);
	} else {
		vpn_provider_add_error(provider,
					VPN_PROVIDER_ERROR_LOGIN_FAILED);
		err = -ECONNABORTED;
	}

	goto done;
}

struct wireguard_exit_data {
	struct vpn_provider *provider;
	int err;
};

static gboolean wg_died(gpointer user_data)
{
	struct wireguard_exit_data *data = user_data;
	struct wireguard_info *info;

	DBG("");

	/* No task for no daemon VPN - use vpn_died() with no task. */
	vpn_died(NULL, data->err, data->provider);

	info = vpn_provider_get_plugin_data(data->provider);
	if (info)
		free_private_data(info);

	g_free(data);

	return G_SOURCE_REMOVE;
}

/* Allow to overrule the exit code for vpn_died */
static int disconnect(struct vpn_provider *provider, int err)
{
	struct wireguard_exit_data *data;
	struct wireguard_info *info;
	struct wg_peer_resolv *resolv;
	int exit_code;

	DBG("");

	info = vpn_provider_get_plugin_data(provider);
	if (!info)
		return -ENODATA;

	if (info->dying_id)
		return -EALREADY;

	if (info->route_setup_id)
		g_source_remove(info->route_setup_id);

	for (resolv = info->resolv; resolv; resolv = resolv->next) {
		if (resolv->reresolve_id)
			g_source_remove(resolv->reresolve_id);

		if (resolv->resolv || resolv->resolv_id)
			remove_resolv(resolv);
	}

	vpn_provider_set_state(provider, VPN_PROVIDER_STATE_DISCONNECT);

	exit_code = wg_del_device(info->device.name);

	/* Simulate a task-running VPN to issue vpn_died after exiting this */
	data = g_malloc0(sizeof(struct wireguard_exit_data));
	data->provider = provider;
	data->err = err ? err : exit_code;

	info->dying_id = g_timeout_add(50, wg_died, data);

	return exit_code;
}

static void wg_disconnect(struct vpn_provider *provider)
{
	int exit_code;

	DBG("");

	exit_code = disconnect(provider, 0);

	DBG("exited with %d", exit_code);
}

static int wg_error_code(struct vpn_provider *provider, int exit_code)
{
	DBG("exit_code %d", exit_code);

	switch (exit_code) {
	/* Failed to parse configuration -> wg_del_device() has no to delete */
	case -ENODEV:
		return 0;
	default:
		return exit_code;
	}
}

static int wg_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	char *str;
	char *end;
	int peercount;
	int i;
	int j;

	option = vpn_provider_get_string(provider, "WireGuard.PeerCount");
	peercount = option ? g_ascii_strtoull(option, &end, 10) : 0;

	for (i = 0; i < (int)ARRAY_SIZE(wg_options); i++) {
		if (!wg_options[i].save)
			continue;

		if (!wg_options[i].peer_option || (wg_options[i].peer_option &&
								!peercount))
			str = get_wg_opt(wg_options[i].opt,
						wg_options[i].peer_option, -1);
		else {
			DBG("skip %s, peers: %d", wg_options[i].opt, peercount);
			continue;
		}

		DBG("%s", str);

		option = vpn_provider_get_string(provider, str);
		if (option)
			g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					str, option);

		g_free(str);
	}

	if (!peercount)
		return 0;

	for (i = 0; i < peercount; i++) {
		for (j = 0; j < (int)ARRAY_SIZE(wg_options); j++) {
			if (!wg_options[j].save || !wg_options[j].peer_option)
				continue;

			str = get_wg_opt(wg_options[j].opt,
						wg_options[j].peer_option, i);
			DBG("%s", str);

			option = vpn_provider_get_string(provider, str);
			if (option)
				g_key_file_set_string(keyfile,
						vpn_provider_get_save_group(
								provider),
						str, option);

			g_free(str);
		}
	}

	return 0;
}

bool wg_uses_vpn_agent(struct vpn_provider *provider)
{
	return false;
}

static struct vpn_driver vpn_driver = {
	.flags		= VPN_FLAG_NO_TUN | VPN_FLAG_NO_DAEMON,
	.connect	= wg_connect,
	.disconnect	= wg_disconnect,
	.save		= wg_save,
	.error_code	= wg_error_code,
	.uses_vpn_agent	= wg_uses_vpn_agent
};

static int wg_init(void)
{
	return vpn_register("wireguard", &vpn_driver, NULL);
}

static void wg_exit(void)
{
	vpn_unregister("wireguard");
}

CONNMAN_PLUGIN_DEFINE(wireguard, "WireGuard VPN plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, wg_init, wg_exit)
