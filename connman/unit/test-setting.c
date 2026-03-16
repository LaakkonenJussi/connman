/*
 *  ConnMan setting unit tests
 *
 *  Copyright (C) 2025 Jolla Ltd.
 *
 *  Contact: jussi.laakkonen@jolla.com
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

#include "src/connman.h"
#include <connman/setting.h>

int __connman_device_request_scan(enum connman_service_type type)
{
	return 0;
}

int __connman_ipconfig_ipv6_set_privacy(struct connman_ipconfig *ipconfig,
		const char *value)
{
	return 0;
}


void __connman_iptables_validate_init(void)
{
	return;
}

void __connman_service_auto_connect(enum connman_service_connect_reason reason)
{
	return;
}

int __connman_service_connect(struct connman_service *service,
		enum connman_service_connect_reason reason)
{
	return 0;
}

int __connman_service_disconnect(struct connman_service *service)
{
	return 0;
}

struct connman_ipconfig *__connman_service_get_ip6config(
		struct connman_service *service)
{
	return NULL;
}

struct connman_network *__connman_service_get_network(struct connman_service *service)
{
	return NULL;
}

int __connman_service_load_modifiable(struct connman_service *service)
{
	return 0;
}

void __connman_service_mark_dirty()
{
	return;
}

int __connman_service_nameserver_append(struct connman_service *service,
		const char *nameserver, bool is_auto)
{
	return 0;
}

void __connman_service_nameserver_clear(struct connman_service *service)
{
	return;
}

int __connman_service_provision_changed(const char *ident)
{
	return 0;
}

bool __connman_service_remove(struct connman_service *service)
{
	return true;
}

int __connman_service_reset_ipconfig(struct connman_service *service,
		enum connman_ipconfig_type type, DBusMessageIter *array,
		enum connman_service_state *new_state)
{
	return 0;
}

void __connman_service_set_config(struct connman_service *service,
		const char *file_id, const char *section)
{
	return;
}

void __connman_service_set_domainname(struct connman_service *service,
		const char *domainname)
{
	return;
}

int __connman_service_set_favorite_delayed(struct connman_service *service,
		bool favorite,
		bool delay_ordering)
{
	return 0;
}

void __connman_service_set_hidden(struct connman_service *service)
{
	return;
}

int __connman_service_set_ignore(struct connman_service *service,
		bool ignore)
{
	return 0;
}

int __connman_service_set_immutable(struct connman_service *service,
		bool immutable)
{
	return 0;
}

int __connman_service_set_mdns(struct connman_service *service,
		bool enabled)
{
	return 0;
}

void __connman_service_set_search_domains(struct connman_service *service,
		char **domains)
{
	return;
}

void __connman_service_set_string(struct connman_service *service,
		const char *key, const char *value)
{
	return;
}

void __connman_service_set_boolean(struct connman_service *service,
		const char *key, bool value)
{
	return;
}

void __connman_service_set_timeservers(struct connman_service *service,
		char **timeservers)
{
	return;
}

enum connman_service_security __connman_service_string2security(const char *str)
{
	return 0;
}

enum connman_service_type __connman_service_string2type(const char *str)
{
	if (!str)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	if (strncmp(str, "ethernet", 8) == 0)
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	if (strncmp(str, "gadget", 6) == 0)
		return CONNMAN_SERVICE_TYPE_GADGET;
	if (strncmp(str, "wifi", 4) == 0)
		return CONNMAN_SERVICE_TYPE_WIFI;
	if (strncmp(str, "cellular", 8) == 0)
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	if (strncmp(str, "bluetooth", 9) == 0)
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	if (strncmp(str, "vpn", 3) == 0)
		return CONNMAN_SERVICE_TYPE_VPN;
	if (strncmp(str, "gps", 3) == 0)
		return CONNMAN_SERVICE_TYPE_GPS;
	if (strncmp(str, "system", 6) == 0)
		return CONNMAN_SERVICE_TYPE_SYSTEM;
	if (strncmp(str, "p2p", 3) == 0)
		return CONNMAN_SERVICE_TYPE_P2P;

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

GKeyFile *__connman_storage_load_config(const char *ident)
{
	return NULL;
}

bool __connman_storage_remove_service(const char *service_id)
{
	return true;
}

int __connman_util_get_random(uint64_t *val)
{
	return 0;
}

const char *connman_device_get_string(struct connman_device *device,
		const char *key)
{
	return NULL;
}

int connman_inet_check_ipaddress(const char *host)
{
	size_t len;
	int last;

	if (!host)
		return -1;

	len = strlen(host);
	if (len < 7)
		return -1;

	last = atoi(host+(len-1));

	if (g_str_has_prefix(host, "127.0.0.") && last > 0 && last < 9)
		return 1;

	return 0;
}

int connman_inotify_register(const char *path, inotify_event_cb callback,
		gpointer user_data,
		GDestroyNotify free_func)
{
	return 0;
}

void connman_inotify_unregister(const char *path, inotify_event_cb callback,
		gpointer user_data)
{
	return;
}

struct connman_ipaddress *connman_ipaddress_alloc(int family)
{
	return NULL;
}

void connman_ipaddress_free(struct connman_ipaddress *ipaddress)
{
	return;
}

int connman_ipaddress_set_ipv4(struct connman_ipaddress *ipaddress,
		const char *address, const char *netmask,
		const char *gateway)
{
	return 0;
}

int connman_ipaddress_set_ipv6(struct connman_ipaddress *ipaddress,
		const char *address,
		unsigned char prefix_length,
		const char *gateway)
{
	return 0;
}

const void *connman_network_get_blob(struct connman_network *network,
		const char *key, unsigned int *size)
{
	return NULL;
}

struct connman_device *connman_network_get_device(struct connman_network *network)
{
	return NULL;
}

const char *connman_network_get_identifier(struct connman_network *network)
{
	return NULL;
}

const char *connman_network_get_string(struct connman_network *network,
		const char *key)
{
	return NULL;
}

int connman_network_set_ipaddress(struct connman_network *network,
		struct connman_ipaddress *ipaddress)
{
	return 0;
}

void connman_network_set_ipv4_method(struct connman_network *network,
		enum connman_ipconfig_method method)
{
	return;
}

void connman_network_set_ipv6_method(struct connman_network *network,
		enum connman_ipconfig_method method)
{
	return;
}

int connman_notifier_register(const struct connman_notifier *notifier)
{
	return 0;
}

void connman_notifier_unregister(const struct connman_notifier *notifier)
{
	return;
}

const char *connman_service_get_identifier(struct connman_service *service)
{
	return NULL;
}

enum connman_service_type connman_service_get_type(struct connman_service *service)
{
	return 0;
}

struct connman_service *connman_service_lookup_from_identifier(const char* identifier)
{
	return NULL;
}

const char *connman_storage_dir(void)
{
	return NULL;
}

const char *connman_storage_user_dir(void)
{
	return NULL;
}


static char *config_empty[] = {
	"",
	NULL
};

static char *config_ok[] = {
	"[General]",
	"Ipv6StatusUrl = http://url6.something/204",
	"Ipv4StatusUrl = http://url.something/204",
	"TetheringSubnetBlock = 10.10.10.0",
	"BackgroundScanning = true",
	"FallbackTimeservers = 127.0.0.1,127.0.0.2",
	"DefaultAutoConnectTechnologies = ethernet,wifi",
	"DefaultFavoriteTechnologies = wifi",
	"AlwaysConnectedTechnologies = ethernet,cellular",
	"PreferredTechnologies = ethernet,wifi",
	"FallbackNameservers = 127.0.0.3",
	"InputRequestTimeout = 10",
	"BrowserLaunchTimeout = 15",
	"NetworkInterfaceBlacklist = p2p,usb",
	"AllowHostnameUpdates = true",
	"AllowDomainnameUpdates = true",
	"SingleConnectedTechnology = true",
	"TetheringTechnologies = wifi",
	"PersistentTetheringMode = true",
	"DontBringDownAtStartup = usb",
	"DisablePlugins = ofono",
	"FileSystemIdentity = fsid1",
	"StorageRoot = /var/lib/",
	"StorageRootPermissions = 0600",
	"StorageDirPermissions = 0655",
	"StorageFilePermissions = 0765",
	"UserStorage = .private/",
	"Umask = 0200",
	"Enable6to4 = true",
	"VendorClassID = id123",
	"EnableOnlineCheck = true",
	"AutoConnectRoamingServices = true",
	"AddressConflictDetection = true",
	"UseGatewaysAsTimeservers = true",
	"FallbackDeviceTypes = rndis0:gadget,usb0:p2p",
	"EnableLoginManager = true",
	"Localtime = /var/local/lib/localtime",
	"RegdomFollowsTimezone = true",
	"OnlineCheckInitialInterval = 100",
	"OnlineCheckMaxInterval = 1000",
	NULL
};

static GKeyFile* load_config_data(char **data)
{
	GKeyFile *config;
	GError *error = NULL;
	char *conf_data;

	config = g_key_file_new();
	g_assert(config);

	conf_data = g_strjoinv("\n", data);

	g_key_file_set_list_separator(config, ',');
	g_assert_true(g_key_file_load_from_data(config, conf_data, -1,
						G_KEY_FILE_NONE, &error));
	g_assert_null(error);

	g_clear_error(&error);
	g_free(conf_data);

	return config;
}

static bool do_init = true;
static bool do_cleanup = true;
static bool do_load = true;
static bool do_main = true;

static void setting_test_basic0(void)
{
	GKeyFile *config = NULL;
	char **str_list;
	unsigned int *int_values;
	mode_t mode;

	if (do_init)
		__connman_setting_init();

	if (do_load) {
		config = load_config_data(config_ok);
		__connman_setting_read_config_values(config, do_main, false);
	}

	g_assert_true(connman_setting_get_bool(CONF_BG_SCAN));

	g_assert_cmpstr(connman_setting_get_string(CONF_STATUS_URL_IPV4), ==,
					"http://url.something/204");
	g_assert_cmpstr(connman_setting_get_string(CONF_STATUS_URL_IPV6), ==,
					"http://url6.something/204");
	g_assert_cmpstr(connman_setting_get_string(CONF_TETHERING_SUBNET_BLOCK),
					==, "10.10.10.0");

	str_list = connman_setting_get_string_list(CONF_FALLBACK_TIMESERVERS);
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 2);
	g_assert_cmpstr(str_list[0], ==, "127.0.0.1");
	g_assert_cmpstr(str_list[1], ==, "127.0.0.2");

	int_values = connman_setting_get_uint_list(CONF_AUTO_CONNECT_TECHS);
	g_assert(int_values);
	g_assert_cmpuint(int_values[0], ==, CONNMAN_SERVICE_TYPE_ETHERNET);
	g_assert_cmpuint(int_values[1], ==, CONNMAN_SERVICE_TYPE_WIFI);
	g_assert_cmpuint(int_values[2], ==, CONNMAN_SERVICE_TYPE_UNKNOWN);

	int_values = connman_setting_get_uint_list(CONF_FAVORITE_TECHS);
	g_assert(int_values);
	g_assert_cmpuint(int_values[0], ==, CONNMAN_SERVICE_TYPE_WIFI);
	g_assert_cmpuint(int_values[1], ==, CONNMAN_SERVICE_TYPE_UNKNOWN);

	int_values = connman_setting_get_uint_list(CONF_PREFERRED_TECHS);
	g_assert(int_values);
	g_assert_cmpuint(int_values[0], ==, CONNMAN_SERVICE_TYPE_ETHERNET);
	g_assert_cmpuint(int_values[1], ==, CONNMAN_SERVICE_TYPE_WIFI);
	g_assert_cmpuint(int_values[2], ==, CONNMAN_SERVICE_TYPE_UNKNOWN);

	int_values = connman_setting_get_uint_list(CONF_ALWAYS_CONNECTED_TECHS);
	g_assert(int_values);
	g_assert_cmpuint(int_values[0], ==, CONNMAN_SERVICE_TYPE_ETHERNET);
	g_assert_cmpuint(int_values[1], ==, CONNMAN_SERVICE_TYPE_CELLULAR);
	g_assert_cmpuint(int_values[2], ==, CONNMAN_SERVICE_TYPE_UNKNOWN);

	str_list = connman_setting_get_string_list(CONF_FALLBACK_NAMESERVERS);
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 1);
	g_assert_cmpstr(str_list[0], ==, "127.0.0.3");

	g_assert_cmpuint(connman_timeout_input_request(), ==, 10*1000);
	g_assert_cmpuint(connman_timeout_browser_launch(), ==, 15*1000);

	str_list = connman_setting_get_string_list(CONF_BLACKLISTED_INTERFACES);
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 2);
	g_assert_cmpstr(str_list[0], ==, "p2p");
	g_assert_cmpstr(str_list[1], ==, "usb");

	g_assert_true(connman_setting_get_bool(CONF_ALLOW_HOSTNAME_UPDATES));
	g_assert_true(connman_setting_get_bool(CONF_ALLOW_DOMAINNAME_UPDATES));
	g_assert_true(connman_setting_get_bool(CONF_SINGLE_TECH));

	str_list = connman_setting_get_string_list(CONF_TETHERING_TECHNOLOGIES);
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 1);
	g_assert_cmpstr(str_list[0], ==, "wifi");

	g_assert_true(connman_setting_get_bool(CONF_PERSISTENT_TETHERING_MODE));

	str_list = connman_setting_get_string_list(
					CONF_DONT_BRING_DOWN_AT_STARTUP);
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 1);
	g_assert_cmpstr(str_list[0], ==, "usb");

	g_assert_cmpstr(connman_setting_get_string(CONF_OPTION_NOPLUGIN), ==,
					"ofono");

	g_assert_cmpstr(connman_setting_get_string(CONF_FILE_SYSTEM_IDENTITY),
					==, "fsid1");
	g_assert_cmpstr(connman_setting_get_string(CONF_STORAGE_ROOT), ==,
					"/var/lib/");

	mode = connman_setting_get_fs_mode(CONF_STORAGE_ROOT_PERMISSIONS);
	g_assert_cmpint(mode, ==, 0600);
	mode = connman_setting_get_fs_mode(CONF_STORAGE_DIR_PERMISSIONS);
	g_assert_cmpint(mode, ==, 0655);
	mode = connman_setting_get_fs_mode(CONF_STORAGE_FILE_PERMISSIONS);
	g_assert_cmpint(mode, ==, 0765);

	g_assert_cmpstr(connman_setting_get_string(CONF_USER_STORAGE_DIR), ==,
					".private/");

	mode = connman_setting_get_fs_mode(CONF_UMASK);
	g_assert_cmpint(mode, ==, 0200);

	g_assert_true(connman_setting_get_bool(CONF_ENABLE_6TO4));

	g_assert_cmpstr(connman_setting_get_string(CONF_VENDOR_CLASS_ID), ==,
					"id123");
	
	g_assert_true(connman_setting_get_bool(CONF_ENABLE_ONLINE_CHECK));
	g_assert_true(connman_setting_get_bool(
					CONF_AUTO_CONNECT_ROAMING_SERVICES));
	g_assert_true(connman_setting_get_bool(CONF_ACD));
	g_assert_true(connman_setting_get_bool(
					CONF_USE_GATEWAYS_AS_TIMESERVERS));

	g_assert_cmpstr(__connman_setting_get_fallback_device_type("rndis0"),
					==, "gadget");
	g_assert_cmpstr(__connman_setting_get_fallback_device_type("usb0"),
					==, "p2p");

	g_assert_true(connman_setting_get_bool(CONF_ENABLE_LOGIN_MANAGER));
	g_assert_cmpstr(connman_setting_get_string(CONF_LOCALTIME), ==,
					"/var/local/lib/localtime");

	g_assert_true(connman_setting_get_bool(CONF_REGDOM_FOLLOWS_TIMEZONE));

	g_assert_cmpuint(connman_setting_get_uint(
					CONF_ONLINE_CHECK_INITIAL_INTERVAL), ==,
					100);
	g_assert_cmpuint(connman_setting_get_uint(
					CONF_ONLINE_CHECK_MAX_INTERVAL), ==,
					1000);

	if (do_cleanup)
		__connman_setting_cleanup();

	if (config)
		g_key_file_unref(config);
}

static void setting_test_basic1(void)
{
	char **str_list;
	unsigned int *int_values;
	mode_t mode;

	do_init = do_load = do_main = true;
	do_cleanup = false;

	/*
	 * Load first with defined names then read the same with the strings
	 * to make sure these are not changed as in code these are mostly used
	 */
	setting_test_basic0();

	g_assert_true(connman_setting_get_bool("BackgroundScanning"));

	g_assert_cmpstr(connman_setting_get_string("Ipv4StatusUrl"), ==,
					"http://url.something/204");
	g_assert_cmpstr(connman_setting_get_string("Ipv6StatusUrl"), ==,
					"http://url6.something/204");
	g_assert_cmpstr(connman_setting_get_string("TetheringSubnetBlock"),
					==, "10.10.10.0");

	str_list = connman_setting_get_string_list("FallbackTimeservers");
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 2);
	g_assert_cmpstr(str_list[0], ==, "127.0.0.1");
	g_assert_cmpstr(str_list[1], ==, "127.0.0.2");

	int_values = connman_setting_get_uint_list(
					"DefaultAutoConnectTechnologies");
	g_assert(int_values);
	g_assert_cmpuint(int_values[0], ==, CONNMAN_SERVICE_TYPE_ETHERNET);
	g_assert_cmpuint(int_values[1], ==, CONNMAN_SERVICE_TYPE_WIFI);
	g_assert_cmpuint(int_values[2], ==, CONNMAN_SERVICE_TYPE_UNKNOWN);

	int_values = connman_setting_get_uint_list(
					"DefaultFavoriteTechnologies");
	g_assert(int_values);
	g_assert_cmpuint(int_values[0], ==, CONNMAN_SERVICE_TYPE_WIFI);
	g_assert_cmpuint(int_values[1], ==, CONNMAN_SERVICE_TYPE_UNKNOWN);

	int_values = connman_setting_get_uint_list("PreferredTechnologies");
	g_assert(int_values);
	g_assert_cmpuint(int_values[0], ==, CONNMAN_SERVICE_TYPE_ETHERNET);
	g_assert_cmpuint(int_values[1], ==, CONNMAN_SERVICE_TYPE_WIFI);
	g_assert_cmpuint(int_values[2], ==, CONNMAN_SERVICE_TYPE_UNKNOWN);

	int_values = connman_setting_get_uint_list(
					"AlwaysConnectedTechnologies");
	g_assert(int_values);
	g_assert_cmpuint(int_values[0], ==, CONNMAN_SERVICE_TYPE_ETHERNET);
	g_assert_cmpuint(int_values[1], ==, CONNMAN_SERVICE_TYPE_CELLULAR);
	g_assert_cmpuint(int_values[2], ==, CONNMAN_SERVICE_TYPE_UNKNOWN);

	str_list = connman_setting_get_string_list("FallbackNameservers");
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 1);
	g_assert_cmpstr(str_list[0], ==, "127.0.0.3");

	g_assert_cmpuint(connman_timeout_input_request(), ==, 10*1000);
	g_assert_cmpuint(connman_timeout_browser_launch(), ==, 15*1000);

	str_list = connman_setting_get_string_list("NetworkInterfaceBlacklist");
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 2);
	g_assert_cmpstr(str_list[0], ==, "p2p");
	g_assert_cmpstr(str_list[1], ==, "usb");

	g_assert_true(connman_setting_get_bool("AllowHostnameUpdates"));
	g_assert_true(connman_setting_get_bool("AllowDomainnameUpdates"));
	g_assert_true(connman_setting_get_bool("SingleConnectedTechnology"));

	str_list = connman_setting_get_string_list("TetheringTechnologies");
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 1);
	g_assert_cmpstr(str_list[0], ==, "wifi");

	g_assert_true(connman_setting_get_bool("PersistentTetheringMode"));

	str_list = connman_setting_get_string_list("DontBringDownAtStartup");
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 1);
	g_assert_cmpstr(str_list[0], ==, "usb");

	g_assert_cmpstr(connman_setting_get_string("DisablePlugins"), ==,
					"ofono");
	g_assert_cmpstr(connman_setting_get_string("noplugin"), ==, "ofono");

	g_assert_cmpstr(connman_setting_get_string("FileSystemIdentity"),
					==, "fsid1");
	g_assert_cmpstr(connman_setting_get_string("StorageRoot"), ==,
					"/var/lib/");

	mode = connman_setting_get_fs_mode("StorageRootPermissions");
	g_assert_cmpint(mode, ==, 0600);
	mode = connman_setting_get_fs_mode("StorageDirPermissions");
	g_assert_cmpint(mode, ==, 0655);
	mode = connman_setting_get_fs_mode("StorageFilePermissions");
	g_assert_cmpint(mode, ==, 0765);

	g_assert_cmpstr(connman_setting_get_string("UserStorage"), ==,
					".private/");

	mode = connman_setting_get_fs_mode("Umask");
	g_assert_cmpint(mode, ==, 0200);

	g_assert_true(connman_setting_get_bool("Enable6to4"));

	g_assert_cmpstr(connman_setting_get_string("VendorClassID"), ==,
					"id123");

	g_assert_true(connman_setting_get_bool("EnableOnlineCheck"));
	g_assert_true(connman_setting_get_bool("AutoConnectRoamingServices"));
	g_assert_true(connman_setting_get_bool("AddressConflictDetection"));
	g_assert_true(connman_setting_get_bool("UseGatewaysAsTimeservers"));

	g_assert_cmpstr(__connman_setting_get_fallback_device_type("rndis0"),
					==, "gadget");
	g_assert_cmpstr(__connman_setting_get_fallback_device_type("usb0"),
					==, "p2p");

	g_assert_true(connman_setting_get_bool("EnableLoginManager"));
	g_assert_cmpstr(connman_setting_get_string("Localtime"), ==,
					"/var/local/lib/localtime");

	g_assert_true(connman_setting_get_bool("RegdomFollowsTimezone"));

	g_assert_cmpuint(connman_setting_get_uint("OnlineCheckInitialInterval"),
					==, 100);
	g_assert_cmpuint(connman_setting_get_uint("OnlineCheckMaxInterval"), ==,
					1000);

	__connman_setting_cleanup();

	do_cleanup = true;
}

static void setting_test_defaults0(void)
{
	GKeyFile *config = NULL;
	char **str_list;
	unsigned int *int_values;
	mode_t mode;

	if (do_init)
		__connman_setting_init();

	if (do_load) {
		config = load_config_data(config_empty);
		__connman_setting_read_config_values(config, do_main, false);
	}

	g_assert_true(connman_setting_get_bool(CONF_BG_SCAN));

	g_assert_cmpstr(connman_setting_get_string(CONF_STATUS_URL_IPV4), ==,
				"http://ipv4.connman.net/online/status.html");
	g_assert_cmpstr(connman_setting_get_string(CONF_STATUS_URL_IPV6), ==,
				"http://ipv6.connman.net/online/status.html");
	g_assert_cmpstr(connman_setting_get_string(CONF_TETHERING_SUBNET_BLOCK),
				==, "192.168.0.0");

	str_list = connman_setting_get_string_list(CONF_FALLBACK_TIMESERVERS);
	g_assert_null(str_list);

	int_values = connman_setting_get_uint_list(CONF_AUTO_CONNECT_TECHS);
	g_assert(int_values);
	g_assert_cmpuint(int_values[0], ==, 0);

	int_values = connman_setting_get_uint_list(CONF_FAVORITE_TECHS);
	g_assert(int_values);
	g_assert_cmpuint(int_values[0], ==, CONNMAN_SERVICE_TYPE_ETHERNET);

	int_values = connman_setting_get_uint_list(CONF_PREFERRED_TECHS);
	g_assert_null(int_values);

	int_values = connman_setting_get_uint_list(CONF_ALWAYS_CONNECTED_TECHS);
	g_assert_null(int_values);

	str_list = connman_setting_get_string_list(CONF_FALLBACK_NAMESERVERS);
	g_assert_null(str_list);

	g_assert_cmpuint(connman_timeout_input_request(), ==, 120*1000);
	g_assert_cmpuint(connman_timeout_browser_launch(), ==, 300*1000);

	str_list = connman_setting_get_string_list(CONF_BLACKLISTED_INTERFACES);
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 6);
	g_assert_cmpstr(str_list[0], ==, "vmnet");
	g_assert_cmpstr(str_list[1], ==, "vboxnet");
	g_assert_cmpstr(str_list[2], ==, "virbr");
	g_assert_cmpstr(str_list[3], ==, "ifb");
	g_assert_cmpstr(str_list[4], ==, "ve-");
	g_assert_cmpstr(str_list[5], ==, "vb-");

	g_assert_true(connman_setting_get_bool(CONF_ALLOW_HOSTNAME_UPDATES));
	g_assert_true(connman_setting_get_bool(CONF_ALLOW_DOMAINNAME_UPDATES));
	g_assert_false(connman_setting_get_bool(CONF_SINGLE_TECH));

	str_list = connman_setting_get_string_list(CONF_TETHERING_TECHNOLOGIES);
	g_assert_null(str_list);

	g_assert_false(connman_setting_get_bool(CONF_PERSISTENT_TETHERING_MODE));

	str_list = connman_setting_get_string_list(
					CONF_DONT_BRING_DOWN_AT_STARTUP);
	g_assert_null(str_list);

	g_assert_null(connman_setting_get_string(CONF_OPTION_NOPLUGIN));

	g_assert_null(connman_setting_get_string(CONF_FILE_SYSTEM_IDENTITY));
	g_assert_cmpstr(connman_setting_get_string(CONF_STORAGE_ROOT), ==,
					"/var/lib");

	mode = connman_setting_get_fs_mode(CONF_STORAGE_ROOT_PERMISSIONS);
	g_assert_cmpint(mode, ==, 0755);
	mode = connman_setting_get_fs_mode(CONF_STORAGE_DIR_PERMISSIONS);
	g_assert_cmpint(mode, ==, 0700);
	mode = connman_setting_get_fs_mode(CONF_STORAGE_FILE_PERMISSIONS);
	g_assert_cmpint(mode, ==, 0600);

	g_assert_cmpstr(connman_setting_get_string(CONF_USER_STORAGE_DIR), ==,
					".config");

	mode = connman_setting_get_fs_mode(CONF_UMASK);
	g_assert_cmpint(mode, ==, 0077);

	g_assert_false(connman_setting_get_bool(CONF_ENABLE_6TO4));

	g_assert_null(connman_setting_get_string(CONF_VENDOR_CLASS_ID));
	
	g_assert_true(connman_setting_get_bool(CONF_ENABLE_ONLINE_CHECK));
	g_assert_false(connman_setting_get_bool(
					CONF_AUTO_CONNECT_ROAMING_SERVICES));
	g_assert_false(connman_setting_get_bool(CONF_ACD));
	g_assert_false(connman_setting_get_bool(
					CONF_USE_GATEWAYS_AS_TIMESERVERS));

	g_assert_null(__connman_setting_get_fallback_device_type("rndis0"));
	g_assert_null(__connman_setting_get_fallback_device_type("usb0"));

	g_assert_false(connman_setting_get_bool(CONF_ENABLE_LOGIN_MANAGER));
	g_assert_cmpstr(connman_setting_get_string(CONF_LOCALTIME), ==,
					"/etc/localtime");

	g_assert_false(connman_setting_get_bool(CONF_REGDOM_FOLLOWS_TIMEZONE));

	g_assert_cmpuint(connman_setting_get_uint(
					CONF_ONLINE_CHECK_INITIAL_INTERVAL), ==,
					1);
	g_assert_cmpuint(connman_setting_get_uint(
					CONF_ONLINE_CHECK_MAX_INTERVAL), ==,
					12);

	if (do_cleanup)
		__connman_setting_cleanup();

	if (config)
		g_key_file_unref(config);
}

static void setting_test_load_confd0(void)
{
	do_init = do_cleanup = false;

	__connman_setting_init();

	/* Load empty config and then new config as additional one*/
	setting_test_defaults0();
	do_main = false;
	setting_test_basic0();

	__connman_setting_cleanup();

	do_init = do_cleanup = do_main = true;
}

static char *conf0[] = {
	"[General]",
	NULL
};

static char *conf_bool[] = {
	"[General]",
	"BackgroundScanning = false",
	NULL
};

static char *conf_uint[] = {
	"[General]",
	"InputRequestTimeout = 5",
	NULL
};

static char *conf_uint_list[] = {
	"[General]",
	"DefaultAutoConnectTechnologies = cellular,wifi,usb",
	NULL
};

static char *conf_str[] = {
	"[General]",
	"StorageRoot = /root/temp",
	NULL
};

static char *conf_str_list[] = {
	"[General]",
	"NetworkInterfaceBlacklist = eth,wlan",
	NULL
};

static void setting_test_load_confd1(void)
{
	GKeyFile *config;
	char **str_list;
	unsigned int *int_values;

	do_init = do_cleanup = false;

	__connman_setting_init();

	/* Load empty config with defaults*/
	setting_test_defaults0();

	/* Then empty config and check default values*/
	config = load_config_data(conf0);
	__connman_setting_read_config_values(config, false, false);
	g_key_file_unref(config);

	do_load = do_main = false;
	setting_test_defaults0();

	/* Load configs with one change and check each */
	config = load_config_data(conf_bool);
	__connman_setting_read_config_values(config, false, false);
	g_key_file_unref(config);

	g_assert_false(connman_setting_get_bool(CONF_BG_SCAN));

	config = load_config_data(conf_uint);
	__connman_setting_read_config_values(config, false, false);
	g_key_file_unref(config);

	g_assert_cmpint(connman_timeout_input_request(), ==, 5*1000);

	config = load_config_data(conf_uint_list);
	__connman_setting_read_config_values(config, false, false);
	g_key_file_unref(config);

	int_values = connman_setting_get_uint_list(CONF_AUTO_CONNECT_TECHS);
	g_assert(int_values);
	g_assert_cmpuint(int_values[0], ==, CONNMAN_SERVICE_TYPE_CELLULAR);
	g_assert_cmpuint(int_values[1], ==, CONNMAN_SERVICE_TYPE_WIFI);
	/* Usb is not known */
	g_assert_cmpuint(int_values[2], ==, CONNMAN_SERVICE_TYPE_UNKNOWN);


	config = load_config_data(conf_str);
	__connman_setting_read_config_values(config, false, false);
	g_key_file_unref(config);

	g_assert_cmpstr(connman_setting_get_string(CONF_STORAGE_ROOT), ==, 
					"/root/temp");

	config = load_config_data(conf_str_list);
	__connman_setting_read_config_values(config, false, false);
	g_key_file_unref(config);

	str_list = connman_setting_get_string_list(CONF_BLACKLISTED_INTERFACES);
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 2);
	g_assert_cmpstr(str_list[0], ==, "eth");
	g_assert_cmpstr(str_list[1], ==, "wlan");

	/* Read a config that has no change to the string lists */
	config = load_config_data(conf_bool);
	__connman_setting_read_config_values(config, false, false);
	g_key_file_unref(config);

	/* Ensure the blacklisted interfaces are not reset to default */
	str_list = connman_setting_get_string_list(CONF_BLACKLISTED_INTERFACES);
	g_assert(str_list);
	g_assert_cmpuint(g_strv_length(str_list), ==, 2);
	g_assert_cmpstr(str_list[0], ==, "eth");
	g_assert_cmpstr(str_list[1], ==, "wlan");

	/* Then load the big config and check values */
	do_load = true;
	do_main = false;
	setting_test_basic0();

	__connman_setting_cleanup();

	do_init = do_cleanup = do_main = true;
}

static void setting_test_options0(void)
{
	__connman_setting_init();

	g_assert_null(connman_setting_get_string(CONF_OPTION_PLUGIN));
	g_assert_null(connman_setting_get_string(CONF_OPTION_NOPLUGIN));
	g_assert_null(connman_setting_get_string(CONF_OPTION_CONFIG));
	g_assert_null(connman_setting_get_string(CONF_OPTION_DEBUG));
	g_assert_null(connman_setting_get_string(CONF_OPTION_DEVICE));
	g_assert_null(connman_setting_get_string(CONF_OPTION_NODEVICE));
	g_assert_cmpstr(connman_setting_get_string(CONF_OPTION_WIFI), ==,
						"nl80211,wext");

	__connman_setting_cleanup();
}

static void setting_test_options1(void)
{
	const char *key;

	__connman_setting_init();

	key = CONF_OPTION_PLUGIN;
	__connman_setting_set_option(key, "value1");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "value1");
	__connman_setting_set_option(key, "value2");
	__connman_setting_set_option(key, "value3");
	g_assert_cmpstr(connman_setting_get_string(key), ==,
					"value1,value2,value3");

	key = CONF_OPTION_NOPLUGIN;
	__connman_setting_set_option(key, "value4");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "value4");
	__connman_setting_set_option(key, "value5");
	__connman_setting_set_option(key, "value6");
	g_assert_cmpstr(connman_setting_get_string(key), ==,
					"value4,value5,value6");
	g_assert_cmpstr(connman_setting_get_string(CONF_DISABLE_PLUGINS), ==,
					"value4,value5,value6");

	key = CONF_OPTION_CONFIG;
	__connman_setting_set_option(key, "main1.conf");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "main1.conf");
	__connman_setting_set_option(key, "main2.conf");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "main2.conf");

	key = CONF_OPTION_DEBUG;
	__connman_setting_set_option(key, NULL);
	g_assert_cmpstr(connman_setting_get_string(key), ==, "*");
	__connman_setting_set_option(key, "main.c");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "main.c");
	__connman_setting_set_option(key, "setting.c");
	__connman_setting_set_option(key, "config.c");
	g_assert_cmpstr(connman_setting_get_string(key), ==,
					"main.c,setting.c,config.c");

	key = CONF_OPTION_DEVICE;
	__connman_setting_set_option(key, "usb");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "usb");
	__connman_setting_set_option(key, "cellular,rmnet");
	g_assert_cmpstr(connman_setting_get_string(key), ==,
					"cellular,rmnet");

	key = CONF_OPTION_NODEVICE;
	__connman_setting_set_option(key, "cellular");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "cellular");
	__connman_setting_set_option(key, "wifi,rmnet");
	g_assert_cmpstr(connman_setting_get_string(key), ==,
					"wifi,rmnet");

	key = CONF_OPTION_WIFI;
	__connman_setting_set_option(key, "wext");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "wext");
	__connman_setting_set_option(key, "nl80211");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "nl80211");

	__connman_setting_cleanup();
}

static void setting_test_options2(void)
{
	const char *key;

	__connman_setting_init();

	key = "plugin";
	__connman_setting_set_option(key, "value1");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "value1");
	__connman_setting_set_option(key, "value2");
	__connman_setting_set_option(key, "value3");
	g_assert_cmpstr(connman_setting_get_string(CONF_OPTION_PLUGIN), ==,
					"value1,value2,value3");

	key = "noplugin";
	__connman_setting_set_option(key, "value4");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "value4");
	__connman_setting_set_option(key, "value5");
	__connman_setting_set_option(key, "value6");
	g_assert_cmpstr(connman_setting_get_string(CONF_OPTION_NOPLUGIN), ==,
					"value4,value5,value6");
	g_assert_cmpstr(connman_setting_get_string(CONF_DISABLE_PLUGINS), ==,
					"value4,value5,value6");

	key = "config";
	__connman_setting_set_option(key, "main1.conf");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "main1.conf");
	__connman_setting_set_option(key, "main2.conf");
	g_assert_cmpstr(connman_setting_get_string(CONF_OPTION_CONFIG), ==,
					"main2.conf");

	key = "debug";
	__connman_setting_set_option(key, NULL);
	g_assert_cmpstr(connman_setting_get_string(key), ==, "*");
	__connman_setting_set_option(key, "main.c");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "main.c");
	__connman_setting_set_option(key, "setting.c");
	__connman_setting_set_option(key, "config.c");
	g_assert_cmpstr(connman_setting_get_string(CONF_OPTION_DEBUG), ==,
					"main.c,setting.c,config.c");

	key = "device";
	__connman_setting_set_option(key, "usb");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "usb");
	__connman_setting_set_option(key, "cellular,rmnet");
	g_assert_cmpstr(connman_setting_get_string(CONF_OPTION_DEVICE), ==,
					"cellular,rmnet");

	key = "nodevice";
	__connman_setting_set_option(key, "cellular");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "cellular");
	__connman_setting_set_option(key, "wifi,rmnet");
	g_assert_cmpstr(connman_setting_get_string(CONF_OPTION_NODEVICE), ==,
					"wifi,rmnet");

	key = "wifi";
	__connman_setting_set_option(key, "wext");
	g_assert_cmpstr(connman_setting_get_string(key), ==, "wext");
	__connman_setting_set_option(key, "nl80211");
	g_assert_cmpstr(connman_setting_get_string(CONF_OPTION_WIFI), ==,
					"nl80211");

	__connman_setting_cleanup();
}

static void setting_test_error0(void)
{
	__connman_setting_init();

	__connman_setting_read_config_values(NULL, true, false);

	g_assert_false(__connman_setting_is_supported_option(NULL));
	g_assert_false(__connman_setting_is_supported_option(""));
	g_assert_false(__connman_setting_is_supported_option("NotAKey"));

	g_assert_false(connman_setting_get_bool(NULL));
	g_assert_false(connman_setting_get_bool(""));
	g_assert_false(connman_setting_get_bool("NotAKey"));

	g_assert_cmpint(connman_setting_get_uint(NULL), ==, 0);
	g_assert_cmpint(connman_setting_get_uint(""), ==, 0);
	g_assert_cmpint(connman_setting_get_uint("NotAKey"), ==, 0);

	g_assert_null(connman_setting_get_uint_list(NULL));
	g_assert_null(connman_setting_get_uint_list(""));
	g_assert_null(connman_setting_get_uint_list("NotAKey"));

	g_assert_null(connman_setting_get_string(NULL));
	g_assert_null(connman_setting_get_string(""));
	g_assert_null(connman_setting_get_string("NotAKey"));

	g_assert_null(connman_setting_get_string_list(NULL));
	g_assert_null(connman_setting_get_string_list(""));
	g_assert_null(connman_setting_get_string_list("NotAKey"));

	g_assert_cmpint(connman_setting_get_fs_mode(NULL), ==, 0);
	g_assert_cmpint(connman_setting_get_fs_mode(""), ==, 0);
	g_assert_cmpint(connman_setting_get_fs_mode("NotAKey"), ==, 0);

	g_assert_null(__connman_setting_get_fallback_device_type(NULL));
	g_assert_null(__connman_setting_get_fallback_device_type(""));
	g_assert_null(__connman_setting_get_fallback_device_type("NotAKey"));

	__connman_setting_set_option(NULL, NULL);
	__connman_setting_set_option(NULL, "");
	__connman_setting_set_option(NULL, "none");
	__connman_setting_set_option("", NULL);
	__connman_setting_set_option("", "");
	__connman_setting_set_option("", "none");
	__connman_setting_set_option("option", NULL);
	__connman_setting_set_option("option", "");
	__connman_setting_set_option("option", "none");

	__connman_setting_cleanup();
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

int main (int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	int err;

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
	__connman_iptables_validate_init();

	g_test_add_func("/setting/test_basic0", setting_test_basic0);
	g_test_add_func("/setting/test_basic1", setting_test_basic1);

	g_test_add_func("/setting/test_defaults0", setting_test_defaults0);

	g_test_add_func("/setting/test_load_config0", setting_test_load_confd0);
	g_test_add_func("/setting/test_load_config1", setting_test_load_confd1);

	g_test_add_func("/setting/test_options0", setting_test_options0);
	g_test_add_func("/setting/test_options1", setting_test_options1);
	g_test_add_func("/setting/test_options2", setting_test_options2);

	g_test_add_func("/setting/test_error0", setting_test_error0);

	err = g_test_run();

	__connman_log_cleanup(false);
	g_free(option_debug);

	return err;
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
