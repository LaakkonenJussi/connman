/*
 *
 *  Connection Manager
 *
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "connman.h"
#include "shared/util.h"

#define CONF_ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]) - 1)

#define DEFAULT_INPUT_REQUEST_TIMEOUT (120 * 1000)
#define DEFAULT_BROWSER_LAUNCH_TIMEOUT (300 * 1000)
#define DEFAULT_STOGAGE_ROOT_PERMISSIONS (0755)
#define DEFAULT_STORAGE_DIR_PERMISSIONS (0700)
#define DEFAULT_STORAGE_FILE_PERMISSIONS (0600)
#define DEFAULT_UMASK (0077)
#define DEFAULT_LOCALTIME "/etc/localtime"

/*
 * We set the integer to 1 sec so that we have a chance to get
 * necessary IPv6 router advertisement messages that might have
 * DNS data etc.
 */
#define DEFAULT_ONLINE_CHECK_INITIAL_INTERVAL 1
#define DEFAULT_ONLINE_CHECK_MAX_INTERVAL 12
#define CONF_STATUS_URL_IPV4_DEF "http://ipv4.connman.net/online/status.html"
#define CONF_STATUS_URL_IPV6_DEF "http://ipv6.connman.net/online/status.html"
#define CONF_TETHERING_SUBNET_BLOCK_DEF "192.168.0.0"
#define CONF_WIFI_DEF "nl80211,wext"

static char *default_auto_connect[] = {
	NULL
};

static char *default_favorite_techs[] = {
	"ethernet",
	NULL
};

static char *default_blacklist[] = {
	"vmnet",
	"vboxnet",
	"virbr",
	"ifb",
	"ve-",
	"vb-",
	NULL
};

static struct {
	char **fallback_timeservers;
	char **fallback_nameservers;
	char **blacklisted_interfaces;
	char **tethering_technologies;
	char **dont_bring_down_at_startup;
	char *ipv6_status_url;
	char *ipv4_status_url;
	char *tethering_subnet_block;
	char *fs_identity;
	char *storage_root;
	char *user_storage_dir;
	char *vendor_class_id;
	char *localtime;
	char *wifi_wpa3_support;
	char *wifi_wpa3_sae_pwe;
	unsigned int *auto_connect;
	unsigned int *favorite_techs;
	unsigned int *preferred_techs;
	unsigned int *always_connected_techs;
	unsigned int timeout_inputreq;
	unsigned int timeout_browserlaunch;
	unsigned int online_check_initial_interval;
	unsigned int online_check_max_interval;
	bool bg_scan;
	bool allow_hostname_updates;
	bool allow_domainname_updates;
	bool single_tech;
	bool persistent_tethering_mode;
	bool enable_6to4;
	bool enable_online_check;
	bool enable_online_to_ready_transition;
	bool auto_connect_roaming_services;
	bool acd;
	bool use_gateways_as_timeservers;
	bool enable_login_manager;
	bool regdom_follows_timezone;
	bool default_mdns_configuration;
	bool tethering_mdns_configuration;
	bool wifi_wpa3_sae_check_mfp;
	mode_t storage_root_permissions;
	mode_t storage_dir_permissions;
	mode_t storage_file_permissions;
	mode_t umask;
	GHashTable *fallback_device_types;
	gchar *option_config;
	gchar *option_debug;
	gchar *option_device;
	gchar *option_plugin;
	gchar *option_nodevice;
	gchar *option_noplugin;
	gchar *option_wifi;
} connman_settings  = { 0 };

enum option_val {
	CONF_BG_SCAN_VAL = 0,
	CONF_FALLBACK_TIMESERVERS_VAL,
	CONF_AUTO_CONNECT_TECHS_VAL,
	CONF_FAVORITE_TECHS_VAL,
	CONF_ALWAYS_CONNECTED_TECHS_VAL,
	CONF_PREFERRED_TECHS_VAL,
	CONF_FALLBACK_NAMESERVERS_VAL,
	CONF_TIMEOUT_INPUTREQ_VAL,
	CONF_TIMEOUT_BROWSERLAUNCH_VAL,
	CONF_BLACKLISTED_INTERFACES_VAL,
	CONF_ALLOW_HOSTNAME_UPDATES_VAL,
	CONF_ALLOW_DOMAINNAME_UPDATES_VAL,
	CONF_SINGLE_TECH_VAL,
	CONF_TETHERING_TECHNOLOGIES_VAL,
	CONF_PERSISTENT_TETHERING_MODE_VAL,
	CONF_FILE_SYSTEM_IDENTITY_VAL,
	CONF_STORAGE_ROOT_VAL,
	CONF_STORAGE_ROOT_PERMISSIONS_VAL,
	CONF_STORAGE_DIR_PERMISSIONS_VAL,
	CONF_STORAGE_FILE_PERMISSIONS_VAL,
	CONF_USER_STORAGE_DIR_VAL,
	CONF_UMASK_VAL,
	CONF_STATUS_URL_IPV4_VAL,
	CONF_STATUS_URL_IPV6_VAL,
	CONF_TETHERING_SUBNET_BLOCK_VAL,
	CONF_DONT_BRING_DOWN_AT_STARTUP_VAL,
	CONF_DISABLE_PLUGINS_VAL,
	CONF_ENABLE_6TO4_VAL,
	CONF_VENDOR_CLASS_ID_VAL,
	CONF_ENABLE_ONLINE_CHECK_VAL,
	CONF_ENABLE_ONLINE_TO_READY_TRANSITION_VAL,
	CONF_AUTO_CONNECT_ROAMING_SERVICES_VAL,
	CONF_ACD_VAL,
	CONF_USE_GATEWAYS_AS_TIMESERVERS_VAL,
	CONF_FALLBACK_DEVICE_TYPES_VAL,
	CONF_ENABLE_LOGIN_MANAGER_VAL,
	CONF_LOCALTIME_VAL,
	CONF_REGDOM_FOLLOWS_TIMEZONE_VAL,
	CONF_DEFAULT_MDNS_CONFIGURATION_VAL,
	CONF_TETHERING_MDNS_CONFIGURATION_VAL,
	CONF_ONLINE_CHECK_INITIAL_INTERVAL_VAL,
	CONF_ONLINE_CHECK_MAX_INTERVAL_VAL,
	CONF_WIFI_WPA3_SUPPORT_VAL,
	CONF_WIFI_WPA3_SAE_PWE_VAL,
	CONF_WIFI_WPA3_SAE_CHECK_MFP_VAL,
};

enum option_type {
	CONF_TYPE_INT = 0,
	CONF_TYPE_INTARR,
	CONF_TYPE_CHAR,
	CONF_TYPE_CHARSTR,
	CONF_TYPE_BOOL,
	CONF_TYPE_PERM
};

struct {
	const char		*opt_key;
	enum option_val		opt_value;
	enum option_type	opt_type;
} supported_options[] = {
	{CONF_BG_SCAN,
					CONF_BG_SCAN_VAL,
					CONF_TYPE_BOOL},
	{CONF_FALLBACK_TIMESERVERS,
					CONF_FALLBACK_TIMESERVERS_VAL,
					CONF_TYPE_CHARSTR},
	{CONF_AUTO_CONNECT_TECHS,
					CONF_AUTO_CONNECT_TECHS_VAL,
					CONF_TYPE_INTARR},
	{CONF_FAVORITE_TECHS,
					CONF_FAVORITE_TECHS_VAL,
					CONF_TYPE_INTARR},
	{CONF_ALWAYS_CONNECTED_TECHS,
					CONF_ALWAYS_CONNECTED_TECHS_VAL,
					CONF_TYPE_INTARR},
	{CONF_PREFERRED_TECHS,
					CONF_PREFERRED_TECHS_VAL,
					CONF_TYPE_CHARSTR},
	{CONF_FALLBACK_NAMESERVERS,
					CONF_FALLBACK_NAMESERVERS_VAL,
					CONF_TYPE_CHARSTR},
	{CONF_TIMEOUT_INPUTREQ,
					CONF_TIMEOUT_INPUTREQ_VAL,
					CONF_TYPE_INT},
	{CONF_TIMEOUT_BROWSERLAUNCH,
					CONF_TIMEOUT_BROWSERLAUNCH_VAL,
					CONF_TYPE_INT},
	{CONF_BLACKLISTED_INTERFACES,
					CONF_BLACKLISTED_INTERFACES_VAL,
					CONF_TYPE_CHARSTR},
	{CONF_ALLOW_HOSTNAME_UPDATES,
					CONF_ALLOW_HOSTNAME_UPDATES_VAL,
					CONF_TYPE_BOOL},
	{CONF_ALLOW_DOMAINNAME_UPDATES,
					CONF_ALLOW_DOMAINNAME_UPDATES_VAL,
					CONF_TYPE_BOOL},
	{CONF_SINGLE_TECH,
					CONF_SINGLE_TECH_VAL,
					CONF_TYPE_BOOL},
	{CONF_TETHERING_TECHNOLOGIES,
					CONF_TETHERING_TECHNOLOGIES_VAL,
					CONF_TYPE_CHARSTR},
	{CONF_PERSISTENT_TETHERING_MODE,
					CONF_PERSISTENT_TETHERING_MODE_VAL,
					CONF_TYPE_BOOL},
	{CONF_FILE_SYSTEM_IDENTITY,
					CONF_FILE_SYSTEM_IDENTITY_VAL,
					CONF_TYPE_CHAR},
	{CONF_STORAGE_ROOT,
					CONF_STORAGE_ROOT_VAL,
					CONF_TYPE_CHAR},
	{CONF_STORAGE_ROOT_PERMISSIONS,
					CONF_STORAGE_ROOT_PERMISSIONS_VAL,
					CONF_TYPE_PERM},
	{CONF_STORAGE_DIR_PERMISSIONS,
					CONF_STORAGE_DIR_PERMISSIONS_VAL,
					CONF_TYPE_PERM},
	{CONF_STORAGE_FILE_PERMISSIONS,
					CONF_STORAGE_FILE_PERMISSIONS_VAL,
					CONF_TYPE_PERM},
	{CONF_USER_STORAGE_DIR,
					CONF_USER_STORAGE_DIR_VAL,
					CONF_TYPE_CHAR},
	{CONF_UMASK,
					CONF_UMASK_VAL,
					CONF_TYPE_PERM},
	{CONF_STATUS_URL_IPV4,
					CONF_STATUS_URL_IPV4_VAL,
					CONF_TYPE_CHAR},
	{CONF_STATUS_URL_IPV6,
					CONF_STATUS_URL_IPV6_VAL,
					CONF_TYPE_CHAR},
	{CONF_TETHERING_SUBNET_BLOCK,
					CONF_TETHERING_SUBNET_BLOCK_VAL,
					CONF_TYPE_CHAR},
	{CONF_DONT_BRING_DOWN_AT_STARTUP,
					CONF_DONT_BRING_DOWN_AT_STARTUP_VAL,
					CONF_TYPE_BOOL},
	{CONF_DISABLE_PLUGINS,
					CONF_DISABLE_PLUGINS_VAL,
					CONF_TYPE_CHARSTR},
	{CONF_ENABLE_6TO4,
					CONF_ENABLE_6TO4_VAL,
					CONF_TYPE_BOOL},
	{CONF_VENDOR_CLASS_ID,
					CONF_VENDOR_CLASS_ID_VAL,
					CONF_TYPE_CHAR},
	{CONF_ENABLE_ONLINE_CHECK,
					CONF_ENABLE_ONLINE_CHECK_VAL,
					CONF_TYPE_BOOL},
	{CONF_ENABLE_ONLINE_TO_READY_TRANSITION,
					CONF_ENABLE_ONLINE_TO_READY_TRANSITION_VAL,
					CONF_TYPE_BOOL},
	{CONF_AUTO_CONNECT_ROAMING_SERVICES,
					CONF_AUTO_CONNECT_ROAMING_SERVICES_VAL,
					CONF_TYPE_BOOL},
	{CONF_ACD,
					CONF_ACD_VAL,
					CONF_TYPE_BOOL},
	{CONF_USE_GATEWAYS_AS_TIMESERVERS,
					CONF_USE_GATEWAYS_AS_TIMESERVERS_VAL,
					CONF_TYPE_BOOL},
	{CONF_FALLBACK_DEVICE_TYPES,
					CONF_FALLBACK_DEVICE_TYPES_VAL,
					CONF_TYPE_CHAR},
	{CONF_ENABLE_LOGIN_MANAGER,
					CONF_ENABLE_LOGIN_MANAGER_VAL,
					CONF_TYPE_BOOL},
	{CONF_LOCALTIME,
					CONF_LOCALTIME_VAL,
					CONF_TYPE_CHAR},
	{CONF_REGDOM_FOLLOWS_TIMEZONE,
					CONF_REGDOM_FOLLOWS_TIMEZONE_VAL,
					CONF_TYPE_BOOL},
	{CONF_DEFAULT_MDNS_CONFIGURATION,
					CONF_DEFAULT_MDNS_CONFIGURATION_VAL,
					CONF_TYPE_BOOL},
	{CONF_TETHERING_MDNS_CONFIGURATION,
					CONF_TETHERING_MDNS_CONFIGURATION_VAL,
					CONF_TYPE_BOOL},
	{CONF_ONLINE_CHECK_INITIAL_INTERVAL,
					CONF_ONLINE_CHECK_INITIAL_INTERVAL_VAL,
					CONF_TYPE_INT},
	{CONF_ONLINE_CHECK_MAX_INTERVAL,
					CONF_ONLINE_CHECK_MAX_INTERVAL_VAL,
					CONF_TYPE_INT},
	{CONF_WIFI_WPA3_SUPPORT,
					CONF_WIFI_WPA3_SUPPORT_VAL,
					CONF_TYPE_CHAR},
	{CONF_WIFI_WPA3_SAE_PWE,
					CONF_WIFI_WPA3_SAE_PWE_VAL,
					CONF_TYPE_CHAR},
	{CONF_WIFI_WPA3_SAE_CHECK_MFP,
					CONF_WIFI_WPA3_SAE_CHECK_MFP_VAL,
					CONF_TYPE_BOOL},
	{ 0 }
};

const char *connman_setting_get_string(const char *key)
{
	if (!key)
		return NULL;

	if (g_str_equal(key, CONF_VENDOR_CLASS_ID))
		return connman_settings.vendor_class_id;

	if (g_str_equal(key, CONF_OPTION_CONFIG))
		return connman_settings.option_config;

	if (g_str_equal(key, CONF_OPTION_DEBUG))
		return connman_settings.option_debug;

	if (g_str_equal(key, CONF_OPTION_DEVICE))
		return connman_settings.option_device;

	if (g_str_equal(key, CONF_OPTION_NODEVICE))
		return connman_settings.option_nodevice;

	if (g_str_equal(key, CONF_OPTION_PLUGIN))
		return connman_settings.option_plugin;

	/*
	 * Support both config options for noplugin as this can be defined in
	 * configuration file as well as on cmd line.
	 */
	if (g_str_equal(key, CONF_OPTION_NOPLUGIN) ||
					g_str_equal(key, CONF_DISABLE_PLUGINS))
		return connman_settings.option_noplugin;

	if (g_str_equal(key, CONF_OPTION_WIFI)) {
		if (!connman_settings.option_wifi)
			return CONF_WIFI_DEF;
		else
			return connman_settings.option_wifi;
	}

	if (g_str_equal(key, CONF_STATUS_URL_IPV4))
		return connman_settings.ipv4_status_url ?
			connman_settings.ipv4_status_url :
			CONF_STATUS_URL_IPV4_DEF;

	if (g_str_equal(key, CONF_STATUS_URL_IPV6))
		return connman_settings.ipv6_status_url ?
			connman_settings.ipv6_status_url :
			CONF_STATUS_URL_IPV6_DEF;

	if (g_str_equal(key, CONF_TETHERING_SUBNET_BLOCK))
		return connman_settings.tethering_subnet_block ?
			connman_settings.tethering_subnet_block :
			CONF_TETHERING_SUBNET_BLOCK_DEF;

	if (g_str_equal(key, CONF_LOCALTIME))
		return connman_settings.localtime ?
				connman_settings.localtime : DEFAULT_LOCALTIME;

	if (g_str_equal(key, CONF_FILE_SYSTEM_IDENTITY))
		return connman_settings.fs_identity;

	if (g_str_equal(key, CONF_STORAGE_ROOT))
		return connman_settings.storage_root;

	if (g_str_equal(key, CONF_USER_STORAGE_DIR))
		return connman_settings.user_storage_dir;

	if (g_str_equal(key, CONF_WIFI_WPA3_SUPPORT))
		return connman_settings.wifi_wpa3_support;

	if (g_str_equal(key, CONF_WIFI_WPA3_SAE_PWE))
		return connman_settings.wifi_wpa3_sae_pwe;

	return NULL;
}

bool connman_setting_get_bool(const char *key)
{
	if (!key)
		return false;

	if (g_str_equal(key, CONF_BG_SCAN))
		return connman_settings.bg_scan;

	if (g_str_equal(key, CONF_ALLOW_HOSTNAME_UPDATES))
		return connman_settings.allow_hostname_updates;

	if (g_str_equal(key, CONF_ALLOW_DOMAINNAME_UPDATES))
		return connman_settings.allow_domainname_updates;

	if (g_str_equal(key, CONF_SINGLE_TECH))
		return connman_settings.single_tech;

	if (g_str_equal(key, CONF_PERSISTENT_TETHERING_MODE))
		return connman_settings.persistent_tethering_mode;

	if (g_str_equal(key, CONF_ENABLE_6TO4))
		return connman_settings.enable_6to4;

	if (g_str_equal(key, CONF_ENABLE_ONLINE_CHECK))
		return connman_settings.enable_online_check;

	if (g_str_equal(key, CONF_ENABLE_ONLINE_TO_READY_TRANSITION))
		return connman_settings.enable_online_to_ready_transition;

	if (g_str_equal(key, CONF_AUTO_CONNECT_ROAMING_SERVICES))
		return connman_settings.auto_connect_roaming_services;

	if (g_str_equal(key, CONF_ACD))
		return connman_settings.acd;

	if (g_str_equal(key, CONF_USE_GATEWAYS_AS_TIMESERVERS))
		return connman_settings.use_gateways_as_timeservers;

	if (g_str_equal(key, CONF_ENABLE_LOGIN_MANAGER))
		return connman_settings.enable_login_manager;

	if (g_str_equal(key, CONF_REGDOM_FOLLOWS_TIMEZONE))
		return connman_settings.regdom_follows_timezone;

	if (g_str_equal(key, CONF_DEFAULT_MDNS_CONFIGURATION))
		return connman_settings.default_mdns_configuration;

	if (g_str_equal(key, CONF_TETHERING_MDNS_CONFIGURATION))
		return connman_settings.tethering_mdns_configuration;

	if (g_str_equal(key, CONF_WIFI_WPA3_SAE_CHECK_MFP))
		return connman_settings.wifi_wpa3_sae_check_mfp;

	return false;
}

unsigned int connman_setting_get_uint(const char *key)
{
	if (!key)
		return 0;

	if (g_str_equal(key, CONF_ONLINE_CHECK_INITIAL_INTERVAL))
		return connman_settings.online_check_initial_interval;

	if (g_str_equal(key, CONF_ONLINE_CHECK_MAX_INTERVAL))
		return connman_settings.online_check_max_interval;

	return 0;
}

char **connman_setting_get_string_list(const char *key)
{
	if (!key)
		return NULL;

	if (g_str_equal(key, CONF_FALLBACK_TIMESERVERS))
		return connman_settings.fallback_timeservers;

	if (g_str_equal(key, CONF_FALLBACK_NAMESERVERS))
		return connman_settings.fallback_nameservers;

	if (g_str_equal(key, CONF_BLACKLISTED_INTERFACES))
		return connman_settings.blacklisted_interfaces;

	if (g_str_equal(key, CONF_TETHERING_TECHNOLOGIES))
		return connman_settings.tethering_technologies;

	if (g_str_equal(key, CONF_DONT_BRING_DOWN_AT_STARTUP))
		return connman_settings.dont_bring_down_at_startup;

	return NULL;
}

unsigned int *connman_setting_get_uint_list(const char *key)
{
	if (!key)
		return NULL;

	if (g_str_equal(key, CONF_AUTO_CONNECT_TECHS))
		return connman_settings.auto_connect;

	if (g_str_equal(key, CONF_FAVORITE_TECHS))
		return connman_settings.favorite_techs;

	if (g_str_equal(key, CONF_PREFERRED_TECHS))
		return connman_settings.preferred_techs;

	if (g_str_equal(key, CONF_ALWAYS_CONNECTED_TECHS))
		return connman_settings.always_connected_techs;

	return NULL;
}

mode_t connman_setting_get_fs_mode(const char *key)
{
	if (!key)
		return 0;

	if (g_str_equal(key, CONF_STORAGE_ROOT_PERMISSIONS))
		return connman_settings.storage_root_permissions;

	if (g_str_equal(key, CONF_STORAGE_DIR_PERMISSIONS))
		return connman_settings.storage_dir_permissions;

	if (g_str_equal(key, CONF_STORAGE_FILE_PERMISSIONS))
		return connman_settings.storage_file_permissions;

	if (g_str_equal(key, CONF_UMASK))
		return connman_settings.umask;

	return 0;
}

unsigned int connman_timeout_input_request(void)
{
	return connman_settings.timeout_inputreq;
}

unsigned int connman_timeout_browser_launch(void)
{
	return connman_settings.timeout_browserlaunch;
}

static int conf_key_to_int(const char *key)
{
	int i;

	for (i = 0; i < CONF_ARRAY_SIZE(supported_options); i++) {
		if (!g_strcmp0(key, supported_options[i].opt_key))
			return supported_options[i].opt_value;
	}

	return -EINVAL;
}

static uint *parse_service_types(char **str_list, gsize len)
{
	unsigned int *type_list;
	int i, j;
	enum connman_service_type type;

	type_list = g_try_new0(unsigned int, len + 1);
	if (!type_list)
		return NULL;

	i = 0;
	j = 0;
	while (str_list[i]) {
		type = __connman_service_string2type(str_list[i]);

		if (type != CONNMAN_SERVICE_TYPE_UNKNOWN) {
			type_list[j] = type;
			j += 1;
		}
		i += 1;
	}

	type_list[j] = CONNMAN_SERVICE_TYPE_UNKNOWN;

	return type_list;
}

static char **parse_nameservers(char **nameservers, gsize *len)
{
	char **servers;
	int i, j;

	servers = g_try_new0(char *, *len + 1);
	if (!servers)
		return NULL;

	i = 0;
	j = 0;
	while (nameservers[i]) {
		if (connman_inet_check_ipaddress(nameservers[i]) > 0) {
			servers[j] = g_strdup(nameservers[i]);
			j += 1;
		}
		i += 1;
	}

	*len = j + 1;

	return servers;
}

static GHashTable *parse_fallback_device_types(char **devtypes, gsize len)
{
	GHashTable *h;
	gsize i;

	h = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	for (i = 0; i < len; ++i) {
		char **v;

		v = g_strsplit(devtypes[i], ":", 2);
		if (!v)
			continue;

		if (v[0] && v[1])
			g_hash_table_replace(h, g_strdup(v[0]),
					g_strdup(v[1]));

		g_strfreev(v);
	}

	if (g_hash_table_size(h) > 0)
		return h;

	g_hash_table_unref(h);
	return NULL;
}

static gboolean parse_perm(GKeyFile *config, const char *group,
					const char *key, mode_t *perm)
{
	gboolean ok = FALSE;
	char *str = g_key_file_get_string(config, group, key, NULL);
	if (str) {
		/*
		 * Some people are thinking that # is a comment
		 * anywhere on the line, not just at the beginning
		 */
		unsigned long val;
		char *comment = strchr(str, '#');
		if (comment) *comment = 0;
		val = strtoul(g_strstrip(str), NULL, 0);
		if (val > 0 && !(val & ~0777UL)) {
			*perm = (mode_t)val;
			ok = TRUE;
		}
		g_free(str);
	}
	return ok;
}

static gboolean check_ip(const char *str)
{
	struct in_addr ip;

	if (!str)
		return FALSE;

	return inet_pton(AF_INET, str, &ip) == 1 &&
						(ntohl(ip.s_addr) & 0xff) == 0;
}

static gboolean check_wpa3_support(const char *str)
{

	if (!util_wpa3_is_valid_support_str(str)) {
		connman_warn("invalid \"WifiWPA3Support\" config value \"%s\"",
			str);
		return FALSE;
	}

	return TRUE;
}

static gboolean check_wpa3_sae_pwe(const char *str)
{
	if (util_wpa3_sae_pwe_index(str) < 0) {
		connman_warn("invalid \"WifiWPA3SAEPWE\" config value \"%s\"",
									str);
		return FALSE;
	}

	return TRUE;
}

void append_noplugin(const char *value)
{
	__connman_setting_set_option(CONF_OPTION_NOPLUGIN, value);
}

typedef gboolean (*str_check_callback) (const char *value);
typedef char** (*str_list_parse_callback) (char **str_list, gsize *len);
typedef void (*str_list_callback) (const char *value);

static void set_str(char **ptr, char *value, str_check_callback cb)
{
	if (*ptr) {
		g_free(*ptr);
		*ptr = NULL;
	}

	if (cb && !cb(value)) {
		g_free(value);
		return;
	}

	*ptr = value;
}

static void set_str_list(char ***ptr, char **value, gsize len, bool append)
{
	if (append) {
		/* TODO */
		DBG("append is ENOTSUP");
	}

	if (*ptr)
		g_strfreev(*ptr);

	*ptr = value;
}

static void set_str_list_cb(char **value, str_list_callback cb, gsize len,
								bool append)
{
	int i;

	if (append) {
		/* TODO */
		DBG("append is ENOTSUP");
	}

	for (i = 0; i < len; i++)
		cb(value[i]);
}

static void set_int_list(unsigned int **ptr, unsigned int *value, bool append)
{
	if (append) {
		/* TODO */
		DBG("append is ENOTSUP");
	}

	if (*ptr)
		g_free(*ptr);

	*ptr = value;
}

static void set_hash_table(GHashTable **ptr, char **value, gsize len,
								bool append)
{
	if (append) {
		/* TODO */
		DBG("append is ENOTSUP");
	}

	if (*ptr)
		g_hash_table_destroy(*ptr);

	*ptr = parse_fallback_device_types(value, len);
}

static void read_config_value(GKeyFile *config, const char *key, bool append)
{
	GError *error = NULL;
	const char *group = "General";
	char *def_str = NULL;
	char **def_str_list = NULL;
	enum option_val key_value;
	str_check_callback check_cb = NULL;
	str_list_callback list_cb = NULL;
	str_list_parse_callback parse_cb = NULL;
	gsize def_str_list_len = 0;
	gsize len;
	unsigned int int_multiplier = 1;

	/* Ptrs for options */
	GHashTable **hash_table_ptr = NULL;
	char ***str_list_ptr = NULL;
	char **str_ptr = NULL;
	bool *bool_ptr = NULL;
	unsigned int **int_list_ptr = NULL;
	unsigned int *int_ptr = NULL;
	mode_t *mode_ptr = NULL;

	key_value = conf_key_to_int(key);

	/* TODO: use a better structure, like struct with union in htable */
	switch (key_value) {
	/* bool */
	case CONF_BG_SCAN_VAL:
		bool_ptr = &connman_settings.bg_scan;
		break;
	case CONF_ALLOW_HOSTNAME_UPDATES_VAL:
		bool_ptr = &connman_settings.allow_hostname_updates;
		break;
	case CONF_ALLOW_DOMAINNAME_UPDATES_VAL:
		bool_ptr = &connman_settings.allow_domainname_updates;
		break;
	case CONF_SINGLE_TECH_VAL:
		bool_ptr = &connman_settings.single_tech;
		break;
	case CONF_PERSISTENT_TETHERING_MODE_VAL:
		bool_ptr = &connman_settings.persistent_tethering_mode;
		break;
	case CONF_ENABLE_6TO4_VAL:
		bool_ptr = &connman_settings.enable_6to4;
		break;
	case CONF_ENABLE_ONLINE_CHECK_VAL:
		bool_ptr = &connman_settings.enable_online_check;
		break;
	case CONF_ENABLE_ONLINE_TO_READY_TRANSITION_VAL:
		bool_ptr = &connman_settings.enable_online_to_ready_transition;
	case CONF_AUTO_CONNECT_ROAMING_SERVICES_VAL:
		bool_ptr = &connman_settings.auto_connect_roaming_services;
		break;
	case CONF_ACD_VAL:
		bool_ptr = &connman_settings.acd;
		break;
	case CONF_USE_GATEWAYS_AS_TIMESERVERS_VAL:
		bool_ptr = &connman_settings.use_gateways_as_timeservers;
		break;
	case CONF_ENABLE_LOGIN_MANAGER_VAL:
		bool_ptr = &connman_settings.enable_login_manager;
		break;
	case CONF_REGDOM_FOLLOWS_TIMEZONE_VAL:
		bool_ptr = &connman_settings.regdom_follows_timezone;
		break;
	case CONF_DEFAULT_MDNS_CONFIGURATION_VAL:
		bool_ptr = &connman_settings.default_mdns_configuration;
		break;
	case CONF_TETHERING_MDNS_CONFIGURATION_VAL:
		bool_ptr = &connman_settings.tethering_mdns_configuration;
		break;
	case CONF_WIFI_WPA3_SAE_CHECK_MFP_VAL:
		bool_ptr = &connman_settings.wifi_wpa3_sae_check_mfp;
		break;

	/* str */
	case CONF_STATUS_URL_IPV4_VAL:
		str_ptr = &connman_settings.ipv4_status_url;
		break;
	case CONF_STATUS_URL_IPV6_VAL:
		str_ptr = &connman_settings.ipv6_status_url;
		break;
	case CONF_TETHERING_SUBNET_BLOCK_VAL:
		str_ptr = &connman_settings.tethering_subnet_block;
		check_cb = check_ip;
		break;
	case CONF_FILE_SYSTEM_IDENTITY_VAL:
		str_ptr = &connman_settings.fs_identity;
		break;
	case CONF_STORAGE_ROOT_VAL:
		str_ptr = &connman_settings.storage_root;
		def_str = DEFAULT_STORAGE_ROOT;
		break;
	case CONF_USER_STORAGE_DIR_VAL:
		str_ptr = &connman_settings.user_storage_dir;
		def_str = DEFAULT_USER_STORAGE;
		break;
	case CONF_VENDOR_CLASS_ID_VAL:
		str_ptr = &connman_settings.vendor_class_id;
		break;
	case CONF_LOCALTIME_VAL:
		str_ptr = &connman_settings.localtime;
		break;
	case CONF_WIFI_WPA3_SUPPORT_VAL:
		str_ptr = &connman_settings.wifi_wpa3_support;
		check_cb = check_wpa3_support;
		break;
	case CONF_WIFI_WPA3_SAE_PWE_VAL:
		str_ptr = &connman_settings.wifi_wpa3_sae_pwe;
		check_cb = check_wpa3_sae_pwe;
		break;

	/* str list */
	case CONF_FALLBACK_TIMESERVERS_VAL:
		str_list_ptr = &connman_settings.fallback_timeservers;
		break;
	case CONF_FALLBACK_NAMESERVERS_VAL:
		str_list_ptr = &connman_settings.fallback_nameservers;
		parse_cb = parse_nameservers;
		break;
	case CONF_BLACKLISTED_INTERFACES_VAL:
		str_list_ptr = &connman_settings.blacklisted_interfaces;
		def_str_list = default_blacklist;
		def_str_list_len = CONF_ARRAY_SIZE(default_blacklist);
		break;
	case CONF_TETHERING_TECHNOLOGIES_VAL:
		str_list_ptr = &connman_settings.tethering_technologies;
		break;
	case CONF_DONT_BRING_DOWN_AT_STARTUP_VAL:
		str_list_ptr = &connman_settings.dont_bring_down_at_startup;
		break;
	/* str list but use append_noplugin */
	case CONF_DISABLE_PLUGINS_VAL:
		list_cb = append_noplugin;
		break;

	/* int */
	case CONF_TIMEOUT_INPUTREQ_VAL:
		int_ptr = &connman_settings.timeout_inputreq;
		int_multiplier = 1000;
		break;
	case CONF_TIMEOUT_BROWSERLAUNCH_VAL:
		int_ptr = &connman_settings.timeout_browserlaunch;
		int_multiplier = 1000;
		break;
	case CONF_ONLINE_CHECK_INITIAL_INTERVAL_VAL:
		int_ptr = &connman_settings.online_check_initial_interval;
		break;
	case CONF_ONLINE_CHECK_MAX_INTERVAL_VAL:
		int_ptr = &connman_settings.online_check_max_interval;
		break;

	/* int array */
	case CONF_AUTO_CONNECT_TECHS_VAL:
		int_list_ptr = &connman_settings.auto_connect;
		def_str_list = default_auto_connect;
		def_str_list_len = CONF_ARRAY_SIZE(default_auto_connect);
		break;
	case CONF_FAVORITE_TECHS_VAL:
		int_list_ptr = &connman_settings.favorite_techs;
		def_str_list = default_favorite_techs;
		def_str_list_len = CONF_ARRAY_SIZE(default_favorite_techs);
		break;
	case CONF_ALWAYS_CONNECTED_TECHS_VAL:
		int_list_ptr = &connman_settings.always_connected_techs;
		break;
	case CONF_PREFERRED_TECHS_VAL:
		int_list_ptr = &connman_settings.preferred_techs;
		break;

	/* GHashTable */
	case CONF_FALLBACK_DEVICE_TYPES_VAL:
		hash_table_ptr = &connman_settings.fallback_device_types;
		break;

	/* mode_t */
	case CONF_STORAGE_ROOT_PERMISSIONS_VAL:
		mode_ptr = &connman_settings.storage_root_permissions;
		break;
	case CONF_STORAGE_DIR_PERMISSIONS_VAL:
		mode_ptr = &connman_settings.storage_dir_permissions;
		break;
	case CONF_STORAGE_FILE_PERMISSIONS_VAL:
		mode_ptr = &connman_settings.storage_file_permissions;
		break;
	case CONF_UMASK_VAL:
		mode_ptr = &connman_settings.umask;
		break;

	default:
		break;
	}

	if (bool_ptr) {
		bool boolean = __connman_config_get_bool(config, group, key,
						&error);
		if (!error)
			*bool_ptr = boolean;
	}

	if (str_ptr) {
		char *str = __connman_config_get_string(config, group, key,
						&error);
		if (!error)
			set_str(str_ptr, str, check_cb);
		/* 
		 * No value has been set to the str, use default in case of
		 * error if default is set.
		 */
		else if (!*str_ptr && def_str)
			set_str(str_ptr, g_strdup(def_str), check_cb);
		else
			g_free(str);
	}

	if (str_list_ptr || list_cb) {
		char **str_list = __connman_config_get_string_list(config,
						group, key, &len, &error);
		if (!error) {
			if (list_cb) {
				set_str_list_cb(str_list, list_cb, len, append);
				g_strfreev(str_list);
			} else if (parse_cb) {
				char **new_str_list = parse_cb(str_list, &len);
				g_strfreev(str_list);

				if (new_str_list)
					set_str_list(str_list_ptr, new_str_list,
								len, append);
			} else {
				set_str_list(str_list_ptr, str_list, len,
									append);
			}
		} else if (str_list_ptr && def_str_list) {
			set_str_list(str_list_ptr, g_strdupv(def_str_list),
						def_str_list_len, append);
		}
	}

	if (int_ptr) {
		int value = g_key_file_get_integer(config, group, key, &error);
		if (!error && value >= 0)
			*int_ptr = value * int_multiplier;
	}

	if (int_list_ptr) {
		char **str_list = __connman_config_get_string_list(config,
						group, key, &len, &error);
		if (!error)
			set_int_list(int_list_ptr,
					parse_service_types(str_list, len),
					append);
		else if (def_str_list)
			set_int_list(int_list_ptr,
					parse_service_types(def_str_list,
						def_str_list_len),
					append);
		g_strfreev(str_list);
	}

	if (hash_table_ptr) {
		char **str_list = __connman_config_get_string_list(config,
						group, key, &len, &error);
		if (!error)
			set_hash_table(hash_table_ptr, str_list, len, append);

		g_strfreev(str_list);
	}

	if (mode_ptr) {
		parse_perm(config, group, key, mode_ptr);
	}

	g_clear_error(&error);
}

static void read_non_main_config(GKeyFile *config, bool append)
{
	GError *error = NULL;
	char **keys;
	gsize len;

	if (!config)
		return;

	keys = g_key_file_get_keys(config, "General", &len, &error);
	if (!error) {
		int i;
		for (i = 0; i < len; i++) {
			if (!__connman_setting_is_supported_option(keys[i])) {
				DBG("invalid key %s", keys[i]);
				continue;
			}

			DBG("read key %s", keys[i]);
			read_config_value(config, keys[i], append);
		}
	}

	g_clear_error(&error);
}

void __connman_setting_read_config_values(GKeyFile *config, bool mainconfig,
								bool append)
{
	int i ;

	if (!mainconfig) {
		read_non_main_config(config, append);
		return;
	}

	if (!config) {
		connman_settings.auto_connect =
			parse_service_types(default_auto_connect,
				CONF_ARRAY_SIZE(default_auto_connect));
		connman_settings.favorite_techs =
			parse_service_types(default_favorite_techs,
				CONF_ARRAY_SIZE(default_favorite_techs));
		connman_settings.blacklisted_interfaces =
			g_strdupv(default_blacklist);
		return;
	}

	for (i = 0; i < CONF_ARRAY_SIZE(supported_options); i++)
		read_config_value(config, supported_options[i].opt_key, append);

	if (!connman_settings.enable_online_check)
		connman_info("Online check disabled by main config.");

	if (connman_settings.online_check_initial_interval < 1 ||
		connman_settings.online_check_initial_interval >
		connman_settings.online_check_max_interval) {
		connman_warn("Incorrect online check intervals [%u, %u]",
				connman_settings.online_check_initial_interval,
				connman_settings.online_check_max_interval);
		connman_settings.online_check_initial_interval =
			DEFAULT_ONLINE_CHECK_INITIAL_INTERVAL;
		connman_settings.online_check_max_interval =
			DEFAULT_ONLINE_CHECK_MAX_INTERVAL;
	}
}

void __connman_setting_set_option(const char *key, const char *value)
{
	if (!key)
		return;

	DBG("key %s value %s", key, value);

	if (g_str_equal(key, CONF_OPTION_PLUGIN)) {
		if (connman_settings.option_plugin) {
			char *prev = connman_settings.option_plugin;

			connman_settings.option_plugin = g_strconcat(prev,
							",", value, NULL);
			g_free(prev);
		} else {
			connman_settings.option_plugin = g_strdup(value);
		}
	}

	if (g_str_equal(key, CONF_OPTION_NOPLUGIN)) {
		if (connman_settings.option_noplugin) {
			char *prev = connman_settings.option_noplugin;

			connman_settings.option_noplugin = g_strconcat(prev,
							",", value, NULL);
			g_free(prev);
		} else {
			connman_settings.option_noplugin = g_strdup(value);
		}
	}

	if (g_str_equal(key, CONF_OPTION_CONFIG)) {
		g_free(connman_settings.option_config);
		connman_settings.option_config = g_strdup(value);
	}

	if (g_str_equal(key, CONF_OPTION_DEBUG)) {
		if (value) {
			if (!connman_settings.option_debug ||
					!g_strcmp0(
						connman_settings.option_debug,
						"*")) {
				g_free(connman_settings.option_debug);
				connman_settings.option_debug = g_strdup(value);
			} else {
				char *prev = connman_settings.option_debug;

				connman_settings.option_debug = g_strconcat(
							prev, ",", value, NULL);
				g_free(prev);
			}
		} else {
			g_free(connman_settings.option_debug);
			connman_settings.option_debug = g_strdup("*");
		}
	}

	if (g_str_equal(key, CONF_OPTION_DEVICE)) {
		g_free(connman_settings.option_device);
		connman_settings.option_device = g_strdup(value);
	}

	if (g_str_equal(key, CONF_OPTION_NODEVICE)) {
		g_free(connman_settings.option_nodevice);
		connman_settings.option_nodevice = g_strdup(value);
	}

	if (g_str_equal(key, CONF_OPTION_WIFI)) {
		g_free(connman_settings.option_wifi);
		connman_settings.option_wifi = g_strdup(value);
	}
}

const char *__connman_setting_get_fallback_device_type(const char *interface)
{
	if (!connman_settings.fallback_device_types)
		return NULL;

	return g_hash_table_lookup(connman_settings.fallback_device_types,
			interface);
}

bool __connman_setting_is_supported_option(const char *key)
{
	int i;

	if (!key)
		return false;

	for (i = 0; i < CONF_ARRAY_SIZE(supported_options); i++) {
		if (!g_strcmp0(key, supported_options[i].opt_key))
			return true;
	}

	return false;
}

int __connman_setting_init()
{
	DBG("");

	memset(&connman_settings, 0, sizeof(connman_settings));

	connman_settings.bg_scan = true;
	connman_settings.timeout_inputreq = DEFAULT_INPUT_REQUEST_TIMEOUT;
	connman_settings.timeout_browserlaunch = DEFAULT_BROWSER_LAUNCH_TIMEOUT;
	connman_settings.allow_hostname_updates = true;
	connman_settings.allow_domainname_updates = true;
	connman_settings.storage_root_permissions =
					DEFAULT_STOGAGE_ROOT_PERMISSIONS;
	connman_settings.storage_dir_permissions =
					DEFAULT_STORAGE_DIR_PERMISSIONS;
	connman_settings.storage_file_permissions =
					DEFAULT_STORAGE_FILE_PERMISSIONS;
	connman_settings.umask = DEFAULT_UMASK;
	connman_settings.enable_online_check = true;
	connman_settings.online_check_initial_interval =
					DEFAULT_ONLINE_CHECK_INITIAL_INTERVAL;
	connman_settings.online_check_max_interval =
					DEFAULT_ONLINE_CHECK_MAX_INTERVAL;

	return 0;
}

void __connman_setting_cleanup()
{
	DBG("");

	g_strfreev(connman_settings.fallback_timeservers);
	g_strfreev(connman_settings.fallback_nameservers);
	g_strfreev(connman_settings.blacklisted_interfaces);
	g_strfreev(connman_settings.tethering_technologies);
	g_strfreev(connman_settings.dont_bring_down_at_startup);

	g_free(connman_settings.ipv6_status_url);
	g_free(connman_settings.ipv4_status_url);
	g_free(connman_settings.tethering_subnet_block);
	g_free(connman_settings.fs_identity);
	g_free(connman_settings.storage_root);
	g_free(connman_settings.user_storage_dir);
	g_free(connman_settings.vendor_class_id);
	g_free(connman_settings.localtime);

	g_free(connman_settings.auto_connect);
	g_free(connman_settings.favorite_techs);
	g_free(connman_settings.preferred_techs);
	g_free(connman_settings.always_connected_techs);

	g_free(connman_settings.option_config);
	g_free(connman_settings.option_debug);
	g_free(connman_settings.option_device);
	g_free(connman_settings.option_plugin);
	g_free(connman_settings.option_nodevice);
	g_free(connman_settings.option_noplugin);
	g_free(connman_settings.option_wifi);

	if (connman_settings.fallback_device_types)
		g_hash_table_unref(connman_settings.fallback_device_types);
}
