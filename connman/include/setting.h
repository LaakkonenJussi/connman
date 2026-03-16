/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#ifndef __CONNMAN_SETTING_H
#define __CONNMAN_SETTING_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONF_STATUS_URL_IPV6                 "Ipv6StatusUrl"
#define CONF_STATUS_URL_IPV4                 "Ipv4StatusUrl"
#define CONF_TETHERING_SUBNET_BLOCK          "TetheringSubnetBlock"

#define CONF_BG_SCAN                         "BackgroundScanning"
#define CONF_FALLBACK_TIMESERVERS            "FallbackTimeservers"
#define CONF_AUTO_CONNECT_TECHS              "DefaultAutoConnectTechnologies"
#define CONF_FAVORITE_TECHS                  "DefaultFavoriteTechnologies"
#define CONF_ALWAYS_CONNECTED_TECHS          "AlwaysConnectedTechnologies"
#define CONF_PREFERRED_TECHS                 "PreferredTechnologies"
#define CONF_FALLBACK_NAMESERVERS            "FallbackNameservers"
#define CONF_TIMEOUT_INPUTREQ                "InputRequestTimeout"
#define CONF_TIMEOUT_BROWSERLAUNCH           "BrowserLaunchTimeout"
#define CONF_BLACKLISTED_INTERFACES          "NetworkInterfaceBlacklist"
#define CONF_ALLOW_HOSTNAME_UPDATES          "AllowHostnameUpdates"
#define CONF_ALLOW_DOMAINNAME_UPDATES        "AllowDomainnameUpdates"
#define CONF_SINGLE_TECH                     "SingleConnectedTechnology"
#define CONF_TETHERING_TECHNOLOGIES          "TetheringTechnologies"
#define CONF_PERSISTENT_TETHERING_MODE       "PersistentTetheringMode"
#define CONF_DONT_BRING_DOWN_AT_STARTUP      "DontBringDownAtStartup"
#define CONF_DISABLE_PLUGINS                 "DisablePlugins"
#define CONF_FILE_SYSTEM_IDENTITY            "FileSystemIdentity"
#define CONF_STORAGE_ROOT                    "StorageRoot"
#define CONF_STORAGE_ROOT_PERMISSIONS        "StorageRootPermissions"
#define CONF_STORAGE_DIR_PERMISSIONS         "StorageDirPermissions"
#define CONF_STORAGE_FILE_PERMISSIONS        "StorageFilePermissions"
#define CONF_USER_STORAGE_DIR                "UserStorage"
#define CONF_UMASK                           "Umask"
#define CONF_ENABLE_6TO4                     "Enable6to4"
#define CONF_VENDOR_CLASS_ID                 "VendorClassID"
#define CONF_ENABLE_ONLINE_CHECK             "EnableOnlineCheck"
#define CONF_ENABLE_ONLINE_TO_READY_TRANSITION "EnableOnlineToReadyTransition"
#define CONF_AUTO_CONNECT_ROAMING_SERVICES   "AutoConnectRoamingServices"
#define CONF_ACD                             "AddressConflictDetection"
#define CONF_USE_GATEWAYS_AS_TIMESERVERS     "UseGatewaysAsTimeservers"
#define CONF_FALLBACK_DEVICE_TYPES           "FallbackDeviceTypes"
#define CONF_ENABLE_LOGIN_MANAGER            "EnableLoginManager"
#define CONF_LOCALTIME                       "Localtime"
#define CONF_REGDOM_FOLLOWS_TIMEZONE         "RegdomFollowsTimezone"
#define CONF_DEFAULT_MDNS_CONFIGURATION      "DefaultmDNSConfiguration"
#define CONF_TETHERING_MDNS_CONFIGURATION    "TetheringmDNSConfiguration"

#define CONF_ONLINE_CHECK_INITIAL_INTERVAL   "OnlineCheckInitialInterval"
#define CONF_ONLINE_CHECK_MAX_INTERVAL       "OnlineCheckMaxInterval"

#define CONF_WIFI_WPA3_SUPPORT               "WifiWPA3Support"
#define CONF_WIFI_WPA3_SAE_PWE               "WifiWPA3SAEPWE"
#define CONF_WIFI_WPA3_SAE_CHECK_MFP         "WifiWPA3SAECheckMFP"

#define CONF_OPTION_CONFIG                   "config"
#define CONF_OPTION_DEBUG                    "debug"
#define CONF_OPTION_DEVICE                   "device"
#define CONF_OPTION_NODEVICE                 "nodevice"
#define CONF_OPTION_PLUGIN                   "plugin"
#define CONF_OPTION_NOPLUGIN                 "noplugin"
#define CONF_OPTION_WIFI                     "wifi"

const char *connman_setting_get_string(const char *key);
bool connman_setting_get_bool(const char *key);
unsigned int connman_setting_get_uint(const char *key);
char **connman_setting_get_string_list(const char *key);
unsigned int *connman_setting_get_uint_list(const char *key);
mode_t connman_setting_get_fs_mode(const char *key);

unsigned int connman_timeout_input_request(void);
unsigned int connman_timeout_browser_launch(void);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_SETTING_H */
