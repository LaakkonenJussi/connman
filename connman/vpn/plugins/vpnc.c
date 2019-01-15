/*
 *
 *  ConnMan VPN daemon
 *
 *  Copyright (C) 2010,2013  BMW Car IT GmbH.
 *  Copyright (C) 2010,2012-2013  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/task.h>
#include <connman/ipconfig.h>
#include <connman/dbus.h>
#include <connman/agent.h>
#include <connman/setting.h>
#include <connman/vpn-dbus.h>

#include "../vpn-provider.h"
#include "../vpn-agent.h"

#include "vpn.h"
#include "../vpn.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

enum {
	OPT_STRING = 1,
	OPT_BOOLEAN = 2,
};

struct {
	const char *cm_opt;
	const char *vpnc_opt;
	const char *vpnc_default;
	int type;
	bool cm_save;
} vpnc_options[] = {
	{ "Host", "IPSec gateway", NULL, OPT_STRING, true },
	{ "VPNC.IPSec.ID", "IPSec ID", NULL, OPT_STRING, true },
	{ "VPNC.IPSec.Secret", "IPSec secret", NULL, OPT_STRING, false },
	{ "VPNC.Xauth.Username", "Xauth username", NULL, OPT_STRING, false },
	{ "VPNC.Xauth.Password", "Xauth password", NULL, OPT_STRING, false },
	{ "VPNC.IKE.Authmode", "IKE Authmode", NULL, OPT_STRING, true },
	{ "VPNC.IKE.DHGroup", "IKE DH Group", NULL, OPT_STRING, true },
	{ "VPNC.PFS", "Perfect Forward Secrecy", NULL, OPT_STRING, true },
	{ "VPNC.Domain", "Domain", NULL, OPT_STRING, true },
	{ "VPNC.Vendor", "Vendor", NULL, OPT_STRING, true },
	{ "VPNC.LocalPort", "Local Port", "0", OPT_STRING, true, },
	{ "VPNC.CiscoPort", "Cisco UDP Encapsulation Port", "0", OPT_STRING,
									true },
	{ "VPNC.AppVersion", "Application version", NULL, OPT_STRING, true },
	{ "VPNC.NATTMode", "NAT Traversal Mode", "cisco-udp", OPT_STRING,
									true },
	{ "VPNC.DPDTimeout", "DPD idle timeout (our side)", NULL, OPT_STRING,
									true },
	{ "VPNC.SingleDES", "Enable Single DES", NULL, OPT_BOOLEAN, true },
	{ "VPNC.NoEncryption", "Enable no encryption", NULL, OPT_BOOLEAN,
									true },
};

struct vc_private_data {
	struct vpn_provider *provider;
	struct connman_task *task;
	char *if_name;
	vpn_provider_connect_cb_t cb;
	void *user_data;
};

static void vc_connect_done(struct vc_private_data *data, int err)
{
	DBG("data %p err %d", data, err);

	if (data && data->cb) {
		vpn_provider_connect_cb_t cb = data->cb;
		void *user_data = data->user_data;

		/* Make sure we don't invoke this callback twice */
		data->cb = NULL;
		data->user_data = NULL;
		cb(data->provider, user_data, err);
	}
}

static void free_private_data(struct vc_private_data *data)
{
	DBG("data %p", data);

	if (!data || !data->provider)
		return;

	DBG("provider %p", data->provider);

	if (vpn_provider_get_plugin_data(data->provider) == data)
		vpn_provider_set_plugin_data(data->provider, NULL);

	vc_connect_done(data, EIO);
	vpn_provider_unref(data->provider);
	g_free(data->if_name);
	g_free(data);
}

static int vc_notify(DBusMessage *msg, struct vpn_provider *provider)
{
	DBusMessageIter iter, dict;
	char *address = NULL, *netmask = NULL, *gateway = NULL;
	struct connman_ipaddress *ipaddress;
	const char *reason, *key, *value;
	struct vc_private_data *data = vpn_provider_get_plugin_data(provider);

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		vc_connect_done(data, ENOENT);
		return VPN_STATE_FAILURE;
	}

	if (g_strcmp0(reason, "connect")) {
		vc_connect_done(data, EIO);
		return VPN_STATE_DISCONNECT;
	}

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		DBG("%s = %s", key, value);

		if (!strcmp(key, "VPNGATEWAY"))
			gateway = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP4_ADDRESS"))
			address = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP4_NETMASK"))
			netmask = g_strdup(value);

		if (!strcmp(key, "INTERNAL_IP4_DNS"))
			vpn_provider_set_nameservers(provider, value);

		if (!strcmp(key, "CISCO_DEF_DOMAIN"))
			vpn_provider_set_domain(provider, value);

		if (g_str_has_prefix(key, "CISCO_SPLIT_INC") ||
			g_str_has_prefix(key, "CISCO_IPV6_SPLIT_INC"))
			vpn_provider_append_route(provider, key, value);

		dbus_message_iter_next(&dict);
	}


	ipaddress = connman_ipaddress_alloc(AF_INET);
	if (!ipaddress) {
		g_free(address);
		g_free(netmask);
		g_free(gateway);
		vc_connect_done(data, EIO);
		return VPN_STATE_FAILURE;
	}

	connman_ipaddress_set_ipv4(ipaddress, address, netmask, gateway);
	vpn_provider_set_ipaddress(provider, ipaddress);

	g_free(address);
	g_free(netmask);
	g_free(gateway);
	connman_ipaddress_free(ipaddress);

	vc_connect_done(data, 0);
	return VPN_STATE_CONNECT;
}

static ssize_t full_write(int fd, const void *buf, size_t len)
{
	ssize_t byte_write;

	while (len) {
		byte_write = write(fd, buf, len);
		if (byte_write < 0) {
			connman_error("failed to write config to vpnc: %s\n",
					strerror(errno));
			return byte_write;
		}
		len -= byte_write;
		buf += byte_write;
	}

	return 0;
}

static ssize_t write_option(int fd, const char *key, const char *value)
{
	gchar *buf;
	ssize_t ret = 0;

	if (key && value) {
		buf = g_strdup_printf("%s %s\n", key, value);
		ret = full_write(fd, buf, strlen(buf));

		g_free(buf);
	}

	return ret;
}

static ssize_t write_bool_option(int fd, const char *key, const char *value)
{
	gchar *buf;
	ssize_t ret = 0;

	if (key && value) {
		if (strcasecmp(value, "yes") == 0 ||
				strcasecmp(value, "true") == 0 ||
				strcmp(value, "1") == 0) {
			buf = g_strdup_printf("%s\n", key);
			ret = full_write(fd, buf, strlen(buf));

			g_free(buf);
		}
	}

	return ret;
}

static int vc_write_config_data(struct vpn_provider *provider, int fd)
{
	const char *opt_s;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(vpnc_options); i++) {
		opt_s = vpn_provider_get_string(provider,
					vpnc_options[i].cm_opt);
		if (!opt_s)
			opt_s = vpnc_options[i].vpnc_default;

		if (!opt_s)
			continue;

		DBG("write type %d opt \"%s\" value \"%s\"",
					vpnc_options[i].type,
					vpnc_options[i].vpnc_opt, opt_s);

		if (vpnc_options[i].type == OPT_STRING) {
			if (write_option(fd,
					vpnc_options[i].vpnc_opt, opt_s) < 0)
				return -EIO;
		} else if (vpnc_options[i].type == OPT_BOOLEAN) {
			if (write_bool_option(fd,
					vpnc_options[i].vpnc_opt, opt_s) < 0)
				return -EIO;
		}

	}

	return 0;
}

static int vc_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(vpnc_options); i++) {
		if (strncmp(vpnc_options[i].cm_opt, "VPNC.", 5) == 0) {

			if (!vpnc_options[i].cm_save)
				continue;

			option = vpn_provider_get_string(provider,
							vpnc_options[i].cm_opt);
			if (!option)
				continue;

			g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					vpnc_options[i].cm_opt, option);
		}
	}
	return 0;
}

static void vc_died(struct connman_task *task, int exit_code, void *user_data)
{
	struct vc_private_data *data = user_data;

	DBG("task %p data %p exit_code %d user_data %p", task, data, exit_code,
				user_data);

	connman_agent_cancel(data->provider);

	if (task && data && data->provider)
		vpn_died(task, exit_code, data->provider);

	free_private_data(data);
}

static int run_connect(struct vc_private_data *data)
{
	struct vpn_provider *provider;
	struct connman_task *task;
	const char *credentials[] = {"VPNC.IPSec.Secret", "VPNC.Xauth.Username",
				"VPNC.Xauth.Password", NULL};
	const char *if_name;
	const char *option;
	int err;
	int fd;
	int i;

	provider = data->provider;
	task = data->task;
	if_name = data->if_name;

	DBG("provider %p task %p interface %s user_data %p", provider, task,
				if_name, data->user_data);

	connman_task_add_argument(task, "--non-inter", NULL);
	connman_task_add_argument(task, "--no-detach", NULL);

	connman_task_add_argument(task, "--ifname", if_name);
	option = vpn_provider_get_string(provider, "VPNC.DeviceType");
	if (option) {
		connman_task_add_argument(task, "--ifmode", option);
	} else {
		/*
		 * Default to tun for backwards compatibility.
		 */
		connman_task_add_argument(task, "--ifmode", "tun");
	}

	connman_task_add_argument(task, "--script", SCRIPTDIR "/vpn-script");

	option = vpn_provider_get_string(provider, "VPNC.Debug");
	if (option)
		connman_task_add_argument(task, "--debug", option);

	connman_task_add_argument(task, "-", NULL);

	err = connman_task_run(data->task, vc_died, data, &fd, NULL, NULL);
	if (err < 0) {
		connman_error("vpnc failed to start");
		err = -EIO;
		goto done;
	}

	err = vc_write_config_data(provider, fd);

	if (err) {
		DBG("config write error %s", strerror(err));
		goto done;
	}

	err = -EINPROGRESS;

done:
	close(fd);

	/*
	 * Clear out credentials if they are non-immutable. If this is called
	 * directly from vc_connect() all credentials are read from config and
	 * are set as immutable, so no change is done. In case a VPN agent is
	 * used these values should be reset to "-" in order to retrieve them
	 * from VPN agent next time VPN connection is established. This supports
	 * then partially defined credentials in .config and some can be
	 * retrieved using an agent.
	 */
	for (i = 0; credentials[i]; i++) {
		const char *key = credentials[i];
		if (!vpn_provider_get_string_immutable(provider, key))
			vpn_provider_set_string(provider, key, "-");
	}

	return err;
}

static void request_input_append_mandatory(DBusMessageIter *iter,
		void *user_data)
{
	char *str = "string";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "mandatory";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);

	if (!user_data)
		return;

	str = user_data;
	connman_dbus_dict_append_basic(iter, "Value", DBUS_TYPE_STRING, &str);
}

static void request_input_append_password(DBusMessageIter *iter,
		void *user_data)
{
	char *str = "password";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "mandatory";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);

	if (!user_data)
		return;

	str = user_data;
	connman_dbus_dict_append_basic(iter, "Value", DBUS_TYPE_STRING, &str);
}

static void request_input_credentials_reply(DBusMessage *reply, void *user_data)
{
	struct vc_private_data *data = user_data;
	char *secret = NULL, *username = NULL, *password = NULL;
	const char *key;
	DBusMessageIter iter, dict;
	DBusError error;
	int err_int = 0;

	DBG("provider %p", data->provider);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		if (!g_strcmp0(error.name, VPN_AGENT_INTERFACE
							".Error.Canceled"))
			err_int = ECONNABORTED;

		if (!g_strcmp0(error.name, VPN_AGENT_INTERFACE
							".Error.Timeout"))
			err_int = ETIMEDOUT;

		dbus_error_free(&error);
		goto abort;
	}

	if (!vpn_agent_check_reply_has_dict(reply))
		goto err;

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "VPNC.IPSec.Secret")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &secret);
			vpn_provider_set_string_hide_value(data->provider,
					key, secret);

		} else if (g_str_equal(key, "VPNC.Xauth.Username")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &username);
			vpn_provider_set_string(data->provider, key, username);

		} else if (g_str_equal(key, "VPNC.Xauth.Password")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &password);
			vpn_provider_set_string_hide_value(data->provider, key,
						password);
		}

		dbus_message_iter_next(&dict);
	}

	if (!secret || !username || !password)
		goto err;

	err_int = run_connect(data);
	if (err_int != -EINPROGRESS)
		goto err;

	return;

err:
	err_int = EACCES;

abort:
	vc_connect_done(data, err_int);
	
	vpn_provider_indicate_error(data->provider,
					VPN_PROVIDER_ERROR_AUTH_FAILED);
}

static int request_input_credentials(struct vc_private_data *data,
					const char* dbus_sender)
{
	struct vpn_provider *provider = data->provider;
	DBusMessage *message;
	const char *path, *agent_sender, *agent_path;
	DBusMessageIter iter;
	DBusMessageIter dict;
	const char *str;
	int err;
	void *agent;

	DBG("provider %p data %p sender %s", provider, data, dbus_sender);

	agent = connman_agent_get_info(dbus_sender, &agent_sender,
							&agent_path);
	if (!provider || !agent || !agent_path)
		return -ESRCH;

	message = dbus_message_new_method_call(agent_sender, agent_path,
					VPN_AGENT_INTERFACE,
					"RequestInput");
	if (!message)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);

	path = vpn_provider_get_path(provider);
	dbus_message_iter_append_basic(&iter,
				DBUS_TYPE_OBJECT_PATH, &path);

	connman_dbus_dict_open(&iter, &dict);

	str = vpn_provider_get_string(provider, "VPNC.IPSec.Secret");
	connman_dbus_dict_append_dict(&dict, "VPNC.IPSec.Secret",
				request_input_append_password,
				str ? (void *)str : NULL);

	str = vpn_provider_get_string(provider, "VPNC.Xauth.Username");
	connman_dbus_dict_append_dict(&dict, "VPNC.Xauth.Username",
				request_input_append_mandatory,
				str ? (void *)str : NULL);

	str = vpn_provider_get_string(provider, "VPNC.Xauth.Password");
	connman_dbus_dict_append_dict(&dict, "VPNC.Xauth.Password",
				request_input_append_password,
				str ? (void *)str : NULL);

	vpn_agent_append_host_and_name(&dict, provider);

	connman_dbus_dict_close(&iter, &dict);

	err = connman_agent_queue_message(provider, message,
			connman_timeout_input_request(),
			request_input_credentials_reply, data, agent);

	if (err < 0 && err != -EBUSY) {
		DBG("error %d sending agent request", err);
		dbus_message_unref(message);

		return err;
	}

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static int vc_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb, const char *dbus_sender,
			void *user_data)
{
	struct vc_private_data *data;
	const char *option;
	bool username_set = false;
	bool password_set = false;
	bool ipsec_secret_set = false;
	int err;
	
	DBG("provider %p if_name %s user_data %p", provider, if_name, user_data);

	option = vpn_provider_get_string(provider, "Host");
	if (!option) {
		connman_error("Host not set; cannot enable VPN");
		return -EINVAL;
	}

	option = vpn_provider_get_string(provider, "VPNC.IPSec.ID");
	if (!option) {
		connman_error("Group not set; cannot enable VPN");
		return -EINVAL;
	}

	option = vpn_provider_get_string(provider, "VPNC.IPSec.Secret");
	if (option && *option && g_strcmp0(option, "-"))
		ipsec_secret_set = true;
	DBG("VPNC.IPSec.Secret %s", option);

	option = vpn_provider_get_string(provider, "VPNC.Xauth.Username");
	if (option && *option && g_strcmp0(option, "-"))
		username_set = true;
	DBG("VPNC.Xauth.Username %s", option);
	
	option = vpn_provider_get_string(provider, "VPNC.Xauth.Password");
	if (option && *option && g_strcmp0(option, "-"))
		password_set = true;
	DBG("VPNC.Xauth.Password %s", option);

	data = g_try_new0(struct vc_private_data, 1);
	if (!data)
		return -ENOMEM;

	vpn_provider_set_plugin_data(provider, data);
	data->provider = vpn_provider_ref(provider);
	data->task = task;
	data->if_name = g_strdup(if_name);
	data->cb = cb;
	data->user_data = user_data;

	if (!ipsec_secret_set || !username_set || !password_set) {
		err = request_input_credentials(data, dbus_sender);
		if (err != -EINPROGRESS) {
			vc_connect_done(data, ECONNABORTED);
			vpn_provider_indicate_error(data->provider,
					VPN_PROVIDER_ERROR_LOGIN_FAILED);
			free_private_data(data);
		}

		return err;
	}

	return run_connect(data);
}

static int vc_error_code(struct vpn_provider *provider, int exit_code)
{
	switch (exit_code) {
	case 1:
		return VPN_PROVIDER_ERROR_CONNECT_FAILED;
	case 2:
		return VPN_PROVIDER_ERROR_LOGIN_FAILED;
	default:
		return VPN_PROVIDER_ERROR_UNKNOWN;
	}
}

static int vc_device_flags(struct vpn_provider *provider)
{
	const char *option;

	option = vpn_provider_get_string(provider, "VPNC.DeviceType");
	if (!option) {
		return IFF_TUN;
	}

	if (g_str_equal(option, "tap")) {
		return IFF_TAP;
	}

	if (!g_str_equal(option, "tun")) {
		connman_warn("bad VPNC.DeviceType value, falling back to tun");
	}

	return IFF_TUN;
}

static struct vpn_driver vpn_driver = {
	.notify		= vc_notify,
	.connect	= vc_connect,
	.error_code	= vc_error_code,
	.save		= vc_save,
	.device_flags	= vc_device_flags,
};

static int vpnc_init(void)
{
	return vpn_register("vpnc", &vpn_driver, VPNC);
}

static void vpnc_exit(void)
{
	vpn_unregister("vpnc");
}

CONNMAN_PLUGIN_DEFINE(vpnc, "vpnc plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, vpnc_init, vpnc_exit)
