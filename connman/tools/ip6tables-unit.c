/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013-2014  BMW Car IT GmbH.
 *  Copyright (C) 2018  Jolla Ltd. All rights reserved.
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

#include <glib.h>
#include <errno.h>

#include "../src/connman.h"

static bool assert_rule(const char *table_name, const char *rule)
{
	char *cmd, *output, **lines;
	GError **error = NULL;
	int i;
	bool ret = true;

	cmd = g_strdup_printf(IP6TABLES_SAVE " -t %s", table_name);
	g_spawn_command_line_sync(cmd, &output, NULL, NULL, error);
	g_free(cmd);

	lines = g_strsplit(output, "\n", 0);
	g_free(output);
	if (!lines)
		return false;

	for (i = 0; lines[i]; i++) {
		DBG("lines[%02d]: %s\n", i, lines[i]);
		if (g_strcmp0(lines[i], rule) == 0)
			break;
	}

	if (!lines[i])
		ret = false;

	g_strfreev(lines);
	return ret;
}

static void assert_rule_exists(const char *table_name, const char *rule)
{
	if (g_strcmp0(IP6TABLES_SAVE, "") == 0) {
		DBG("ip6tables-save is missing, no assertion possible");
		return;
	}

	g_assert(assert_rule(table_name, rule));
}

static void assert_rule_not_exists(const char *table_name, const char *rule)
{
	if (g_strcmp0(IP6TABLES_SAVE, "") == 0) {
		DBG("ip6tables-save is missing, no assertion possible");
		return;
	}

	g_assert(!assert_rule(table_name, rule));
}

static void test_ip6tables_chain0(void)
{
	int err;

	err = __connman_ip6tables_new_chain("filter", "foo");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_exists("filter", ":foo - [0:0]");

	err = __connman_ip6tables_delete_chain("filter", "foo");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_not_exists("filter", ":foo - [0:0]");
}

static void test_ip6tables_chain1(void)
{
	int err;

	err = __connman_ip6tables_new_chain("filter", "foo");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	err = __connman_ip6tables_flush_chain("filter", "foo");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	err = __connman_ip6tables_delete_chain("filter", "foo");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);
}

static void test_ip6tables_chain2(void)
{
	int err;

	err = __connman_ip6tables_change_policy("filter", "INPUT", "DROP");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	err = __connman_ip6tables_change_policy("filter", "INPUT", "ACCEPT");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);
}

static void test_ip6tables_chain3(void)
{
	int err;

	err = __connman_ip6tables_new_chain("filter", "user-chain-0");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_exists("filter", ":user-chain-0 - [0:0]");

	err = __connman_ip6tables_new_chain("filter", "user-chain-1");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_exists("filter", ":user-chain-0 - [0:0]");
	assert_rule_exists("filter", ":user-chain-1 - [0:0]");

	err = __connman_ip6tables_delete_chain("filter", "user-chain-1");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_exists("filter", ":user-chain-0 - [0:0]");
	assert_rule_not_exists("filter", ":user-chain-1 - [0:0]");

	err = __connman_ip6tables_delete_chain("filter", "user-chain-0");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_not_exists("filter", ":user-chain-0 - [0:0]");
}

static void test_ip6tables_rule0(void)
{
	int err;

	/* Test simple appending and removing a rule */

	err = __connman_ip6tables_append("filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_exists("filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");

	err = __connman_ip6tables_delete("filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_not_exists("filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
}

static void test_ip6tables_rule1(void)
{
	int err;

	/* Test if we can do NAT stuff */

	err = __connman_ip6tables_append("nat", "POSTROUTING",
				"-s FC00::/7 -o eth0 -j MASQUERADE");

	err = __connman_ip6tables_commit("nat");
	g_assert(err == 0);

	assert_rule_exists("nat",
		"-A POSTROUTING -s FC00::/7 -o eth0 -j MASQUERADE");

	err = __connman_ip6tables_delete("nat", "POSTROUTING",
				"-s FC00::/7 -o eth0 -j MASQUERADE");

	err = __connman_ip6tables_commit("nat");
	g_assert(err == 0);

	assert_rule_not_exists("nat",
		"-A POSTROUTING -s FC00::/7 -o eth0 -j MASQUERADE");
}

static void test_ip6tables_rule2(void)
{
	int err;

	/* Test if the right rule is removed */

	err = __connman_ip6tables_append("filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_exists("filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");

	err = __connman_ip6tables_append("filter", "INPUT",
					"-m mark --mark 2 -j LOG");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_exists("filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
	assert_rule_exists("filter",
				"-A INPUT -m mark --mark 0x2 -j LOG");

	err = __connman_ip6tables_delete("filter", "INPUT",
					"-m mark --mark 2 -j LOG");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_exists("filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
	assert_rule_not_exists("filter",
				"-A INPUT -m mark --mark 0x2 -j LOG");

	err = __connman_ip6tables_delete("filter", "INPUT",
					"-m mark --mark 1 -j LOG");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_not_exists("filter",
				"-A INPUT -m mark --mark 0x1 -j LOG");
}

static void test_ip6tables_target0(void)
{
	int err;

	/* Test if 'fallthrough' targets work */

	err = __connman_ip6tables_append("filter", "INPUT",
					"-m mark --mark 1");
	g_assert(err == 0);

	err = __connman_ip6tables_append("filter", "INPUT",
					"-m mark --mark 2");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_exists("filter", "-A INPUT -m mark --mark 0x1");
	assert_rule_exists("filter", "-A INPUT -m mark --mark 0x2");

	err = __connman_ip6tables_delete("filter", "INPUT",
					"-m mark --mark 1");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	err = __connman_ip6tables_delete("filter", "INPUT",
					"-m mark --mark 2");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("filter");
	g_assert(err == 0);

	assert_rule_not_exists("filter", "-A INPUT -m mark --mark 0x1");
	assert_rule_not_exists("filter", "-A INPUT -m mark --mark 0x2");
}

struct connman_notifier *nat_notifier;

struct connman_service {
	char *dummy;
};

char *connman_service_get_interface(struct connman_service *service)
{
	return "eth0";
}

/*
int connman_notifier_register(struct connman_notifier *notifier)
{
	nat_notifier = notifier;

	return 0;
}

void connman_notifier_unregister(struct connman_notifier *notifier)
{
	nat_notifier = NULL;
}

static void test_nat_basic0(void)
{
	int err;

	err = __connman_nat_enable("bridge", "192.168.2.1", 24);
	g_assert(err == 0);

	// test that table is empty
	err = __connman_ip6tables_append("nat", "POSTROUTING",
					"-s 192.168.2.1/24 -o eth0 -j MASQUERADE");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("nat");
	g_assert(err == 0);

	assert_rule_exists("nat",
		"-A POSTROUTING -s 192.168.2.0/24 -o eth0 -j MASQUERADE");

	err = __connman_ip6tables_delete("nat", "POSTROUTING",
					"-s 192.168.2.1/24 -o eth0 -j MASQUERADE");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("nat");
	g_assert(err == 0);

	assert_rule_not_exists("nat",
		"-A POSTROUTING -s 192.168.2.0/24 -o eth0 -j MASQUERADE");

	__connman_nat_disable("bridge");
}

static void test_nat_basic1(void)
{
	struct connman_service *service;
	int err;

	service = g_try_new0(struct connman_service, 1);
	g_assert(service);

	nat_notifier->default_changed(service);

	err = __connman_nat_enable("bridge", "192.168.2.1", 24);
	g_assert(err == 0);

	// test that table is not empty
	err = __connman_ip6tables_append("nat", "POSTROUTING",
					"-s 192.168.2.1/24 -o eth0 -j MASQUERADE");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("nat");
	g_assert(err == 0);

	__connman_nat_disable("bridge");

	// test that table is empty again
	err = __connman_ip6tables_delete("nat", "POSTROUTING",
					"-s 192.168.2.1/24 -o eth0 -j MASQUERADE");
	g_assert(err == 0);

	err = __connman_ip6tables_commit("nat");
	g_assert(err == 0);

	g_free(service);
}*/

static void test_firewall6_basic0(void)
{
	struct firewall6_context *ctx;
	int err;

	ctx = __connman_firewall6_create();
	g_assert(ctx);

	err = __connman_firewall6_add_rule(ctx, "filter", "INPUT",
					"-m mark --mark 999 -j LOG");
	g_assert(err >= 0);

	err = __connman_firewall6_enable(ctx);
	g_assert(err == 0);

	assert_rule_exists("filter", ":connman-INPUT - [0:0]");
	assert_rule_exists("filter", "-A INPUT -j connman-INPUT");
	assert_rule_exists("filter", "-A connman-INPUT -m mark --mark 0x3e7 -j LOG");

	err = __connman_firewall6_disable(ctx);
	g_assert(err == 0);

	assert_rule_not_exists("filter", ":connman-INPUT - [0:0]");
	assert_rule_not_exists("filter", "-A INPUT -j connman-INPUT");
	assert_rule_not_exists("filter", "-A connman-INPUT -m mark --mark 0x3e7 -j LOG");

	__connman_firewall6_destroy(ctx);
}

static void test_firewall6_basic1(void)
{
	struct firewall6_context *ctx;
	int err;

	ctx = __connman_firewall6_create();
	g_assert(ctx);

	err = __connman_firewall6_add_rule(ctx, "filter", "INPUT",
					"-m mark --mark 999 -j LOG");
	g_assert(err >= 0);

	err = __connman_firewall6_add_rule(ctx, "filter", "OUTPUT",
					"-m mark --mark 999 -j LOG");
	g_assert(err >= 0);

	err = __connman_firewall6_enable(ctx);
	g_assert(err == 0);

	err = __connman_firewall6_disable(ctx);
	g_assert(err == 0);

	__connman_firewall6_destroy(ctx);
}

static void test_firewall6_basic2(void)
{
	struct firewall6_context *ctx;
	int err;

	ctx = __connman_firewall6_create();
	g_assert(ctx);

	err = __connman_firewall6_add_rule(ctx, "mangle", "INPUT",
					"-j CONNMARK --restore-mark");
	g_assert(err >= 0);

	err = __connman_firewall6_add_rule(ctx, "mangle", "POSTROUTING",
					"-j CONNMARK --save-mark");
	g_assert(err >= 0);

	err = __connman_firewall6_enable(ctx);
	g_assert(err == 0);

	err = __connman_firewall6_disable(ctx);
	g_assert(err == 0);

	__connman_firewall6_destroy(ctx);
}

static void test_firewall6_basic3(void)
{
	struct firewall6_context *ctx;
	int err, id;

	ctx = __connman_firewall6_create();
	g_assert(ctx);

	id = __connman_firewall6_add_rule(ctx, "mangle", "INPUT",
					"-j CONNMARK --restore-mark");
	g_assert(id >= 0);

	err = __connman_firewall6_enable_rule(ctx, id);
	g_assert(err == 0);

	err = __connman_firewall6_disable_rule(ctx, id);
	g_assert(err == 0);

	err = __connman_firewall6_remove_rule(ctx, id);
	g_assert(err == 0);

	err = __connman_firewall6_disable(ctx);
	g_assert(err == -ENOENT);

	__connman_firewall6_destroy(ctx);
}*/

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

int main(int argc, char *argv[])
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

	__connman_iptables_init();
	__connman_firewall6_init();
	//__connman_nat_init();

	g_test_add_func("/ip6tables/chain0", test_ip6tables_chain0);
	g_test_add_func("/ip6tables/chain1", test_ip6tables_chain1);
	g_test_add_func("/ip6tables/chain2", test_ip6tables_chain2);
	g_test_add_func("/ip6tables/chain3", test_ip6tables_chain3);
	g_test_add_func("/ip6tables/rule0",  test_ip6tables_rule0);
	g_test_add_func("/ip6tables/rule1",  test_ip6tables_rule1);
	g_test_add_func("/ip6tables/rule2",  test_ip6tables_rule2);
	g_test_add_func("/ip6tables/target0", test_ip6tables_target0);
	/*g_test_add_func("/nat/basic0", test_nat_basic0);
	g_test_add_func("/nat/basic1", test_nat_basic1);*/
	g_test_add_func("/firewall/basic0", test_firewall6_basic0);
	g_test_add_func("/firewall/basic1", test_firewall6_basic1);
	g_test_add_func("/firewall/basic2", test_firewall6_basic2);
	g_test_add_func("/firewall/basic3", test_firewall6_basic3);

	err = g_test_run();

	//__connman_nat_cleanup();
	__connman_firewall_cleanup();
	__connman_iptables_cleanup();

	g_free(option_debug);

	return err;
}
