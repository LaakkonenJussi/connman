/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013,2015  BMW Car IT GmbH.
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
#include <netdb.h>

#include <xtables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include <gdbus.h>

#include "connman.h"

#define CHAIN_PREFIX "connman-"
#define FW_ALL_RULES -1

/*
 * All IPv6 equivalents of the indexes used here have the same values as the
 * IPv4 ones.
 */
static const char *builtin_chains[] = {
	[NF_IP_PRE_ROUTING]	= "PREROUTING",
	[NF_IP_LOCAL_IN]	= "INPUT",
	[NF_IP_FORWARD]		= "FORWARD",
	[NF_IP_LOCAL_OUT]	= "OUTPUT",
	[NF_IP_POST_ROUTING]	= "POSTROUTING",
};

struct connman_managed_table {
	int type;
	char *name;
	unsigned int chains[NF_INET_NUMHOOKS];
};

struct fw_rule {
	int id;
	int type;
	bool enabled;
	char *table;
	char *chain;
	char *rule_spec;
	char *ifname;
	char *config_file;
	connman_iptables_manage_cb_t cb;
};

struct firewall_context {
	GList *rules;
	bool enabled;
};

static GSList *managed_tables = NULL;

static bool firewall_is_up;
static unsigned int firewall_rule_id;

#define FIREWALLFILE "firewall.conf"
#define FIREWALLCONFIGFILE CONFIGDIR "/" FIREWALLFILE
#define FIREWALLCONFIGDIR CONFIGDIR "/firewall.d/"
#define GROUP_GENERAL "General"
#define GROUP_TETHERING "tethering"
#define GENERAL_FIREWALL_POLICIES 3

/* TODO add all (tethering and dynamic) under this general firewall context */
struct general_firewall_context {
	char **policies;
	char **policiesv6;
	char **restore_policies;
	char **restore_policiesv6;
	struct firewall_context *ctx;
};

static struct general_firewall_context *general_firewall = NULL;

/* The dynamic rules that are loaded from config */
static struct firewall_context **dynamic_rules = NULL;

/* Tethering rules are a special case */
static struct firewall_context *tethering_firewall = NULL;

/* Configuration files that are read */
static GList *configuration_files = NULL;

static const char *supported_chains[] = {
	[NF_IP_PRE_ROUTING]	= NULL,
	[NF_IP_LOCAL_IN]	= "IPv4.INPUT.RULES",
	[NF_IP_FORWARD]		= "IPv4.FORWARD.RULES",
	[NF_IP_LOCAL_OUT]	= "IPv4.OUTPUT.RULES",
	[NF_IP_POST_ROUTING]	= NULL,
};

static const char *supported_chainsv6[] = {
	[NF_IP_PRE_ROUTING]	= NULL,
	[NF_IP_LOCAL_IN]	= "IPv6.INPUT.RULES",
	[NF_IP_FORWARD]		= "IPv6.FORWARD.RULES",
	[NF_IP_LOCAL_OUT]	= "IPv6.OUTPUT.RULES",
	[NF_IP_POST_ROUTING]	= NULL,
};

static const char *supported_policies[] = {
	[NF_IP_PRE_ROUTING]	= NULL,
	[NF_IP_LOCAL_IN]	= "IPv4.INPUT.POLICY",
	[NF_IP_FORWARD]		= "IPv4.FORWARD.POLICY",
	[NF_IP_LOCAL_OUT]	= "IPv4.OUTPUT.POLICY",
	[NF_IP_POST_ROUTING]	= NULL,
};

static const char *supported_policiesv6[] = {
	[NF_IP_PRE_ROUTING]	= NULL,
	[NF_IP_LOCAL_IN]	= "IPv6.INPUT.POLICY",
	[NF_IP_FORWARD]		= "IPv6.FORWARD.POLICY",
	[NF_IP_LOCAL_OUT]	= "IPv6.OUTPUT.POLICY",
	[NF_IP_POST_ROUTING]	= NULL,
};

/*
 * The dynamic rules that are currently in use. Service name is used as hash
 * value and the struct firewall_context is the data held.
 */
static GHashTable *current_dynamic_rules = NULL;

static int firewall_rule_compare(gconstpointer a, gconstpointer b)
{
	const struct fw_rule *rule_a;
	const struct fw_rule *rule_b;

	rule_a = a;
	rule_b = b;

	/*
	 * g_strcmp0 sorts NULLs before others, the system defined rules that
	 * are added by connman have no config_file and should be on top of
	 * other rules.
	 */
	return g_strcmp0(rule_a->config_file, rule_b->config_file);
}

static int chain_to_index(const char *chain_name)
{
	if (!g_strcmp0(builtin_chains[NF_IP_PRE_ROUTING], chain_name))
		return NF_IP_PRE_ROUTING;
	if (!g_strcmp0(builtin_chains[NF_IP_LOCAL_IN], chain_name))
		return NF_IP_LOCAL_IN;
	if (!g_strcmp0(builtin_chains[NF_IP_FORWARD], chain_name))
		return NF_IP_FORWARD;
	if (!g_strcmp0(builtin_chains[NF_IP_LOCAL_OUT], chain_name))
		return NF_IP_LOCAL_OUT;
	if (!g_strcmp0(builtin_chains[NF_IP_POST_ROUTING], chain_name))
		return NF_IP_POST_ROUTING;

	return -1;
}

static int managed_chain_to_index(const char *chain_name)
{
	if (!g_str_has_prefix(chain_name, CHAIN_PREFIX))
		return -1;

	return chain_to_index(chain_name + strlen(CHAIN_PREFIX));
}

static int insert_managed_chain(int type, const char *table_name, int id)
{
	char *rule, *managed_chain;
	int err;

	managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX,
					builtin_chains[id]);

	err = __connman_iptables_new_chain(type, table_name, managed_chain);

	if (err < 0)
		goto out;

	rule = g_strdup_printf("-j %s", managed_chain);

	err = __connman_iptables_insert(type, table_name,
					builtin_chains[id], rule);

	g_free(rule);
	if (err < 0) {
		__connman_iptables_delete_chain(type, table_name,
						managed_chain);
		goto out;
	}

out:
	g_free(managed_chain);

	return err;
}

static int delete_managed_chain(int type, const char *table_name, int id)
{
	char *rule, *managed_chain;
	int err;

	managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX,
					builtin_chains[id]);

	rule = g_strdup_printf("-j %s", managed_chain);
	err = __connman_iptables_delete(type, table_name,
					builtin_chains[id], rule);
	g_free(rule);

	if (err < 0)
		goto out;

	err =  __connman_iptables_delete_chain(type, table_name,
					managed_chain);

out:
	g_free(managed_chain);

	return err;
}

static char *format_new_rule(int chain, const char* ifname, const char* rule)
{
	char *new_rule = NULL;

	if (ifname && *ifname && rule && *rule) {
		switch (chain) {
		case NF_IP_LOCAL_IN:
			new_rule = g_strdup_printf("-i %s %s", ifname, rule);
			break;
		case NF_IP_FORWARD:
		case NF_IP_LOCAL_OUT:
			new_rule = g_strdup_printf("-o %s %s", ifname, rule);
			break;
		default:
			break;
		}
	}

	return new_rule;
}

static int insert_managed_rule(connman_iptables_manage_cb_t cb,
				int type,
				const char *table_name,
				const char *chain_name,
				const char *ifname,
				const char *rule_spec)
{
	struct connman_managed_table *mtable = NULL;
	GSList *list;
	char *chain;
	char *full_rule = NULL;
	int id, err;

	id = chain_to_index(chain_name);

	full_rule = format_new_rule(id, ifname, rule_spec);

	if (id < 0) {
		/* This chain is not managed */
		chain = g_strdup(chain_name);
		goto out;
	}

	for (list = managed_tables; list; list = list->next) {
		mtable = list->data;

		if (g_strcmp0(mtable->name, table_name) == 0 &&
				mtable->type == type)
			break;

		mtable = NULL;
	}

	if (!mtable) {
		mtable = g_new0(struct connman_managed_table, 1);
		mtable->name = g_strdup(table_name);
		mtable->type = type;

		managed_tables = g_slist_prepend(managed_tables, mtable);
	}

	if (mtable->chains[id] == 0) {
		DBG("table %s add managed chain for %s",
			table_name, chain_name);

		err = insert_managed_chain(type, table_name, id);
		if (err < 0)
			return err;
	}

	mtable->chains[id]++;
	chain = g_strdup_printf("%s%s", CHAIN_PREFIX, chain_name);

out:
	if (cb)
		err = cb(type, table_name, chain,
					full_rule ? full_rule : rule_spec);
	else
		err = __connman_iptables_append(type, table_name, chain,
					full_rule ? full_rule : rule_spec);
	
	if (err < 0)
		DBG("table %s cannot append rule %s", table_name,
				full_rule ? full_rule : rule_spec);

	g_free(chain);
	g_free(full_rule);

	return err;
 }

static int delete_managed_rule(int type, const char *table_name,
				const char *chain_name,
				const char *ifname,
				const char *rule_spec)
 {
	struct connman_managed_table *mtable = NULL;
	GSList *list;
	int id, err;
	char *managed_chain;
	char *full_rule = NULL;

	id = chain_to_index(chain_name);

	full_rule = format_new_rule(id, ifname, rule_spec);

	if (id < 0) {
		/* This chain is not managed */
		return __connman_iptables_delete(type, table_name,
					chain_name,
					full_rule ? full_rule : rule_spec);
	}

	managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX, chain_name);

	err = __connman_iptables_delete(type, table_name, managed_chain,
				full_rule ? full_rule : rule_spec);
	
	if (err < 0)
		DBG("table %s managed rule %s was not removed from ip%stables",
			table_name, full_rule ? full_rule : rule_spec,
			type == AF_INET6 ? "6" : "");

	for (list = managed_tables; list; list = list->next) {
		mtable = list->data;

		if (g_strcmp0(mtable->name, table_name) == 0 &&
				mtable->type == type)
			break;

		mtable = NULL;
	}

	if (!mtable) {
		err = -ENOENT;
		goto out;
	}

	mtable->chains[id]--;
	if (mtable->chains[id] > 0)
		goto out;

	DBG("table %s remove managed chain for %s",
			table_name, chain_name);

	err = delete_managed_chain(type, table_name, id);

 out:
	g_free(managed_chain);
	g_free(full_rule);

	return err;
}

static void cleanup_managed_table(gpointer user_data)
{
	struct connman_managed_table *table = user_data;

	g_free(table->name);
	g_free(table);
}

static void cleanup_fw_rule(gpointer user_data)
{
	struct fw_rule *rule = user_data;

	g_free(rule->ifname);
	g_free(rule->rule_spec);
	g_free(rule->chain);
	g_free(rule->table);
	g_free(rule->config_file);
	g_free(rule);
}

struct firewall_context *__connman_firewall_create(void)
{
	struct firewall_context *ctx;

	ctx = g_new0(struct firewall_context, 1);

	return ctx;
}

void __connman_firewall_destroy(struct firewall_context *ctx)
{
	g_list_free_full(ctx->rules, cleanup_fw_rule);
	g_free(ctx);
}

static int firewall_enable_rule(struct fw_rule *rule)
{
	int err;

	if (rule->enabled)
		return -EALREADY;

	DBG("%d %s %s %s %s", rule->type, rule->table, rule->chain,
					rule->ifname, rule->rule_spec);

	err = insert_managed_rule(rule->cb, rule->type, rule->table,
					rule->chain, rule->ifname,
					rule->rule_spec);
	if (err < 0) {
		DBG("cannot insert managed rule %d", err);
		return err;
	}

	err = __connman_iptables_commit(rule->type, rule->table);

	if (err < 0) {
		DBG("iptables commit failed %d", err);
		return err;
	}

	rule->enabled = true;

	return 0;
}

static int firewall_disable_rule(struct fw_rule *rule)
{
	int err;

	if (!rule->enabled)
		return -EALREADY;

	err = delete_managed_rule(rule->type, rule->table, rule->chain,
					rule->ifname, rule->rule_spec);
	if (err < 0) {
		connman_error("pre-commit: Cannot remove previously installed "
			"iptables rules: %s", strerror(-err));
		return err;
	}

	err = __connman_iptables_commit(rule->type, rule->table);
	
	if (err < 0) {
		connman_error("Cannot remove previously installed "
			"iptables rules: %s", strerror(-err));
		return err;
	}

	rule->enabled = false;

	return 0;
}

int __connman_firewall_add_rule(struct firewall_context *ctx,
				connman_iptables_manage_cb_t cb,
				const char *config_file,
				const char *table,
				const char *chain,
				const char *rule_fmt, ...)
{
	va_list args;
	char *rule_spec;
	struct fw_rule *rule;

	va_start(args, rule_fmt);

	rule_spec = g_strdup_vprintf(rule_fmt, args);

	va_end(args);

	rule = g_new0(struct fw_rule, 1);

	rule->id = firewall_rule_id++;
	rule->type = AF_INET;
	rule->enabled = false;
	rule->cb = cb;

	if (config_file)
		rule->config_file = g_path_get_basename(config_file);

	rule->table = g_strdup(table);
	rule->chain = g_strdup(chain);
	rule->rule_spec = rule_spec;

	ctx->rules = g_list_insert_sorted(ctx->rules, rule,
				firewall_rule_compare);
	return rule->id;
}

int __connman_firewall_add_ipv6_rule(struct firewall_context *ctx,
				connman_iptables_manage_cb_t cb,
				const char *config_file,
				const char *table,
				const char *chain,
				const char *rule_fmt, ...)
{
	va_list args;
	char *rule_spec;
	struct fw_rule *rule;

	va_start(args, rule_fmt);

	rule_spec = g_strdup_vprintf(rule_fmt, args);

	va_end(args);

	rule = g_new0(struct fw_rule, 1);

	rule->id = firewall_rule_id++;
	rule->type = AF_INET6;
	rule->enabled = false;
	rule->cb = cb;

	if (config_file)
		rule->config_file = g_path_get_basename(config_file);

	rule->table = g_strdup(table);
	rule->chain = g_strdup(chain);
	rule->rule_spec = rule_spec;

	ctx->rules = g_list_insert_sorted(ctx->rules, rule,
				firewall_rule_compare);
	return rule->id;
}

int __connman_firewall_remove_rule(struct firewall_context *ctx, int id)
{
	struct fw_rule *rule;
	GList *list;
	int err = -ENOENT;

	list = g_list_last(ctx->rules);
	while (list) {
		GList *prev = g_list_previous(list);

		rule = list->data;
		if (rule->id == id || id == FW_ALL_RULES) {
			ctx->rules = g_list_remove(ctx->rules, rule);
			cleanup_fw_rule(rule);
			err = 0;

			if (id != FW_ALL_RULES)
				break;
		}

		list = prev;
	}

	return err;
}

/* For consistency, both IPv4 and IPv6 rules can be removed in similar way. */
int __connman_firewall_remove_ipv6_rule(struct firewall_context *ctx, int id)
{
	return __connman_firewall_remove_rule(ctx, id);
}

int __connman_firewall_enable_rule(struct firewall_context *ctx, int id)
{
	struct fw_rule *rule;
	GList *list;
	int e;
	int err = -ENOENT;
	int count = 0;

	for (list = g_list_first(ctx->rules); list; list = g_list_next(list)) {
		rule = list->data;

		if (rule->id == id || id == FW_ALL_RULES) {
			e = firewall_enable_rule(rule);

			/* Do not stop if enabling all rules */
			if (e == 0 && err == -ENOENT)
				err = 0;
			else if (e < 0)
				err = e;

			if (id != FW_ALL_RULES)
				break;
		}

		count++;
	}

	if (!err && id == FW_ALL_RULES) {
		DBG("firewall enabled");
		ctx->enabled = true;
	}

	return err;
}

int __connman_firewall_disable_rule(struct firewall_context *ctx, int id)
{
	struct fw_rule *rule;
	GList *list;
	int e;
	int err = -ENOENT;

	for (list = g_list_last(ctx->rules); list;
			list = g_list_previous(list)) {
		rule = list->data;

		if (rule->id == id || id == FW_ALL_RULES) {
			e = firewall_disable_rule(rule);

			/* Report last error back */
			if (e == 0 && err == -ENOENT)
				err = 0;
			else if (e < 0)
				err = e;

			if (id != FW_ALL_RULES)
				break;
		}
	}

	if (!err && id == FW_ALL_RULES) {
		DBG("firewall disabled");
		ctx->enabled = false;
	}

	return err;
}

int __connman_firewall_enable(struct firewall_context *ctx)
{
	int err;

	err = __connman_firewall_enable_rule(ctx, FW_ALL_RULES);
	if (err < 0) {
		connman_warn("Failed to install iptables rules: %s",
				strerror(-err));
		__connman_firewall_disable_rule(ctx, FW_ALL_RULES);
		return err;
	}

	firewall_is_up = true;

	return 0;
}

int __connman_firewall_disable(struct firewall_context *ctx)
{
	__connman_firewall_disable_rule(ctx, FW_ALL_RULES);
	return __connman_firewall_remove_rule(ctx, FW_ALL_RULES);
}

bool __connman_firewall_is_up(void)
{
	return firewall_is_up;
}

static void iterate_chains_cb(const char *chain_name, void *user_data)
{
	GSList **chains = user_data;
	int id;

	id = managed_chain_to_index(chain_name);
	if (id < 0)
		return;

	*chains = g_slist_prepend(*chains, GINT_TO_POINTER(id));
}

static void flush_table(int type, const char *table_name)
{
	GSList *chains = NULL, *list;
	char *rule, *managed_chain;
	int id, err;

	err = __connman_iptables_iterate_chains(type, table_name,
					iterate_chains_cb, &chains);
	
	if (err < 0)
		DBG("table %s cannot iterate chains", table_name);

	for (list = chains; list; list = list->next) {
		id = GPOINTER_TO_INT(list->data);

		managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX,
						builtin_chains[id]);

		rule = g_strdup_printf("-j %s", managed_chain);
		
		err = __connman_iptables_delete(type, table_name,
						builtin_chains[id],
						rule);

		if (err < 0) {
			connman_warn("Failed to delete jump rule '%s': %s",
				rule, strerror(-err));
		}
		g_free(rule);

		err = __connman_iptables_flush_chain(type, table_name,
						managed_chain);
		
		if (err < 0) {
			connman_warn("Failed to flush chain '%s': %s",
				managed_chain, strerror(-err));
		}
		
		err = __connman_iptables_delete_chain(type, table_name,
						managed_chain);
		
		if (err < 0) {
			connman_warn("Failed to delete chain '%s': %s",
				managed_chain, strerror(-err));
		}

		g_free(managed_chain);
	}

	err = __connman_iptables_commit(type, table_name);
	if (err < 0) {
		connman_warn("Failed to flush table '%s': %s",
			table_name, strerror(-err));
	}

	g_slist_free(chains);
}

#define IP_TABLES_NAMES_FILE "/proc/net/ip_tables_names"
#define IP6_TABLES_NAMES_FILE "/proc/net/ip6_tables_names"

static void flush_all_tables(int type)
{
	gchar *content = NULL;
	gsize len = -1;
	GError *error = NULL;
	const char *iptables_file = NULL;
	const char *tables[] = { "filter", "mangle", "nat", NULL };
	char **tokens = NULL;
	int i, j;

	switch (type) {
	case AF_INET:
		iptables_file = IP_TABLES_NAMES_FILE;
		break;
	case AF_INET6:
		iptables_file = IP6_TABLES_NAMES_FILE;
		break;
	default:
		return;
	}

	if (!g_file_test(iptables_file,
			G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
		firewall_is_up = false;
		return;
	}

	firewall_is_up = true;

	if (!g_file_get_contents(iptables_file, &content, &len, &error)) {
		DBG("cannot flush tables, file %s read error: %s",
					iptables_file, error->message);
		g_clear_error(&error);
		goto out;
	}

	tokens = g_strsplit(content, "\n", -1);

	if (!tokens || !g_strv_length(tokens))
		goto out;

	/* Flush the tables ConnMan might have modified
	 * But do so if only ConnMan has done something with
	 * iptables */
	for (i = 0; tables[i]; i++) {
		for (j = 0; tokens[j]; j++) {
			if (!g_strcmp0(tables[i], tokens[j])) {
				DBG("flush type %d table %s", type, tables[i]);
				flush_table(type, tables[i]);
			}
		}
	}

out:
	g_free(content);
	g_strfreev(tokens);
}

static bool has_dynamic_rules_set(enum connman_service_type type)
{
	if (!dynamic_rules || !dynamic_rules[type])
		return false;

	if (g_list_length(dynamic_rules[type]->rules) == 0)
		return false;

	return true;
}

static void setup_firewall_rule_interface(gpointer data, gpointer user_data)
{
	struct fw_rule *rule;
	char *ifname;

	rule = data;
	ifname = user_data;

	/* If rule is already enabled interface info is already set */
	if (!rule || !ifname || rule->enabled)
		return;

	if (rule->ifname && g_str_equal(rule->ifname, ifname)) {
		DBG("rule %d ifname %s not changed", rule->id, rule->ifname);
		return;
	}

	g_free(rule->ifname);
	rule->ifname = g_strdup(ifname);

	DBG("rule %d %s %s", rule->id, rule->ifname, rule->rule_spec);
}

static gpointer copy_fw_rule(gconstpointer src, gpointer data)
{
	const struct fw_rule *old;
	struct fw_rule *new;
	char *ifname;
	
	old = src;
	ifname = data;

	if (!old)
		return NULL;

	new = g_try_new0(struct fw_rule, 1);

	if (!new)
		return NULL;

	new->id = firewall_rule_id++;
	new->enabled = false;
	new->type = old->type;
	new->cb = old->cb;

	if (old->config_file)
		new->config_file = g_strdup(old->config_file);

	new->table = g_strdup(old->table);
	new->chain = g_strdup(old->chain);
	new->rule_spec = g_strdup(old->rule_spec);

	setup_firewall_rule_interface(new, ifname);

	return new;
}

static struct firewall_context *clone_firewall_context(
						struct firewall_context *ctx,
						char *ifname)
{
	struct firewall_context *clone;

	if (!ctx || !ifname)
		return NULL;
	
	clone = __connman_firewall_create();
	
	if (!clone)
		return NULL;
	
	clone->rules = g_list_copy_deep(ctx->rules, copy_fw_rule, ifname);
	
	return clone;
}

static int enable_dynamic_rules(struct connman_service *service)
{
	struct firewall_context *ctx;
	enum connman_service_type type;
	const char *identifier;
	char *ifname = NULL;
	char *hash;

	DBG("");

	/* This is not set if the configuration has not been loaded */
	if (!current_dynamic_rules)
		return 0;

	identifier = connman_service_get_identifier(service);

	ctx = g_hash_table_lookup(current_dynamic_rules, identifier);

	/* Not found, check if it has dynamic rules configured */
	if (!ctx) {
		type = connman_service_get_type(service);
		
		/* No rules set for this type */
		if (!has_dynamic_rules_set(type))
			return 0;

		ifname = connman_service_get_interface(service);

		/* Create a clone with interface info from service */
		ctx = clone_firewall_context(dynamic_rules[type], ifname);

		/* Allocation of ctx failed */
		if (!ctx) {
			g_free(ifname);
			return -ENOMEM;
		}

		hash = g_strdup(identifier);

		/*
		 * Add a new into hash table, this condition should not be ever
		 * met. Left for debugging.
		 */
		if (!g_hash_table_replace(current_dynamic_rules, hash, ctx))
			DBG("hash table error, key %s exists", hash);
		else
			DBG("added new firewall rules for service %p %s",
					service, identifier);
	} else {
		if (ctx->enabled)
			return -EALREADY;

		ifname = connman_service_get_interface(service);

		/* Set interface information for each firewall rule */
		g_list_foreach(ctx->rules, setup_firewall_rule_interface,
					ifname);

		DBG("reused firewall for service %p %s", service, identifier);
	}

	g_free(ifname);

	return __connman_firewall_enable(ctx);
}

static int disable_dynamic_rules(struct connman_service *service)
{
	struct firewall_context *ctx;
	const char *identifier;

	DBG("");

	if (!current_dynamic_rules)
		return 0;

	identifier = connman_service_get_identifier(service);

	ctx = g_hash_table_lookup(current_dynamic_rules, identifier);

	/* No rules set, no error */
	if (!ctx)
		return 0;

	if (!ctx->enabled)
		return -EALREADY;

	/* Only disable rules, do not remove them to reduce mem fragmentation */
	return __connman_firewall_disable_rule(ctx, FW_ALL_RULES);
}

static void service_state_changed(struct connman_service *service,
				enum connman_service_state state)
{
	enum connman_service_type type;
	int err;

	type = connman_service_get_type(service);

	DBG("service %p %s type %d state %d", service,
				__connman_service_get_name(service), type,
				state);

	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		break;
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
		err = disable_dynamic_rules(service);

		if (err == -EALREADY)
			DBG("dynamic firewall already disabled for service %p",
						service);
		else if (err)
			DBG("cannot disable dynamic rules of service %p "
						"error %d", service, err);

		break;
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		err = enable_dynamic_rules(service);

		if (err == -EALREADY)
			DBG("dynamic firewall already enabled for service %p",
						service);
		else if (err == -ENOMEM)
			DBG("firewall cloning failed for service %p", service);
		else if (err)
			DBG("cannot enable dynamic rules of service %p "
						", error %d", service, err);
	}
}

static void service_remove(struct connman_service *service)
{
	const char *identifier;

	if (!current_dynamic_rules)
		return;

	identifier = connman_service_get_identifier(service);

	if (g_hash_table_remove(current_dynamic_rules, identifier))
		DBG("removed dynamic rules of service %s", identifier);
}

static int add_default_tethering_rules(struct firewall_context *ctx,
								char *ifname)
{
	/* Add more in the future if needed */
	const char *tethering_rules[] = { "-j ACCEPT", NULL };
	connman_iptables_manage_cb_t cb = __connman_iptables_insert;
	int id;
	int i;

	/* Add tethering rules for both IPv4 and IPv6 when using usb */
	for (i = 0; tethering_rules[i]; i++) {
		id = __connman_firewall_add_rule(ctx, cb, NULL, "filter",
					"INPUT", tethering_rules[i]);
		if (id < 0)
			DBG("cannot add IPv4 rule %s",
						tethering_rules[i]);

		id = __connman_firewall_add_ipv6_rule(ctx, cb, NULL, "filter",
					"INPUT", tethering_rules[i]);
		if (id < 0)
			DBG("cannot add IPv6 rule %s",
						tethering_rules[i]);
	}

	g_list_foreach(ctx->rules, setup_firewall_rule_interface, ifname);

	return 0;
}

#define DEFAULT_TETHERING_IDENT "tethering_default"

static void tethering_changed(struct connman_technology *tech, bool on)
{
	struct firewall_context *ctx;
	enum connman_service_type type;
	const char *identifier;
	char *ifname = NULL;
	char *hash;
	int err;
	
	DBG("technology %p %s", tech, on ? "on" : "off");
	
	if (!tech)
		return;
	
	/* This is not set if the configuration has not been loaded */
	if (!current_dynamic_rules)
		return;

	type = __connman_technology_get_type(tech);
	identifier = __connman_technology_get_tethering_ident(tech);
	
	/* This is known to happen with usb tethering, no ident exists */
	if (!identifier)
		identifier = DEFAULT_TETHERING_IDENT;
	
	DBG("tethering ident %s type %s", identifier,
				__connman_service_type2string(type));
	
	ctx = g_hash_table_lookup(current_dynamic_rules, identifier);

	/* Not found, create new. */
	if (!ctx) {
		/* If no rules are set and tethering is disabled, return */
		if (!on)
			return;

		/*
		 * Eventually ifname is duplicated for each rule but bridge is
		 * defined as const in technology.c it is safer to dup the
		 * ifname and free it accordingly.
		 */
		ifname = g_strdup(__connman_tethering_get_bridge());

		/* Clone with specific types only */
		switch (type) {
		case CONNMAN_SERVICE_TYPE_WIFI:
			ctx = clone_firewall_context(tethering_firewall,
						ifname);
			break;
		default:
			break;
		}

		/* No match to type of tethering_firewall is not set */
		if (!ctx) {
			ctx = __connman_firewall_create();

			/* Allocation of ctx failed, disable tethering. */
			if (!ctx) {
				DBG("new firewall cannot be created");
				goto disable;
			}
		}

		/* If list is empty add default rules */
		if (!g_list_length(ctx->rules)) {
			/* Try to add default rules for tethering */
			if (add_default_tethering_rules(ctx, ifname)) {
				DBG("default tethering rules cannot be added.");
				goto disable;
			}
		}

		hash = g_strdup(identifier);

		/*
		 * Add a new into hash table, this condition should not be ever
		 * met. Left for debugging.
		 */
		if (!g_hash_table_replace(current_dynamic_rules, hash, ctx))
			DBG("hash table error, key %s exists", hash);
		else
			DBG("added new tethering firewall rules for %p %s %s",
						tech, identifier, ifname);
	} else {
		/*
		 * If tethering is on and firewall is enabled, return. 
		 * If tethering is off and firewall is disabled, return.
		 */
		if ((on && ctx->enabled) || (!on && !ctx->enabled)) {
			DBG("tethering firewall already %s for %s",
						on ? "enabled" : "disabled",
						identifier);
			return;
		}

		/*
		 * If there is a tethering firewall for this identifier it will
		 * have the rules set up properly. Just to make sure, update the
		 * used interface info.
		 */
		if (on) {
			ifname = g_strdup(__connman_tethering_get_bridge());

			/* Set interface information for each firewall rule */
			g_list_foreach(ctx->rules,
						setup_firewall_rule_interface,
						ifname);

			DBG("reused tethering firewall for %p %s %s",
						tech, identifier, ifname);
		}
	}

	if (on) {
		err = __connman_firewall_enable(ctx);

		if (err && err != -EALREADY) {
			DBG("cannot enable firewall, tethering disabled: "
						"error %d", err);
			goto disable;
		}
	} else {
		err = __connman_firewall_disable_rule(ctx, FW_ALL_RULES);

		if (err && err != -EALREADY)
			DBG("cannot disable firewall: error %d", err);
	}

	g_free(ifname);

	return;

disable:
	connman_error("tethering firewall error, tethering disabled");

	/* This generates notification */
	connman_technology_tethering_notify(tech, FALSE);
	g_free(ifname);
}

enum iptables_switch_type {
	IPTABLES_UNSET    = 0,
	IPTABLES_SWITCH   = 1,
	IPTABLES_MATCH    = 2,
	IPTABLES_TARGET   = 3,
	IPTABLES_PROTO    = 4,
	IPTABLES_PORT     = 5,
	IPTABLES_OPTION   = 6,
};

#define MAX_IPTABLES_SWITCH 7

static bool is_string_digits(const char *str)
{
	int i;

	if (!str || !*str)
		return false;

	for (i = 0; str[i]; i++) {
		if (!g_ascii_isdigit(str[i]))
			return false;
	}

	return true;
}

static bool is_string_hexadecimal(const char *str)
{
	int i;

	if (!str || !*str)
		return false;

	if (!g_str_has_prefix(str, "0x"))
		return false;

	for (i = 2; str[i]; i++) {
		if (!g_ascii_isxdigit(str[i]))
			return false;
	}

	return true;
}

/* Increase this if any of the rules require more options */
#define IPTABLES_OPTION_COUNT_MAX 2

/*
 * List of supported match option types.
 * - UDP not included as it has no other than port switches
 * - hashlimit match is not supported
 * - dcsp match is not supported
 */
enum iptables_match_options_type {
	IPTABLES_OPTION_PORT = 0,
	IPTABLES_OPTION_MULTIPORT,
	IPTABLES_OPTION_TCP,
	IPTABLES_OPTION_MARK,
	IPTABLES_OPTION_CONNTRACK,
	IPTABLES_OPTION_TTL, // Only with IPv4
	IPTABLES_OPTION_PKTTYPE,
	IPTABLES_OPTION_LIMIT,
	IPTABLES_OPTION_HELPER,
	IPTABLES_OPTION_ECN, // Only with TCP
	IPTABLES_OPTION_AH,
	IPTABLES_OPTION_ESP,
	IPTABLES_OPTION_MH,
	IPTABLES_OPTION_SCTP,
	IPTABLES_OPTION_ICMP,
	IPTABLES_OPTION_ICMPv6,
	IPTABLES_OPTION_DCCP,
	IPTABLES_OPTION_NOT_SUPPORTED
};

static const char *port_options[] = {"--destination-port", "--dport",
					"--source-port", "--sport", NULL};
static const int port_options_count[] = {1, 1, 1, 1, -1};

static const char *multiport_options[] = {"--destination-ports", "--dports",
					"--source-ports", "--sports",
					"--port", "--ports", NULL};
static const int multiport_options_count[] = {1, 1, 1, 1, 1, 1, -1};
/*
 * tcp match options:
 * [!] --tcp-flags mask comp	match when TCP flags & mask == comp
 * 				(Flags: SYN ACK FIN RST URG PSH ALL NONE)
 * [!] --syn	match when only SYN flag set
 * 				(equivalent to --tcp-flags SYN,RST,ACK,FIN SYN)
 * 				match destination port(s)
 * [!] --tcp-option number	match if TCP option set
*/
static const char *tcp_options[] = {"--tcp-flags",
			"--syn",
			"--tcp-option",
			NULL
};
static const int tcp_options_count[] = {2, 0, 1, -1};

/*
 * mark match options:
 * [!] --mark value[/mask]	Match nfmark value with optional mask
*/
static const char *mark_options[] = {"--mark", NULL};
static const int mark_options_count[] = {1, -1};

/*
 * conntrack match options:
 * [!] --ctstate {INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED|SNAT|DNAT}[,...]
 * 				State(s) to match
 * [!] --ctproto proto		Protocol to match; by number or name, e.g. "tcp"
 * [!] --ctorigsrc address[/mask] TODO
 * [!] --ctorigdst address[/mask] TODO
 * [!] --ctreplsrc address[/mask] TODO
 * [!] --ctrepldst address[/mask] TODO
 * 				Original/Reply source/destination address
 * [!] --ctorigsrcport port
 * [!] --ctorigdstport port
 * [!] --ctreplsrcport port
 * [!] --ctrepldstport port
 * 				TCP/UDP/SCTP orig./reply source/destination port
 * [!] --ctstatus {NONE|EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED}[,...]
 * 				Status(es) to match
 * [!] --ctexpire time[:time]	Match remaining lifetime in seconds against
 *				value or range of values (inclusive)
 * --ctdir {ORIGINAL|REPLY}	Flow direction of packet
 */
static const char *conntrack_options[] = {"--ctstate",
			"--ctproto",
			"--ctorigsrc",
			"--ctorigdst",
			"--ctreplsrc",
			"--ctrepldst",
			"--ctorigsrcport",
			"--ctorigdstport",
			"--ctreplsrcport",
			"--ctrepldstport",
			"--ctstatus",
			"--ctexpire",
			"--ctdir",
			NULL
};
static const int conntrack_options_count[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
			1, 1,-1};

/*
 * ttl match options:
 * [!] --ttl-eq value		Match time to live value
 * --ttl-lt value		Match TTL < value
 * --ttl-gt value		Match TTL > value

 */
static const char *ttl_options[] = {"--ttl-eq", "--ttl-lt", "--ttl-gt", NULL};
static const int ttl_options_count[] = {1, 1, 1, -1};

/*
 * pkttype match options:
 * [!] --pkt-type packettype	match packet type
 * 				Valid packet types:
 * 					unicast		to us
 * 					broadcast	to all
 * 					multicast	to group
*/
static const char *pkttype_options[] = {"--pkt-type", NULL};
static const int pkttype_options_count[] = {1, -1};

/*
 * limit match options:
 * --limit avg			max average match rate: default 3/hour
 * 				[Packets per second unless followed by
 * 				/sec /minute /hour /day postfixes]
 * --limit-burst number		number to match in a burst, default 5
 */
static const char *limit_options[] = {"--limit", "--limit-burst", NULL};
static const int limit_options_count[] = {1, 1, -1};

/*
 * helper match options:
 * [!] --helper string		Match helper identified by string
 */
static const char *helper_options[] = {"--helper", NULL};
static const int helper_options_count[] = {1, -1};

/*
 * ECN match options
 * [!] --ecn-tcp-cwr 		Match CWR bit of TCP header
 * [!] --ecn-tcp-ece		Match ECE bit of TCP header
 * [!] --ecn-ip-ect [0..3]	Match ECN codepoint in IPv4/IPv6 header
 */
static const char *ecn_options[] = {"--ecn-tcp-cwr",
			"--ecn-tcp-ece",
			"--ecn-ip-ect",
			NULL
};
static const int ecn_options_count[] = {0, 0, 1, -1};

/*
 * ah match options:
 * [!] --ahspi spi[:spi]	match spi (range)
 *
 * TODO AH IPv6 option support:
 * [!] --ahspi spi[:spi]	match spi (range)
 * [!] --ahlen length		total length of this header
 * --ahres			check the reserved field too
 */
static const char *ah_options[] = {"--ahspi", NULL};
static const int ah_options_count[] = {1, -1};

/*
 * esp match options:
 * [!] --espspi spi[:spi]	match spi (range)
 */
static const char *esp_options[] = {"--espspi", NULL};
static const int esp_options_count[] = {1, -1};

/*
 * mh match options:
 * [!] --mh-type type[:type]	match mh type
 * 				Valid MH types:
 * 					binding-refresh-request (brr)
 * 					home-test-init (hoti)
 * 					careof-test-init (coti)
 * 					home-test (hot)
 * 					careof-test (cot)
 * 					binding-update (bu)
 * 					binding-acknowledgement (ba)
 * 					binding-error (be)
 */
static const char *mh_options[] = {"--mh-type", NULL};
static const int mh_options_count[] = {1, -1};

/*
 * sctp match options
 * [!] --chunk-types (all|any|none) (chunktype[:flags])+
 * 				match if all, any or none of chunktypes are
 * 				present
 */

static const char *sctp_options[] = {"--chunk-types", NULL};
static const int sctp_options_count[] = {2, -1};

/*
 * icmp match options:
 * [!] --icmp-type typename	match icmp type
 * [!] --icmp-type type[/code]	(or numeric type or type/code)
 */
static const char *icmp_options[] = {"--icmp-type", NULL};
static const int icmp_options_count[] = {1, -1};

/*
 * icmpv6 match options:
 * [!] --icmpv6-type typename	match icmpv6 type
 * 				(or numeric type or type/code)
 */

static const char *icmpv6_options[] = {"--icmpv6-type", NULL};
static const int icmpv6_options_count[] = {1, -1};

/*
 * dccp match options
 * [!] --dccp-types type[,...]	match when packet is one of the given types
 * [!] --dccp-option option	match if option (by number!) is set
 */

static const char *dccp_options[] = {"--dccp-types", "--dccp-option", NULL};
static const int dccp_options_count[] = {1, 1, -1};

struct iptables_type_options {
	enum iptables_match_options_type type;
	const char **options;
	const int *option_count;
};

/*
 * Allocate new wrapper for iptables_type_options to insert into hash table.
 * Can be free'd with g_free().
 */
static struct iptables_type_options *iptables_type_options_new(
			const struct iptables_type_options *option)
{
	struct iptables_type_options *type_options;

	type_options = g_try_new0(struct iptables_type_options, 1);

	if (!type_options)
		return NULL;

	type_options->type = option->type;
	type_options->options = option->options;
	type_options->option_count = option->option_count;

	return type_options;
}

static const struct iptables_type_options iptables_opts[] = {
	{IPTABLES_OPTION_PORT, port_options, port_options_count},
	{IPTABLES_OPTION_MULTIPORT, multiport_options, multiport_options_count},
	{IPTABLES_OPTION_TCP, tcp_options, tcp_options_count},
	{IPTABLES_OPTION_MARK, mark_options, mark_options_count},
	{IPTABLES_OPTION_CONNTRACK, conntrack_options, conntrack_options_count},
	{IPTABLES_OPTION_TTL, ttl_options, ttl_options_count},
	{IPTABLES_OPTION_PKTTYPE, pkttype_options, pkttype_options_count},
	{IPTABLES_OPTION_LIMIT, limit_options, limit_options_count},
	{IPTABLES_OPTION_HELPER, helper_options, helper_options_count},
	{IPTABLES_OPTION_ECN, ecn_options, ecn_options_count},
	{IPTABLES_OPTION_AH, ah_options, ah_options_count},
	{IPTABLES_OPTION_ESP, esp_options, esp_options_count},
	{IPTABLES_OPTION_MH, mh_options, mh_options_count},
	{IPTABLES_OPTION_SCTP, sctp_options, sctp_options_count},
	{IPTABLES_OPTION_ICMP, icmp_options, icmp_options_count},
	{IPTABLES_OPTION_ICMPv6, icmpv6_options, icmpv6_options_count},
	{IPTABLES_OPTION_DCCP, dccp_options, dccp_options_count},
};

static GHashTable *iptables_options = NULL;

static void initialize_iptables_options()
{
	enum iptables_match_options_type type;
	struct iptables_type_options *type_options;
	const char *opt_names[] = {"port", "multiport", "tcp", "mark",
				"conntrack", "ttl", "pkttype", "limit",
				"helper", "ecn", "ah", "esp", "mh", "sctp",
				"icmp", "ipv6-icmp", "dccp", NULL};

	if (!iptables_options)
		return;

	for (type = IPTABLES_OPTION_PORT; type < IPTABLES_OPTION_NOT_SUPPORTED;
				type++) {
		type_options = iptables_type_options_new(&iptables_opts[type]);

		if (!type_options)
			continue;

		g_hash_table_insert(iptables_options, g_strdup(opt_names[type]),
				type_options);
	}
}

static enum iptables_match_options_type validate_option_type(
			const char *protocol, const char *match,
			const char *option, int *count, int *position,
			bool multiport)
{
	struct iptables_type_options *type_options;
	struct protoent *p;
	enum iptables_match_options_type return_type =
				IPTABLES_OPTION_NOT_SUPPORTED;
	GSList *keys = NULL, *iter;
	const char *key = NULL;
	int proto_int;
	int i;

	DBG("");

	if (match) {
		/* Only port options for udp/udplite */
		if (!g_strcmp0(match, "udp") || !g_strcmp0(match, "udplite"))
			keys = g_slist_prepend(keys, "port");
		/* Use official name of for icmpv6 */
		else if (!g_strcmp0(match, "icmpv6"))
			keys = g_slist_prepend(keys, "ipv6-icmp");
		/*
		 * Otherwise add the match as search key, cast to char* to avoid
		 * compiler warning.
		 */
		else
			keys = g_slist_prepend(keys, (char*)match);

		/* Search for match and port for multiport and TCP.*/
		if (multiport || !g_strcmp0(match, "tcp"))
			keys = g_slist_prepend(keys, "port");
	} else if (protocol) { /* If only protocol is given (sctp|dccp) */
		if (is_string_digits(protocol)) {
			proto_int = (int)g_ascii_strtoll(protocol, NULL, 10);

			p = getprotobynumber(proto_int);
		} else {
			p = getprotobyname(protocol);
		}

		if (!p)
			return IPTABLES_OPTION_NOT_SUPPORTED;

		/* SCTP options do not work, search with port option */
		if (!g_ascii_strcasecmp(p->p_name, "sctp")) {
			keys = g_slist_prepend(keys, "port");
		/* DCCP can have both port and protocol options */
		} else if (!g_ascii_strcasecmp(p->p_name, "dccp")) {
			keys = g_slist_prepend(keys, p->p_name);
			keys = g_slist_prepend(keys, "port");
		}
	} else {
		return IPTABLES_OPTION_NOT_SUPPORTED;
	}

	DBG("search protocol %s match %s ", protocol, match);

	for (iter = keys; iter; iter = iter->next) {
		key = iter->data;

		DBG("search key %s", key);
		type_options = g_hash_table_lookup(iptables_options, key);

		if (!type_options)
			continue;

		for (i = 0; type_options->options[i]; i++) {
			if (!g_strcmp0(type_options->options[i], option)) {
				DBG("found match for option %s type %d "
					"position %d parameter count %d",
					option, type_options->type, i,
					type_options->option_count[i]);

				*count = type_options->option_count[i];
				*position = i;

				/*
				 * In case a port option was used with multiport
				 * return multiport type since port options work
				 * with multiport as well.
				 */
				if (type_options->type ==
					IPTABLES_OPTION_PORT && multiport)
					return_type = IPTABLES_OPTION_MULTIPORT;
				else
					return_type = type_options->type;

				break;
			}
		}

		/* Match was found */
		if (return_type != IPTABLES_OPTION_NOT_SUPPORTED)
			break;
	}

	g_slist_free(keys);

	return return_type;
}

/*
 * This check has to be done because two same direction port options causes
 * iptables to report invalid parameters which in turn results in exit().
 */
static bool is_port_option_same_group(const char *str1, const char *str2,
			bool multiport)
{
	const char *dst_multiport[] = {"--destination-ports", "--dports", NULL};
	const char *src_multiport[] = {"--source-ports", "--sports", NULL};
	const char *gen_multiport[] = {"--port", "--ports", NULL};
	const char *dst_port[] = {"--destination-port", "--dport", NULL};
	const char *src_port[] = {"--source-port", "--sport", NULL};
	int i;
	int direction1 = -1, direction2 = -1;

	if (!g_strcmp0(str1, str2))
		return true;

	if (multiport) {
		/*
		 * If either of the port options is --port or --ports there can
		 * be no other port option set.
		 */
		for (i = 0; gen_multiport[i]; i++) {
			if (!g_strcmp0(gen_multiport[i], str1))
				return true;
			if (!g_strcmp0(gen_multiport[i], str2))
				return true;
		}

		for (i = 0; dst_multiport[i]; i++) {
			if (!g_strcmp0(dst_multiport[i], str1))
				direction1 = 0;
			if (!g_strcmp0(dst_multiport[i], str2))
				direction2 = 0;
		}

		for (i = 0; src_multiport[i]; i++) {
			if (!g_strcmp0(src_multiport[i], str1))
				direction1 = 1;
			if (!g_strcmp0(src_multiport[i], str2))
				direction2 = 1;
		}
	}

	for (i = 0; dst_port[i]; i++) {
		if (!g_strcmp0(dst_port[i], str1))
			direction1 = 0;
		if (!g_strcmp0(dst_port[i], str2))
			direction2 = 0;
	}

	for (i = 0; src_port[i]; i++) {
		if (!g_strcmp0(src_port[i], str1))
			direction1 = 1;
		if (!g_strcmp0(src_port[i], str2))
			direction2 = 1;
	}

	return direction1 == direction2;
}

static bool is_port_option(const char *str, bool multiport)
{
	if (!str || !*str)
		return true;

	if (multiport) {
		if (g_strv_contains(multiport_options, str))
			return true;
	}

	/* Normal port switches can be used also with -m multiport */
	if (g_strv_contains(port_options, str))
		return true;

	return false;
}

static bool validate_ports_or_services(const char *str)
{
	gchar **tokens;
	 /* In iptables ports are separated with commas, ranges with colon. */
	const char delimiters[] = ",:";
	struct servent *s;
	bool ret = true;
	int portnum;
	int i;

	if (!str || !*str)
		return false;

	tokens = g_strsplit_set(str, delimiters, 0);

	if (!tokens)
		return false;

	for (i = 0; tokens[i]; i++) {

		/* Plain digits, check if port is valid */
		if (is_string_digits(tokens[i])) {
			portnum = (int) g_ascii_strtoll(tokens[i], NULL, 10);

			/* Valid port number */
			if (portnum && portnum <= G_MAXUINT16)
				continue;
		}

		/* Check if service name is valid with any protocol */
		s = getservbyname(tokens[i], NULL);

		if (s)
			continue;

		/* If one of the ports/services is invalid, rule is invalid */
		ret = false;
		DBG("invalid port/service %s in %s", tokens[i], str);
		break;
	}

	g_strfreev(tokens);

	return ret;
}

static bool is_icmp_int_type_valid(const char *icmp_type)
{
	int icmp_num;

	icmp_num = (int) g_ascii_strtoll(icmp_type, NULL, 10);

	/* Anything from 0...255 is "valid" even though not correct.*/
	if (icmp_num >= 0 && icmp_num <= UINT8_MAX)
		return true;

	return false;
}

/*
 * To clarify this function a bit, since it is so large, each different match
 * option that is supported and its values are validated here.
 *
 * type: match type of the option 
 * params: parameters given for the option, 2 params max.
 * option_position: this defines the actual option used, it tells the position
 * 		of the supported option within the options array of the match
 * 		defined by the type.
 * multiport: is this a multiport match (special port option case)
 */
static bool is_valid_option_type_params(enum iptables_match_options_type type,
			const char **params, const int option_position,
			bool multiport)
{
	const char *valid_tcp_flags[] = {"SYN", "ACK", "FIN", "RST", "URG",
				"PSH", "ALL", "NONE", NULL};
	const char *valid_limit_postfixes[] = { "sec", "minute", "hour", "day",
				NULL};
	const char *valid_pkttypes[] = {"unicast", "broadcast", "multicast",
				NULL};
	const char *valid_conntrack_states[] = {"INVALID", "ESTABLISHED", "NEW",
				"RELATED", "UNTRACKED", "SNAT", "DNAT", NULL};
	const char *valid_conntrack_status[] = {"NONE", "EXPECTED",
				"SEEN_REPLY", "ASSURED", "CONFIRMED", NULL};
	const char *valid_conntrack_flows[] = {"ORIGINAL", "REPLY", NULL};
	const char *valid_dccp_types[] = {"REQUEST", "RESPONSE", "DATA", "ACK",
				"DATAACK", "CLOSEREQ","CLOSE", "RESET", "SYNC",
				"SYNCACK", "INVALID", NULL};
	/* List provided by iptables -p icmp --help */
	const char *icmp_types_ipv4[] = {"any",
				"echo-reply",
				"destination-unreachable",
				"network-unreachable",
				"host-unreachable",
				"protocol-unreachable",
				"port-unreachable",
				"fragmentation-needed",
				"source-route-failed",
				"network-unknown",
				"host-unknown",
				"network-prohibited",
				"host-prohibited",
				"TOS-network-unreachable",
				"TOS-host-unreachable",
				"communication-prohibited",
				"host-precedence-violation",
				"precedence-cutoff",
				"source-quench",
				"redirect",
				"network-redirect",
				"host-redirect",
				"TOS-network-redirect",
				"TOS-host-redirect",
				"echo-request",
				"router-advertisement",
				"router-solicitation",
				"time-exceeded",
				"ttl-zero-during-transit",
				"ttl-zero-during-reassembly",
				"parameter-problem",
				"ip-header-bad",
				"required-option-missing",
				"timestamp-request",
				"timestamp-reply",
				"address-mask-request",
				"address-mask-reply",
				NULL
	};

	/* List provided by ip6tables -p icmpv6 --help */
	const char *icmp_types_ipv6[] = {"destination-unreachable",
				"no-route",
				"communication-prohibited",
				"beyond-scope",
				"address-unreachable",
				"port-unreachable",
				"failed-policy",
				"reject-route",
				"packet-too-big",
				"time-exceeded",
				"ttl-exceeded",
				"ttl-zero-during-transit",
				"ttl-zero-during-reassembly",
				"parameter-problem",
				"bad-header",
				"unknown-header-type",
				"unknown-option",
				"echo-request",
				"echo-reply",
				"router-solicitation",
				"router-advertisement",
				"neighbour-solicitation",
				"neighbor-solicitation",
				"neighbour-advertisement",
				"neighbor-advertisement",
				"redirect",
				NULL
	};
	const char **icmp_types = NULL;
	char **tokens = NULL;
	bool value1 = false;
	bool value2 = false;
	int token_count = 0;
	int i;

	switch (type) {
	/* Both AH and ESP have the same index value with optional range ':' */
	case IPTABLES_OPTION_AH:
	case IPTABLES_OPTION_ESP:
		if (!params[0])
			return false;

		tokens = g_strsplit(params[0], ":", 2);

		if (!tokens)
			return false;

		token_count = g_strv_length(tokens);

		if (token_count == 2) {
			value1 = is_string_digits(tokens[0]);
			value2 = is_string_digits(tokens[1]);
		} else if (token_count == 1) {
			value1 = is_string_digits(tokens[0]);
		}

		break;
	case IPTABLES_OPTION_CONNTRACK:
		/* --ctstate */
		if (option_position == 0) {
			if (!params[0])
				return false;

			tokens = g_strsplit(params[0], ",", -1);

			if (!tokens)
				return false;

			token_count = g_strv_length(tokens);

			for (i = 0; i < token_count; i++) {
				if (!(value1 = g_strv_contains(
							valid_conntrack_states,
							tokens[i])))
					break;
			}

			token_count = 1; /* Check value1 */
		}

		/* --ctproto, protocol must be valid */
		if (option_position == 1) {
			struct protoent *p;
			if (!params[0])
				return false;

			if (!g_strcmp0(params[0], "all"))
				return true;

			/* If protocol is integer */
			if (is_string_digits(params[0])) {
				int protonum = (int) g_ascii_strtoll(params[0],
							NULL, 10);
				p = getprotobynumber(protonum);
			} else {
				p = getprotobyname(params[0]);
			}

			if (p)
				return true;
		}

		/*
		 * TODO: --ctorigsrc, --ctorigdst, --ctreplsrc and --ctrepldst
		 * are ignored as are other address options. Each have
		 * address/mask as values. Add support when other address
		 * options are enabled.
		 */
		if (option_position >= 2 && option_position <= 5) {
			return false;
		}

		/*
		 * --ctorigsrcport, --ctorigdstport, --ctreplsrcport and
		 * --ctrepldstport support one port parameter value.
		 */
		if (option_position >= 6 && option_position <= 9)
			return validate_ports_or_services(params[0]);

		/* --ctstatus, values must be comma separated */
		if (option_position == 10) {
			if (!params[0])
				return false;

			tokens = g_strsplit(params[0], ",", -1);

			if (!tokens)
				return false;

			token_count = g_strv_length(tokens);

			for (i = 0; i < token_count; i++) {
				if (!(value1 = g_strv_contains(
							valid_conntrack_status,
							tokens[i])))
					break;
			}

			token_count = 1; /* Check value1 */
		}

		/* --ctexpire */
		if (option_position == 11) {
			if (!params[0])
				return false;

			tokens = g_strsplit(params[0], ":", 2);

			if (!tokens)
				return false;

			token_count = g_strv_length(tokens);

			if (token_count == 2) {
				value1 = is_string_digits(tokens[0]);
				value2 = is_string_digits(tokens[1]);
			} else if (token_count == 1) {
				value1 = is_string_digits(tokens[0]);
			}
		}

		/* --ctdir */
		if (option_position == 12) {
			if (!params[0])
				return false;

			return g_strv_contains(valid_conntrack_flows,
						params[0]);
		}

		break;
	case IPTABLES_OPTION_ECN:
		/* --ecn-ip-ect */
		if (option_position == 2) {
			/* ECN codepoint in IPv4/IPv6 header must be 0...3.*/
			if (is_string_digits(params[0])) {
				int str_digit = (int)g_ascii_strtoll(params[0],
							NULL, 10);

				if (str_digit >= 0 && str_digit <= 3)
					return true;
			}
			return false;
		}
		/* --ecn-tcp-cwr or --ecn-tcp-ece have no parameters */
		return true;
	case IPTABLES_OPTION_DCCP:
		if (!params[0])
			return false;

		/* --dccp-types */
		if (option_position == 0) {
			tokens = g_strsplit(params[0], ",", -1);

			if (!tokens)
				return false;

			token_count = g_strv_length(tokens);

			for (i = 0; i < token_count; i++) {
				if (!(value1 = g_strv_contains(valid_dccp_types,
							tokens[i])))
					break;
			}

			token_count = 1; // Check only value1
			break;
		}

		/* --dccp-option */
		if (option_position == 1)
			return is_string_digits(params[0]);

		return false;
	case IPTABLES_OPTION_ICMPv6:
		icmp_types = icmp_types_ipv6;
	/* Fallthrough */
	case IPTABLES_OPTION_ICMP:
		if (!params[0])
			return false;

		/* If this is not fallthrough from ICMPv6 */
		if (!icmp_types)
			icmp_types = icmp_types_ipv4;

		/* Single ICMP type as digit */
		if (is_string_digits(params[0]) &&
					is_icmp_int_type_valid(params[0]))
			return true;

		/* ICMP type as type/code */
		tokens = g_strsplit(params[0], "/", 2);

		if (!tokens)
			return false;

		token_count = g_strv_length(tokens);

		if (token_count == 2) {
			value1 = is_string_digits(tokens[0]) &&
					is_icmp_int_type_valid(tokens[0]);
			value2 = is_string_digits(tokens[1]) &&
					is_icmp_int_type_valid(tokens[1]);
			break; // Out from switch()
		}

		g_strfreev(tokens);

		/* ICMP type as charstring */
		return g_strv_contains(icmp_types, params[0]);
	case IPTABLES_OPTION_HELPER:
		/* Iptables does not care what helper text is, can be empty. */
		return true;
	case IPTABLES_OPTION_LIMIT:
		/* --limit can have single digit or digit/postfix */
		if (option_position == 0) {
			if (!params[0])
				return false;

			tokens = g_strsplit(params[0], "/", 2);

			if (!tokens)
				return false;

			token_count = g_strv_length(tokens);

			if (token_count == 2) {
				value1 = is_string_digits(tokens[0]);
				value2 = g_strv_contains(valid_limit_postfixes,
							tokens[1]);
			} else if (token_count == 1) {
				value1 = is_string_digits(tokens[0]);
			}
		}

		/* --limit-burst can have a single digit parameter */
		if (option_position == 1)
			return is_string_digits(params[0]);

		break;
	case IPTABLES_OPTION_MARK:
		if (!params[0])
			return false;

		tokens = g_strsplit(params[0], "/", 2);

		if (!tokens)
			return false;

		token_count = g_strv_length(tokens);

		/* --mark supports hexacedimals as well, value/mask syntax */
		if (token_count == 2) {
			value1 = is_string_digits(tokens[0]);

			if (!value1)
				value1 = is_string_hexadecimal(tokens[0]);

			value2 = is_string_digits(tokens[1]);

			if (!value2)
				value2 = is_string_hexadecimal(tokens[1]);
		} else if (token_count == 1) {
			value1 = is_string_digits(tokens[0]);

			if (!value1)
				value1 = is_string_hexadecimal(tokens[0]);
		}

		break;
	/*
	 * TODO: MH protocol support is not working, protocol specific options
	 * are not added properly to iptables. For this reason, the MH options
	 * are disabled as the option is omitted from the added rule, which is
	 * impossible to remove using the added rule containing these options.
	 */
	case IPTABLES_OPTION_MH:
		return false;
	case IPTABLES_OPTION_MULTIPORT:
	case IPTABLES_OPTION_PORT:
		return validate_ports_or_services(params[0]);
		break;
	case IPTABLES_OPTION_PKTTYPE:
		if (!params[0])
			return false;

		return g_strv_contains(valid_pkttypes, params[0]);
	/*
	 * TODO: SCTP protocol support is not working, protocol specific options
	 * are not added properly to iptables. For this reason, the SCTP options
	 * are disabled as the option is omitted from the added rule, which is
	 * impossible to remove using the added rule containing these options.
	 */
	case IPTABLES_OPTION_SCTP:
		return false;
	case IPTABLES_OPTION_TCP:
		/* --tcp-flags */
		if (option_position == 0) {
			/* Two must be set */
			if (!params[0] || !params[1])
				return false;

			tokens = g_strsplit(params[0], ",", 8);

			if (!tokens)
				return false;

			token_count = g_strv_length(tokens);
			
			for (i = 0; i < token_count; i++) {
				if (!(value1 = g_strv_contains(valid_tcp_flags,
							tokens[i])))
					break;
			}

			if (!value1)
				break;

			g_strfreev(tokens);

			tokens = g_strsplit(params[1], ",", 8);

			if (!tokens)
				return false;

			token_count = g_strv_length(tokens);

			for (i = 0; i < token_count; i++) {
				if (!(value2 = g_strv_contains(valid_tcp_flags,
							tokens[i])))
					break;
			}

			token_count = 2; /* Check both boolean values */
		}

		/* --syn has no parameters */
		if (option_position == 1)
			return true;

		/* --tcp-option */
		if (option_position == 2) {
			/* Must be int */
			return is_string_digits(params[0]);
		}

		break;
	case IPTABLES_OPTION_TTL:
		/* Each option requires a single value */
		return is_string_digits(params[0]);
	case IPTABLES_OPTION_NOT_SUPPORTED:
		break;
	}

	g_strfreev(tokens);

	switch (token_count) {
	case 1:
		return value1;
	case 2:
		return value1 && value2;
	default:
		return false;
	}
}

static bool is_protocol_str_match(const char *protocol_str_int,
			const char *protocol)
{
	struct protoent *p;
	int proto_int;

	if (!protocol || !protocol_str_int)
		return false;

	proto_int = (int)g_ascii_strtoll(protocol_str_int, NULL, 10);
	p = getprotobyname(protocol);

	return p && p->p_proto == proto_int;
}

static bool is_valid_option_for_protocol_match(const char* protocol,
			const char* match,
			enum iptables_match_options_type type)
{
	struct protoent *p;
	const char *port_protocols[] = {"tcp", "udp", "udplite", "sctp", "dccp",
				NULL};
	const char *icmp_ipv6[] = { "icmpv6", "ipv6-icmp", NULL };
	bool protocol_found = false;
	bool match_found = false;
	int proto_int = 0;
	int i;

	switch (type) {
	case IPTABLES_OPTION_AH:
		if (is_string_digits(protocol))
			protocol_found = is_protocol_str_match(protocol, "ah");
		else
			protocol_found = !g_ascii_strcasecmp(protocol, "ah");

		return protocol_found && !g_strcmp0(match, "ah");
	case IPTABLES_OPTION_ESP:
		if (is_string_digits(protocol))
			protocol_found = is_protocol_str_match(protocol, "esp");
		else
			protocol_found = !g_ascii_strcasecmp(protocol, "esp");

		return protocol_found && !g_strcmp0(match, "esp");
	case IPTABLES_OPTION_CONNTRACK:
		return !g_strcmp0(match, "conntrack");
	case IPTABLES_OPTION_DCCP:
		if (!g_strcmp0(match, "dccp")) /* Match cannot be dccp */
			return false;

		if (is_string_digits(protocol))
			return is_protocol_str_match(protocol, "dccp");

		return !g_ascii_strcasecmp(protocol, "dccp");
	case IPTABLES_OPTION_ECN:
		if (g_strcmp0(match, "ecn"))
			return false;

		match_found = true;
	/* Fallthrough, ECN match needs TCP protocol */
	case IPTABLES_OPTION_TCP:
		if (is_string_digits(protocol)) {
			if (is_protocol_str_match(protocol, "tcp"))
				protocol_found = true;
			else
				return false;
		} else {
			if (!g_ascii_strcasecmp(protocol, "tcp"))
				protocol_found = true;
			else
				return false;
		}

		if (!match_found && !g_strcmp0(match, "tcp"))
			match_found = true;

		return protocol_found && match_found;
	case IPTABLES_OPTION_HELPER:
		return !g_strcmp0(match, "helper");
	case IPTABLES_OPTION_ICMP:
		return !g_strcmp0(match, "icmp");
	case IPTABLES_OPTION_ICMPv6:
		return g_strv_contains(icmp_ipv6, match);
	case IPTABLES_OPTION_LIMIT:
		return !g_strcmp0(match, "limit");
	case IPTABLES_OPTION_MARK:
		return !g_strcmp0(match, "mark");
	case IPTABLES_OPTION_MH:
		return false; /* MH options not supported */
	case IPTABLES_OPTION_MULTIPORT:
		/* Match must be -m multiport for multiport options */
		if (g_strcmp0(match, "multiport"))
			return false;

		match_found = true;
	/* Fallthrough */
	case IPTABLES_OPTION_PORT:
		/*
		 * -p sctp -m sctp is not supported and -m sctp is ignored in
		 * earlier checks so it is safe to set match as found if the
		 * protocol is SCTP. Same with protocol DCCP.
		 */
		if (!g_ascii_strcasecmp(protocol, "sctp") ||
					!g_ascii_strcasecmp(protocol, "dccp"))
			match_found = true;

		if (is_string_digits(protocol))
			proto_int = (int)g_ascii_strtoll(protocol, NULL, 10);

		/*
		 * Port switches do not work with iptables.c if they do not have
		 * both match and port set */
		for (i = 0; port_protocols[i]; i++) {
			if (!protocol_found) {
				if (proto_int) {
					p = getprotobyname(port_protocols[i]);

					if (p && p->p_proto == proto_int)
						protocol_found = true;

					/*
					 * Set match to found if SCTP is the
					 * protocol defined with integer.
					 */
					if (p && (!g_strcmp0(port_protocols[i],
							"sctp") ||
						!g_strcmp0(port_protocols[i],
							"dccp")))
						match_found = true;
				} else if (!g_ascii_strcasecmp(
							port_protocols[i],
							protocol)) {
					protocol_found = true;
				}
			}

			if (!match_found &&
					!g_strcmp0(port_protocols[i], match))
					match_found = true;
		}

		return protocol_found && match_found;
	case IPTABLES_OPTION_PKTTYPE:
		return !g_strcmp0(match, "pkttype");
	case IPTABLES_OPTION_SCTP:
		return false; /* SCTP options not supported */
	case IPTABLES_OPTION_TTL:
		return !g_strcmp0(match, "ttl");
	case IPTABLES_OPTION_NOT_SUPPORTED:
		return false;
	}

	return false;
}

static bool is_supported(int type, enum iptables_switch_type switch_type,
					const char* group, const char *str)
{
	/*
	 * The switches and matches that are not supported.
	 *
	 * Chain manipulation is not supported, the rules are going to specific
	 * managed chains within connman.
	 *
	 * Setting specific addresses is not supported because the purpose of
	 * these rules is to set the base line of prevention to be used on both
	 * IPv4 and IPv6. In the future rules may be separated to have own for
	 * both of the IP protocols.
	.*
	 * Setting specific interfaces is not supported for dynamic rules, these
	 * are added dynamically into the rules when interface comes up. For
	 * General rules setting interfaces is allowed.
	 */
	const char *not_supported_switches[] = { "--source", "--src","-s",
						"--destination", "--dst", "-d",
						"--append", "-A",
						"--delete", "-D",
						"--delete-chain", "-X",
						"--flush", "-F",
						"--insert", "-I",
						"--new-chain", "-N",
						"--policy", "-P",
						"--rename-chain", "-E",
						"--replace", "-R",
						"--zero", "-Z",
						"--to-destination",
						"--from-destination",
						"--ipv4", "-4",
						"--ipv6", "-6",
						"-f", "--fragment",
						NULL
	};
	const char *not_supported_dynamic_switches[] = { "--in-interface", "-i",
						"--out-interface", "-o",
						NULL
	};

	const char *not_supported_matches_ipv4[] = { "comment",
						"state",
						"iprange",
						"recent",
						"owner",
						"sctp",
						"mh",
						"hashlimit",
						"frag",
						"icmpv6",
						"ipv6-icmp",
						NULL
	};
	const char *not_supported_matches_ipv6[] = { "comment",
						"state",
						"iprange",
						"recent",
						"owner",
						"ttl",
						"sctp",
						"mh",
						"hashlimit",
						"frag",
						"icmp",
						NULL
	};

	const char **not_supported_matches = NULL;

	/* Protocols that iptables supports with -p or --protocol switch */
	const char *supported_protocols_ipv4[] = { "tcp",
						"udp",
						"udplite",
						"icmp",
						"esp",
						"ah",
						"sctp",
						"dccp",
						"all",
						NULL
	};

	/* Protocols that iptables supports with -p or --protocol switch */
	const char *supported_protocols_ipv6[] = { "tcp",
						"udp",
						"udplite",
						"icmpv6",
						"ipv6-icmp",
						"esp",
						"ah",
						"sctp",
						"mh",
						"dccp",
						"all",
						NULL
	};

	const char **supported_protocols = NULL;

	/*
	 * Targets that are supported. No targets to custom chains are
	 * allowed
	 */
	const char *supported_targets[] = { "ACCEPT",
						"DROP",
						"REJECT",
						"LOG",
						"QUEUE",
						NULL
	};

	struct protoent *p = NULL;
	bool is_general = false;
	int protonum = 0;
	int i = 0;

	/* Do not care about empty or nonexistent content */
	if (!str || !*str)
		return true;

	if (group && !g_strcmp0(group, GROUP_GENERAL))
		is_general = true;

	switch (type) {
	case AF_INET:
		not_supported_matches = not_supported_matches_ipv4;
		supported_protocols = supported_protocols_ipv4;
		break;
	case AF_INET6:
		not_supported_matches = not_supported_matches_ipv6;
		supported_protocols = supported_protocols_ipv6;
		break;
	default:
		return false;
	}

	switch (switch_type) {
	case IPTABLES_SWITCH:
		if (g_strv_contains(not_supported_switches, str))
			return false;

		/* If the rule is not in Group general */
		if (!is_general)
			return !g_strv_contains(not_supported_dynamic_switches,
						str);

		return true;
	case IPTABLES_MATCH:
		return !g_strv_contains(not_supported_matches, str);
	case IPTABLES_TARGET:
		return g_strv_contains(supported_targets, str);
	case IPTABLES_PROTO:
		if (is_string_digits(str))
			protonum = (int) g_ascii_strtoll(str, NULL, 10);

		for (i = 0; supported_protocols[i]; i++) {
			/* Protocols can be also capitalized */
			if (!g_ascii_strcasecmp(str, supported_protocols[i]))
				return true;

			/* Protocols can be defined by their number. */
			if (protonum) {
				p = getprotobyname(supported_protocols[i]);
				if (p && protonum == p->p_proto)
					return true;
			}
		}

		return false;
	case IPTABLES_PORT:
		return validate_ports_or_services(str);
	case IPTABLES_OPTION: /* Fallthrough, options are checked elsewhere */
	default:
		return true;
	}
}

enum icmp_check_result {
			NOT_ICMP = 0,
			VALID_ICMP,
			INVALID_ICMP,
};

static enum icmp_check_result is_icmp_proto_or_match(int type,
			const char *proto_or_match)
{
	const char *icmp_ipv4[] = { "icmp", NULL };
	const char *icmp_ipv6[] = { "icmpv6", "ipv6-icmp", NULL };

	if (!proto_or_match || !*proto_or_match)
		return NOT_ICMP;

	switch (type) {
	case AF_INET:
		if (g_strv_contains(icmp_ipv4, proto_or_match))
			return VALID_ICMP;

		/* IPv4 cannot use IPv6 ICMP types */
		if (g_strv_contains(icmp_ipv6, proto_or_match))
			return INVALID_ICMP;
		break;
	case AF_INET6:
		if (g_strv_contains(icmp_ipv6, proto_or_match))
			return VALID_ICMP;

		/* IPv4 cannot use IPv6 ICMP types */
		if (g_strv_contains(icmp_ipv4, proto_or_match))
			return INVALID_ICMP;
	}

	return NOT_ICMP;
}

static bool protocol_match_equals(int type, const char *protocol,
			const char *match)
{
	struct protoent *p = NULL;
	int protonum;
	int i;

	if (!protocol || !match)
		return false;

	/* Matches cannot be integers, matches are case sensitive */
	if (is_string_digits(match))
		return false;

	/* Protocols are not case sensitive */
	if (!g_ascii_strcasecmp(protocol, match))
		return true;

	/*
	 * ICMP matches are a special case, if protocol is ICMP match must be
	 * also valid ICMP for the type. Protocol "icmpv6" is not found with
	 * getprotobyname() but is understood by iptables.
	*/
	switch (is_icmp_proto_or_match(type, protocol)) {
	case NOT_ICMP:
		break; // Is not ICMP protocol
	case VALID_ICMP:
		return is_icmp_proto_or_match(type, match);
	case INVALID_ICMP:
		return false;
	}

	/* If protocol is integer */
	if (is_string_digits(protocol)) {
		protonum = (int) g_ascii_strtoll(protocol, NULL, 10);

		if (!protonum && g_strcmp0(protocol, "0"))
			return false;

		p = getprotobynumber(protonum);
	} else {
		p = getprotobyname(protocol);
	}

	if (!p)
		return false;

	/* Protocol official name equals */
	if (!g_ascii_strcasecmp(p->p_name, match))
		return true;

	/* If ICMP protocol was defined as integer */
	switch (is_icmp_proto_or_match(type, p->p_name)) {
	case NOT_ICMP:
		break; // Is not ICMP protocol
	case VALID_ICMP:
		return is_icmp_proto_or_match(type, match);
	case INVALID_ICMP:
		return false;
	}

	/* Check if it is one of the aliases */
	for (i = 0; p->p_aliases && p->p_aliases[i]; i++) {
		/* Protocols can be also capitalized */
		if (!g_ascii_strcasecmp(p->p_aliases[i], match))
			return true;
	}

	return false;
}

static bool validate_iptables_rule(int type, const char *group,
							const char *rule_spec)
{
	gchar **argv = NULL;
	GError *error = NULL;
	bool ret = false;
	int i = 0;
	int argc = 0;
	int protocol_index = 0;
	int match_index = 0;
	int port_option_index = 0;
	bool multiport_used = false;
	unsigned int switch_types_found[MAX_IPTABLES_SWITCH] = { 0 };
	enum iptables_switch_type switch_type = IPTABLES_UNSET;
	const char *opt = NULL;
	const char valid_prefix = '-';

	if (!g_shell_parse_argv(rule_spec, &argc, &argv, &error)) {
		DBG("failed in parsing %s", error ? error->message : "");
		goto out;
	}

	/* -j TARGET is the bare minimum of a rule */
	if (argc < 2 || !argv[0][0]) {
		DBG("parsed content is invalid");
		goto out;
	}

	/* Only '-' prefixed rules are allowed in iptables. */
	if (argv[0][0] != valid_prefix) {
		DBG("invalid rule prefix");
		goto out;
	}

	for (i = 0; i < argc; ) {
		const char *arg = argv[i++];

		if (!is_supported(type, IPTABLES_SWITCH, group, arg)) {
			DBG("switch %s is not supported", arg);
			goto out;
		}

		if (!g_strcmp0(arg, "-m") || !g_strcmp0(arg, "--match")) {
			switch_type = IPTABLES_MATCH;
			opt = argv[i++];

			if (!opt) {
				DBG("trailing '%s' in rule \"%s\"", arg,
							rule_spec);
				goto out;
			}

			DBG("match %s", opt);

			/* multiport match has to have valid port switches */
			if (!g_strcmp0(opt, "multiport")) {
				multiport_used = true;
				
				/* Cannot use -m multiport with -m protocol */
				if (match_index) {
					DBG("-m multiport with -m %s",
						argv[match_index]);
					goto out;
				}
			/* If this is one of the supported protocols */
			} else if (is_supported(type, IPTABLES_PROTO, group,
						opt)) {
				/*
				 * If no protocol is set before, protocol match
				 * cannot be used
				 */
				if (!switch_types_found[IPTABLES_PROTO]) {
					DBG("-m %s without -p protocol", opt);
					goto out;
				}

				/*
				 * SCTP protocol -m sctp, MH protocol -m mh and
				 * DCCP protocol -m dccp cannot be used because
				 * because iptables gives error (commit/quit)
				 * with these.
				 */
				if (!g_strcmp0(opt, "sctp") ||
					!g_strcmp0(opt, "mh") ||
					!g_strcmp0(opt, "dccp")) {
					DBG("-m %s is not supported", opt);
					goto out;
				}

				/* Check if match protocol equals */
				if (!protocol_match_equals(type,
						argv[protocol_index], opt)) {
					DBG("-p %s -m %s different protocol",
						argv[protocol_index], opt);
					goto out;
				}

				if (multiport_used) {
					DBG("-m multiport -m %s not supported",
							opt);
					goto out;
				}
			}

			/* Save match index for multiport and option checks.*/
			match_index = i-1;
		} else if (!g_strcmp0(arg, "-j") || !g_strcmp0(arg, "--jump") ||
					!g_strcmp0(arg, "-g") ||
					!g_strcmp0(arg, "--goto")) {
			switch_type = IPTABLES_TARGET;
			opt = argv[i++];

			if (!opt) {
				DBG("trailing '%s' in rule \"%s\"", arg,
							rule_spec);
				goto out;
			}

			DBG("target %s", opt);
		} else if (!g_strcmp0(arg, "-p") ||
					!g_strcmp0(arg, "--protocol")) {
			switch_type = IPTABLES_PROTO;
			opt = argv[i++];

			if (!opt) {
				DBG("trailing '%s' in rule \"%s\"", arg,
							rule_spec);
				goto out;
			}

			/* Negated switch must be skipped */
			if (!g_strcmp0(opt, "!"))
				opt = argv[i++];

			/* Save the protocol index for -m switch check */
			protocol_index = i-1;
			DBG("protocol %s", opt);
		} else if (g_str_has_prefix(arg, "--")) {
			enum iptables_match_options_type option_type;
			int option_type_params = 0;
			int option_type_position = 0;
			int opt_index;
			const char *params[IPTABLES_OPTION_COUNT_MAX] =
						{NULL, NULL};

			switch_type = IPTABLES_OPTION;

			/*
			 * Port switches must be recorded. 2 is max and they
			 * must be different direction switches. With multiport
			 * the --port and --ports can be used only once.
			 */
			if (is_port_option(arg, multiport_used)) {
				/* One port option switch is set */
				if (port_option_index) {
					if (is_port_option_same_group(
						argv[port_option_index],
						arg, multiport_used)) {
						DBG("port option %s defined "
							"twice", arg);
						goto out;
					}
				} else {
					port_option_index = i-1;
					DBG("port option %s", arg);
				}
				switch_type = IPTABLES_PORT;
			} else {
				DBG("option %s", arg);
			}

			option_type = validate_option_type(
				protocol_index ? argv[protocol_index] : NULL,
				match_index ? argv[match_index] : NULL,
				arg, &option_type_params,
				&option_type_position, multiport_used);

			if (option_type == IPTABLES_OPTION_NOT_SUPPORTED) {
				DBG("%s is not supported", arg);
				goto out;
			}

			if (!is_valid_option_for_protocol_match(
				protocol_index ? argv[protocol_index] : NULL,
				match_index ? argv[match_index] : NULL,
				option_type)) {
				DBG("option %s does not work with protocol %s "
						"match %s", arg,
						argv[protocol_index],
						argv[match_index]);
				goto out;
			}

			for (opt_index = 0; opt_index < option_type_params &&
					opt_index < IPTABLES_OPTION_COUNT_MAX;
					opt_index++) {
				/* Ignore negations */
				while (!g_strcmp0(argv[i], "!"))
					i++;

				params[opt_index] = argv[i++];
			}

			if (!is_valid_option_type_params(option_type, params,
						option_type_position,
						multiport_used))
			{
				DBG("option %s has invalid params %s %s",
							arg, params[0],
							params[1]);
				goto out;
			}
		} else if (!g_strcmp0(arg, "!")) {
			continue;
		} else {
			DBG("not supported switch %s", arg);
			goto out;
		}

		if (opt && !is_supported(type, switch_type, group, opt)) {
			DBG("%s %s is not supported", arg, opt);
			goto out;
		}

		/* Record the current switch type */
		switch_types_found[switch_type]++;
		switch_type = IPTABLES_UNSET;
		opt = NULL;
	}

	/* There can be 0...2 port switches in rule */
	if (switch_types_found[IPTABLES_PORT] > 2)
		goto out;

	/* If no port switches are used with multiport then rule is invalid */
	if (multiport_used && switch_types_found[IPTABLES_PORT] == 0)
		goto out;

	/* There should be 0...2 matches in one rule */
	if (switch_types_found[IPTABLES_MATCH] > 2)
		goto out;
	
	/*
	 * If there are matches used, there must be options for it. There can
	 * be two matches and options are set only for one of them. Port options
	 * are accounted for as well.
	 */
	if (switch_types_found[IPTABLES_MATCH] &&
				!switch_types_found[IPTABLES_PORT] &&
				!switch_types_found[IPTABLES_OPTION]) {
		DBG("rule has match(es) but not options");
		goto out;
	}

	/* There should be 0...1 protocols defined in rule */
	if (switch_types_found[IPTABLES_PROTO] > 1)
		goto out;

	/* There has to be exactly one target in rule */
	if (switch_types_found[IPTABLES_TARGET] != 1)
		goto out;

	ret = true;

out:
	g_clear_error(&error);
	g_strfreev(argv);

	return ret;
}

static bool is_rule_in_context(struct firewall_context *ctx, int type,
			const char *table, const char *chain, const char *rule)
{
	GList *iter;
	struct fw_rule *list_rule;

	for (iter = g_list_first(ctx->rules); iter; iter = iter->next) {
		list_rule = iter->data;

		if (!list_rule)
			continue;

		if (list_rule->type == type &&
					!g_strcmp0(list_rule->table, table) &&
					!g_strcmp0(list_rule->chain, chain) &&
					!g_strcmp0(list_rule->rule_spec, rule))
			return true;
	}

	return false;
}

typedef int (*add_rules_cb_t)(int type, const char *filename, const char *group,
						int chain_id, char** rules);

static int add_dynamic_rules_cb(int type, const char *filename,
				const char *group, int chain_id, char** rules)
{
	enum connman_service_type service_type;
	connman_iptables_manage_cb_t cb = __connman_iptables_insert;
	char table[] = "filter";
	int count = 0;
	int err = 0;
	int id;
	int i; 

	if (!dynamic_rules || !rules)
		return 0;

	service_type = __connman_service_string2type(group);

	if (!dynamic_rules[service_type])
		dynamic_rules[service_type] = __connman_firewall_create();

	for(i = 0; rules[i]; i++) {

		DBG("processing type %d rule tech %s chain %s rule %s", type,
					group, builtin_chains[chain_id],
					rules[i]);

		if (!validate_iptables_rule(type, group, rules[i])) {
			DBG("failed to add rule, rule is invalid");
			continue;
		}

		if (is_rule_in_context(dynamic_rules[service_type], type, table,
						builtin_chains[chain_id],
						rules[i])) {
			DBG("ignoring rule %s in service type %d, rule exists",
						rules[i], service_type);
			continue;
		}

		switch (type) {
		case AF_INET:
			id = __connman_firewall_add_rule(
						dynamic_rules[service_type],
						cb, filename, table,
						builtin_chains[chain_id],
						rules[i]);
			break;
		case AF_INET6:
			id = __connman_firewall_add_ipv6_rule(
						dynamic_rules[service_type],
						cb, filename, table,
						builtin_chains[chain_id],
						rules[i]);
			break;
		default:
			id = -1;
			DBG("invalid IP protocol %d", type);
			break;
		}

		if (id < 0) {
			DBG("failed to add rule to firewall");
			err = -EINVAL;
		} else {
			DBG("added with id %d", id);
			count++;
		}
	}

	if (!err)
		return count;

	return err;
}

static int add_general_rules_cb(int type, const char *filename,
				const char *group, int chain_id, char** rules)
{
	connman_iptables_manage_cb_t cb = __connman_iptables_append;
	char table[] = "filter";
	int count = 0;
	int err = 0;
	int id;
	int i;

	if (!general_firewall)
		return -EINVAL;

	if (!general_firewall->ctx)
		general_firewall->ctx = __connman_firewall_create();

	if (!general_firewall->ctx)
		return -ENOMEM;

	if (!rules)
		return 0;

	for (i = 0; rules[i]; i++) {

		if (!g_utf8_validate(rules[i], -1, NULL)) {
			DBG("skipping rule, not valid UTF8");
			continue;
		}

		DBG("processing type %d group %s rule chain %s rule %s", type,
					GROUP_GENERAL, builtin_chains[chain_id],
					rules[i]);

		if (!validate_iptables_rule(type, group, rules[i])) {
			DBG("invalid general rule");
			continue;
		}

		if (is_rule_in_context(general_firewall->ctx, type, table,
						builtin_chains[chain_id],
						rules[i])) {
			DBG("ignoring rule %s in general rules, rule exists",
						rules[i]);
			continue;
		}

		switch (type) {
		case AF_INET:
			id = __connman_firewall_add_rule(general_firewall->ctx,
						cb, filename, table,
						builtin_chains[chain_id],
						rules[i]);
			break;
		case AF_INET6:
			id = __connman_firewall_add_ipv6_rule(
						general_firewall->ctx, cb,
						filename, table,
						builtin_chains[chain_id],
						rules[i]);
			break;
		default:
			id = -1;
			DBG("invalid IP protocol %d", type);
			break;
		}

		if (id < 0) {
			DBG("failed to add group %s chain_id %d rule %s",
					GROUP_GENERAL, chain_id, rules[i]);
			err = -EINVAL;
		} else {
			DBG("added with id %d", id);
			count++;
		}
	}

	if (!err)
		return count;

	return err;
}

static int add_tethering_rules_cb(int type, const char *filename,
				const char *group, int chain_id, char** rules)
{
	connman_iptables_manage_cb_t cb = __connman_iptables_insert;
	char table[] = "filter";
	int count = 0;
	int err = 0;
	int id;
	int i;

	if (!tethering_firewall)
		tethering_firewall = __connman_firewall_create();

	if (!tethering_firewall)
		return -ENOMEM;

	if (!rules)
		return 0;

	for (i = 0; rules[i]; i++) {

		if (!g_utf8_validate(rules[i], -1, NULL)) {
			DBG("skipping rule, not valid UTF8");
			continue;
		}

		DBG("processing type %d group %s rule chain %s rule %s", type,
					group, builtin_chains[chain_id],
					rules[i]);

		if (!validate_iptables_rule(type, group, rules[i])) {
			DBG("invalid general rule");
			continue;
		}

		if (is_rule_in_context(tethering_firewall, type, table,
						builtin_chains[chain_id],
						rules[i])) {
			DBG("ignoring rule %s in tethering rules, rule exists",
						rules[i]);
			continue;
		}

		switch (type) {
		case AF_INET:
			id = __connman_firewall_add_rule(tethering_firewall, cb,
						filename, table,
						builtin_chains[chain_id],
						rules[i]);
			break;
		case AF_INET6:
			id = __connman_firewall_add_ipv6_rule(
						tethering_firewall, cb,
						filename, table,
						builtin_chains[chain_id],
						rules[i]);
			break;
		default:
			id = -1;
			DBG("invalid IP protocol %d", type);
			break;
		}

		if (id < 0) {
			DBG("failed to add group %s chain_id %d rule %s",
					group, chain_id, rules[i]);
			err = -EINVAL;
		} else {
			DBG("added with id %d", id);
			count++;
		}
	}

	if (!err)
		return count;

	return err;
}

static int add_rules_from_group(const char *filename, GKeyFile *config,
					const char *group, add_rules_cb_t cb)
{
	GError *error = NULL;
	char** rules;
	const char *chain_name = NULL;
	int types[3] = { AF_INET, AF_INET6, 0 };
	int chain;
	int count;
	int err = 0;
	int i;
	gsize len;

	DBG("config %s group %s", filename, group);

	if (!group || !*group || !cb || !filename || !*filename)
		return 0;

	for (chain = NF_IP_LOCAL_IN; chain < NF_IP_NUMHOOKS - 1; chain++) {
		for (i = 0; types[i]; i++) {

			/* Setup chain name based on IP type */
			switch (types[i]) {
			case AF_INET:
				chain_name = supported_chains[chain];
				break;
			case AF_INET6:
				chain_name = supported_chainsv6[chain];
				break;
			default:
				chain_name = NULL;
			}

			if (!chain_name)
				continue;

			rules = __connman_config_get_string_list(config, group,
						chain_name, &len, &error);

			if (rules && len) {
				DBG("found %d rules in group %s chain %s", len,
							group, chain_name);

				count = cb(types[i], filename, group, chain,
							rules);
			
				if (count < 0) {
					DBG("cannot add rules from config");
					err = -EINVAL;
				} else if (count < len) {
					DBG("%d invalid rules were detected, "
						"%d rules were added",
						len - count, count);
				} else {
					DBG("all %d rules were added", count);
				}
			} else if (rules && error) {
					/* A real error has happened */
					DBG("group %s chain %s error: %s",
							group, chain_name,
							error->message);
			}

			g_clear_error(&error);

			g_strfreev(rules);
		}
	}

	return err;
}

static bool check_config_key(const char* group, const char* key)
{
	bool is_general = false;
	int i;

	if (group && !g_strcmp0(group, GROUP_GENERAL))
		is_general = true;

	/*
	 * Allow only NF_IP_LOCAL_IN...NF_IP_LOCAL_OUT chains since filter
	 * table has no PRE/POST_ROUTING chains.
	 *
	 * The chain ids defined by netfilter are:
	 * NF_IP_PRE_ROUTING	0
	 * NF_IP_LOCAL_IN	1
	 * NF_IP_FORWARD	2
	 * NF_IP_LOCAL_OUT	3
	 * NF_IP_POST_ROUTING	4
	 * NF_IP_NUMHOOKS	5
	 */
	for (i = NF_IP_LOCAL_IN; i < NF_IP_NUMHOOKS - 1; i++) {
		if (!g_strcmp0(key, supported_chains[i]))  {
			DBG("match key %s chain %s", key, supported_chains[i]);
			return true;
		}

		if (!g_strcmp0(key, supported_chainsv6[i])) {
			DBG("match key %s chain %s", key,
						supported_chainsv6[i]);
			return true;
		}

		/* No other than General group should have policies set. */
		if (is_general) {
			if (!g_strcmp0(key, supported_policies[i])) {
				DBG("match key %s chain %s", key,
						supported_policies[i]);
				return true;
			}
			
			if (!g_strcmp0(key, supported_policiesv6[i])) {
				DBG("match key %s chain %s", key,
						supported_policiesv6[i]);
				return true;
			}
		}
	}

	DBG("no match for key %s", key);

	return false;
}

static bool check_config_group(const char *group)
{
	const char *type_str;
	enum connman_service_type type;
	
	if (!g_strcmp0(group, GROUP_GENERAL)) {
		DBG("match group %s", group);
		return true;
	}

	for (type = CONNMAN_SERVICE_TYPE_UNKNOWN;
				type < MAX_CONNMAN_SERVICE_TYPES; type++) {
			type_str = __connman_service_type2string(type);

			if (!type_str)
				continue;

			if (!g_strcmp0(group, type_str)) {
				DBG("match group %s type %s", group, type_str);
				return true;
			}
	}

	if (!g_strcmp0(group, GROUP_TETHERING)) {
		DBG("match group %s", group);
		return true;
	}

	DBG("no match for group %s", group);

	return false;
}

static bool check_dynamic_rules(GKeyFile *config)
{
	enum connman_service_type type;
	char **keys;
	int i;
	bool ret = true;
	const char *group;

	if (!config)
		return false;

	keys = g_key_file_get_groups(config, NULL);

	/* Check that there are only valid service types */
	for (i = 0; keys && keys[i]; i++) {
		if (!check_config_group(keys[i])) {
			connman_warn("Unknown group %s in file %s",
						keys[i], FIREWALLFILE);
			ret = false;
		}
	}

	g_strfreev(keys);

	for (type = CONNMAN_SERVICE_TYPE_UNKNOWN;
			type < MAX_CONNMAN_SERVICE_TYPES; type++) {

		group = __connman_service_type2string(type);

		if (!group)
			continue;

		keys = g_key_file_get_keys(config, group, NULL, NULL);

		for (i = 0; keys && keys[i]; i++) {
			if (!check_config_key(group, keys[i])) {
				connman_warn("Unknown group %s option %s in %s",
							group, keys[i],
							FIREWALLFILE);
				ret = false;
			}
		}

		g_strfreev(keys);
	}

	return ret;
}

static GKeyFile *load_dynamic_rules(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ';');

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		if (err->code != G_FILE_ERROR_NOENT) {
			connman_error("Parsing %s failed: %s", file,
						err->message);
		}

		g_error_free(err);
		g_key_file_unref(keyfile);
		return NULL;
	}

	return keyfile;
}

static int enable_general_firewall_policies(int type, char **policies)
{
	char table[] = "filter";
	int err;
	int i;

	if (!policies || !g_strv_length(policies))
		return 0;

	for (i = NF_IP_LOCAL_IN; i < NF_IP_NUMHOOKS - 1; i++) {
		if (!policies[i-1])
			continue;

		err = __connman_iptables_change_policy(type, table,
					builtin_chains[i], policies[i-1]);

		if (err)
			DBG("cannot set type %d chain %s policy %s", type,
						builtin_chains[i],
						policies[i-1]);
		else {
			DBG("set type %d chain %s policy %s", type,
						builtin_chains[i],
						policies[i-1]);

			err = __connman_iptables_commit(type, table);

			if (err) {
				DBG("commit failed, type %d table %s", type,
							table);
				return err;
			}
		}
	}

	return 0;
}

static int enable_general_firewall()
{
	int err;

	DBG("");

	if (!general_firewall || !general_firewall->ctx) {
		DBG("no general firewall or firewall context set");
		return -EINVAL;
	}

	if (!g_list_length(general_firewall->ctx->rules)) {
		DBG("no general rules set, policies are not set");

		/* No rules defined, no error */
		return 0;
	}

	DBG("%d general rules", g_list_length(general_firewall->ctx->rules));

	err = __connman_firewall_enable(general_firewall->ctx);

	/*
	 * If there is a problem with general firewall, do not apply policies
	 * since it may result in blocking all incoming traffic and the device
	 * is not accessible.
	 */
	if (err) {
		DBG("cannot enable general firewall, policies are not changed");
		return err;
	}

	err = enable_general_firewall_policies(AF_INET,
				general_firewall->policies);

	if (err)
		DBG("cannot enable IPv4 iptables policies, err %d", err);

	err = enable_general_firewall_policies(AF_INET6,
				general_firewall->policiesv6);

	if (err)
		DBG("cannot enable IPv6 iptables policies, err %d", err);

	return err;

}

static bool is_valid_policy(char *policy)
{
	const char *valid_policies[] = {"ACCEPT", "DROP", NULL};

	if (!policy || !*policy)
		return false;

	if (!g_strcmp0(policy, valid_policies[0]) || 
				!g_strcmp0(policy, valid_policies[1]))
		return true;

	DBG("invalid policy %s", policy);

	return false;
}

static int load_general_firewall_policies(int type, GKeyFile *config,
								char **policies)
{
	GError *error = NULL;
	const char *policy;
	char *load_policy;
	int i;

	if (!policies)
		return -EINVAL;

	for (i = NF_IP_LOCAL_IN; i < NF_IP_NUMHOOKS - 1; i++) {
		switch (type) {
		case AF_INET:
			policy = supported_policies[i];
			break;
		case AF_INET6:
			policy = supported_policiesv6[i];
			break;
		default:
			return -EINVAL;
		}

		if (!policy)
			continue;

		load_policy = __connman_config_get_string(config,
					GROUP_GENERAL, policy, &error);

		if (!load_policy) {
			DBG("no policy set for type %d chain %s", type,
						builtin_chains[i]);
		} else if (!is_valid_policy(load_policy)) {
			g_free(load_policy);
		} else {
			/* When the policy is valid, override existing */
			if (policies[i-1])
				g_free(policies[i-1]);

			policies[i-1] = load_policy;
			DBG("set type %d chain %s policy %s", type,
					builtin_chains[i], policies[i-1]);
		}

		/* If policy is read and error is set is is a proper error.*/
		if (policies[i-1] && error)
			DBG("failed to read %s: %s", policy, error->message);

		g_clear_error(&error);
	}

	return 0;
}

static bool restore_policies_set = false;

static int init_general_firewall_policies(GKeyFile *config)
{
	int err = 0;
	int i;

	DBG("");

	if (!general_firewall || !config)
		return -EINVAL;

	if (!general_firewall->policies)
		general_firewall->policies = g_try_new0(char*,
					GENERAL_FIREWALL_POLICIES);

	if (!general_firewall->policies)
		return -ENOMEM;

	if (!general_firewall->restore_policies)
		general_firewall->restore_policies = g_try_new0(char*,
					GENERAL_FIREWALL_POLICIES);

	if (!general_firewall->restore_policies)
		return -ENOMEM;
	
	if (!general_firewall->policiesv6)
		general_firewall->policiesv6 = g_try_new0(char*,
					GENERAL_FIREWALL_POLICIES);

	if (!general_firewall->policiesv6)
		return -ENOMEM;

	if (!general_firewall->restore_policiesv6)
		general_firewall->restore_policiesv6 = g_try_new0(char*,
					GENERAL_FIREWALL_POLICIES);

	if (!general_firewall->restore_policiesv6)
		return -ENOMEM;

	err = load_general_firewall_policies(AF_INET, config,
				general_firewall->policies);
	if (err)
		DBG("failed to load IPv4 iptables chain policies, err %d", err);

	err = load_general_firewall_policies(AF_INET6, config,
				general_firewall->policiesv6);
	if (err)
		DBG("failed to load IPv6 iptables chain policies, err %d", err);

	if (!restore_policies_set) {
		// TODO add function into iptables.c to get chain policy
		for (i = 0; i < GENERAL_FIREWALL_POLICIES; i++) {
			general_firewall->restore_policies[i] =
						g_strdup("ACCEPT");
			general_firewall->restore_policiesv6[i] =
						g_strdup("ACCEPT");
		}
		restore_policies_set = true;
	}

	return err;
}

static int init_general_firewall(const char *config_file, GKeyFile *config)
{
	int err;

	DBG("");

	if (!config)
		return -EINVAL;

	if (!general_firewall)
		general_firewall = g_try_new0(struct general_firewall_context,
									1);

	if (!general_firewall)
		return -ENOMEM;

	err = init_general_firewall_policies(config);

	if (err)
		DBG("cannot initialize general policies"); // TODO react to this

	err = add_rules_from_group(config_file, config, GROUP_GENERAL,
				add_general_rules_cb);

	if (err)
		DBG("cannot setup general firewall rules");

	return err;
}

static void remove_ctx(gpointer user_data)
{
	struct firewall_context *ctx = user_data;

	if (ctx->enabled)
		__connman_firewall_disable_rule(ctx, FW_ALL_RULES);

	__connman_firewall_destroy(ctx);
}

static int init_dynamic_firewall_rules(const char *file)
{
	GKeyFile *config;
	enum connman_service_type type;
	const char *group;
	int ret = 0;

	DBG("");

	config = load_dynamic_rules(file);

	/* No config is set, no error but dynamic rules are disabled */
	if (!config) {
		DBG("no configuration found, file %s", file);
		goto out;
	}

	/* The firewall config must be correct */
	if (!check_dynamic_rules(config)) {
		connman_error("firewall config %s has errors", file);
		ret = -EINVAL;
		goto out;
	}

	if (init_general_firewall(file, config))
		DBG("Cannot setup general firewall");

	if (!dynamic_rules)
		dynamic_rules = g_try_new0(struct firewall_context*,
					MAX_CONNMAN_SERVICE_TYPES);

	if (!dynamic_rules) {
		ret = -ENOMEM;
		goto out;
	}

	if (!current_dynamic_rules)
		current_dynamic_rules = g_hash_table_new_full(g_str_hash,
					g_str_equal,g_free, remove_ctx);

	for (type = CONNMAN_SERVICE_TYPE_UNKNOWN;
			type < MAX_CONNMAN_SERVICE_TYPES; type++) {

		group = __connman_service_type2string(type);

		if (!group)
			continue;

		if (add_rules_from_group(file, config, group,
					add_dynamic_rules_cb))
			DBG("failed to process rules from group type %d", type);
	}

	if (add_rules_from_group(file, config, GROUP_TETHERING,
				add_tethering_rules_cb))
		DBG("failed to add tethering rules");

out:
	if (config)
		g_key_file_unref(config);

	return ret;
}

static int init_all_dynamic_firewall_rules(void)
{
	GList *iter;
	GError *error = NULL;
	GDir *dir;
	const char *filename = NULL;
	char *filepath = NULL;
	int err;

	err = init_dynamic_firewall_rules(FIREWALLCONFIGFILE);

	if (g_file_test(FIREWALLCONFIGDIR, G_FILE_TEST_IS_DIR)) {
		dir = g_dir_open(FIREWALLCONFIGDIR, 0, &error);

		if (!dir) {
			if (error) {
				DBG("cannot open dir, error: %s",
							error->message);
				g_clear_error(&error);
			}
			goto out;
		}

		DBG("read configs from %s", FIREWALLCONFIGDIR);

		/*
		 * Ordering of files is not guaranteed with g_dir_open(). Read
		 * the filenames into sorted GList.
		 */
		while ((filename = g_dir_read_name(dir))) {
			/* Read configs that have firewall.conf suffix */
			if (!g_str_has_suffix(filename, FIREWALLFILE))
				continue;

			/*
			 * Prepend read files into list of configuration
			 * files to be used in checks when new configurations
			 * are added to avoid unnecessary reads of already read
			 * configurations. Sort list after all are added.
			 */
			configuration_files = g_list_prepend(
						configuration_files,
						g_strdup(filename));
		}

		configuration_files = g_list_sort(configuration_files,
					(GCompareFunc)g_strcmp0);

		for (iter = configuration_files; iter; iter = iter->next) {
			filename = iter->data;

			filepath = g_strconcat(FIREWALLCONFIGDIR, filename,
						NULL);
			DBG("reading config %s", filepath);

			/* Allow also symbolic links in configs */
			if (g_file_test(filepath, G_FILE_TEST_IS_REGULAR)) {
				if (init_dynamic_firewall_rules(filepath))
					DBG("invalid firewall config");
			}

			g_free(filepath);
		}

		g_dir_close(dir);
	} else {
		DBG("no config dir %s", FIREWALLCONFIGDIR);
	}

	/* Error loading main configuration */
	if (err)
		return err;

out:
	err = enable_general_firewall();

	return err;
}

static int restore_policies(int type, char **policies, char **set_policies)
{
	char table[] = "filter";
	int commit_err = 0;
	int err = 0;
	int i;

	DBG("");

	if (!policies && !set_policies)
		return -EINVAL;

	for (i = NF_IP_LOCAL_IN; i < NF_IP_NUMHOOKS - 1; i++) {
		/* Policy is changed only if it has been set */
		if (policies[i-1]) {

			g_free(policies[i-1]);

			if (!set_policies[i-1])
				continue;

			/* Commit errors are not recoverable */
			if (!commit_err) {
				err = __connman_iptables_change_policy(type,
							table,
							builtin_chains[i],
							set_policies[i-1]);

				if (err) {
					/* Ignore this and continue with next */
					DBG("cannot restore chain %s policy %s",
							builtin_chains[i],
							set_policies[i-1]);
				} else {
					commit_err = __connman_iptables_commit(
								type, table);

					if (commit_err) {
						DBG("cannot commit policy "
							"restore on chain %s "
							"policy %s",
							builtin_chains[i],
							set_policies[i-1]);
					}
				}
			}
		}

		g_free(set_policies[i-1]);
	}

	return commit_err;
}

static void cleanup_general_firewall()
{
	int err;

	DBG("");

	if (!general_firewall)
		return;

	if (!general_firewall->ctx)
		return;

	if (general_firewall->ctx->enabled) {
		err = __connman_firewall_disable_rule(general_firewall->ctx,
				FW_ALL_RULES);

		if (err)
			DBG("Cannot disable generic firewall rules");
	}
	__connman_firewall_destroy(general_firewall->ctx);
	general_firewall->ctx = NULL;

	g_free(general_firewall);
	general_firewall = NULL;
}

static void cleanup_dynamic_firewall_rules()
{
	enum connman_service_type type;

	DBG("");

	if (current_dynamic_rules)
		g_hash_table_destroy(current_dynamic_rules);

	current_dynamic_rules = NULL;

	if (!dynamic_rules)
		return;

	/* These rules are never enabled directly */
	for (type = CONNMAN_SERVICE_TYPE_UNKNOWN + 1;
			type < MAX_CONNMAN_SERVICE_TYPES; type++) {

		if (!dynamic_rules[type])
			continue;

		__connman_firewall_destroy(dynamic_rules[type]);
		dynamic_rules[type] = NULL;
	}

	if (tethering_firewall) {
		if (tethering_firewall->enabled)
			__connman_firewall_disable_rule(tethering_firewall,
						FW_ALL_RULES);

		__connman_firewall_destroy(tethering_firewall);
		tethering_firewall = NULL;
	}

	g_free(dynamic_rules);
	dynamic_rules = NULL;
}

static void firewall_failsafe(const char *chain_name, void *user_data)
{
	int err;
	int type;
	const char *data = user_data;

	if (!data)
		return;

	if (!g_strcmp0(data, "AF_INET"))
		type = AF_INET;
	else if (!g_strcmp0(data, "AF_INET6"))
		type = AF_INET6;
	else
		return;

	err = __connman_iptables_change_policy(type, "filter", chain_name,
				"ACCEPT");

	if (err) {
		DBG("cannot set table filter chain %s policy ACCEPT, error %d",
					chain_name, err);
		return;
	}

	err = __connman_iptables_commit(type, "filter");

	if (err)
		DBG("cannot commit table filter chain %s policy, error %d",
					chain_name, err);
}

static int copy_new_dynamic_rules(struct firewall_context *dyn_ctx,
			struct firewall_context *srv_ctx, char* ifname)
{
	GList *dyn_list;
	struct fw_rule *dyn_rule;
	struct fw_rule *new_rule;
	int err;

	/* Go over dynamic rules for this type */
	for (dyn_list = g_list_first(dyn_ctx->rules); dyn_list;
				dyn_list = dyn_list->next) {
		dyn_rule = dyn_list->data;

		/* If the dynamic rule is already added for service firewall */
		if (is_rule_in_context(srv_ctx, dyn_rule->type,
					dyn_rule->table, dyn_rule->chain,
					dyn_rule->rule_spec))
			continue;

		new_rule = copy_fw_rule(dyn_rule, ifname);
		
		srv_ctx->rules = g_list_insert_sorted(srv_ctx->rules, new_rule,
					firewall_rule_compare);

		if (srv_ctx->enabled) {
			err = firewall_enable_rule(new_rule);

			if (err)
				DBG("new rule not enabled %d", err);
		}
	}

	return 0;
}

static int remove_config_from_context(struct firewall_context *ctx,
						const char *config_file,
						bool disable)
{
	GList *iter = NULL;
	struct fw_rule *rule;
	int err = 0;
	int e = 0;

	if (!ctx || !config_file)
		return e;

	iter = g_list_first(ctx->rules);

	while (iter) {
		rule = iter->data;
		iter = iter->next; /* Move to next before removal */

		if (!g_strcmp0(config_file, rule->config_file)) {
			DBG("removing rule %d table %s chain %s %s",
						rule->id, rule->table,
						rule->chain, rule->rule_spec);

			/*
			 * If the rule was enabled and requested to be disabled
			 * try to disable it first. If disabling fails, do not
			 * remove the rule yet so it the rule might be attempted
			 * to be removed at shutdown.
			 */
			if (rule->enabled && disable) {
				err = __connman_firewall_disable_rule(ctx,
							rule->id);

				if (err) {
					DBG("cannot disable rule %d", err);
					e = err;
					continue;
				}
			}

			switch (rule->type) {
			case AF_INET:
				err = __connman_firewall_remove_rule(ctx,
							rule->id);
				break;
			case AF_INET6:
				err = __connman_firewall_remove_ipv6_rule(ctx,
							rule->id);
			}

			if (err) {
				DBG("cannot remove rule, err %d", err);
				e = err;
			}
		}
	}

	return e;
}

static void firewall_config_removed(const char *config_file)
{
	GHashTableIter iter;
	gpointer key, value;
	enum connman_service_type type;
	struct firewall_context *ctx;
	int err;

	DBG("removing config %s rules from general firewall", config_file);

	err = remove_config_from_context(general_firewall->ctx, config_file,
				true);

	if (err)
		DBG("cannot remove deleted rules.");

	DBG("removing config %s rules from tethering firewall", config_file);

	err = remove_config_from_context(tethering_firewall, config_file, true);

	if (err)
		DBG("cannot remove deleted rules.");

	for (type = 0; type < MAX_CONNMAN_SERVICE_TYPES; type++) {
		if (!dynamic_rules[type] || !dynamic_rules[type]->rules)
			continue;

		DBG("removing config %s rules from %s dynamic rules",
					config_file,
					__connman_service_type2string(type));

		err = remove_config_from_context(dynamic_rules[type],
					config_file, false);

		if (err)
			DBG("cannot remove deleted rules");
	}

	g_hash_table_iter_init(&iter, current_dynamic_rules);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		ctx = value;

		DBG("removing config %s rules from active service %s",
					config_file, (char*)key);

		err = remove_config_from_context(ctx, config_file, true);

		if (err)
			DBG("cannot remove deleted rules");
	}
}

static int enable_new_firewall_rules(struct connman_service *service,
								void *data)
{
	enum connman_service_state state;

	state = connman_service_get_state(service);

	/*
	 * Call service_state_changed() although the state has not changed but
	 * there may be a service which was online before firewall reloading and
	 * it might now have new rules set. This enables the rules for connected
	 * services by acting as if the notification of such event was sent.
	 */
	service_state_changed(service, state);

	return 0;
}

static int firewall_reload_configurations()
{
	GError *error = NULL;
	GDir *dir;
	GSList *read_files = NULL;
	GSList *slist_iter = NULL;
	GList *list_iter = NULL;
	GHashTableIter iter;
	gpointer key, value;
	struct connman_service *service;
	enum connman_service_type type;
	struct firewall_context *ctx;
	const char *filename;
	const char *config_file;
	char *ifname;
	char *filepath;
	bool new_configuration_files = false;
	int err = 0;

	/* Nothing to read */
	if (!g_file_test(FIREWALLCONFIGDIR, G_FILE_TEST_IS_DIR))
		return 0;

	dir = g_dir_open(FIREWALLCONFIGDIR, 0, &error);

	if (!dir) {
		if (error) {
			DBG("cannot open dir, error: %s", error->message);
			g_clear_error(&error);
		}

		/* Ignore dir open error in reload */
		return 0;
	}

	DBG("read configs from %s", FIREWALLCONFIGDIR);

	/* Read filenames into ordered list */
	while ((filename = g_dir_read_name(dir))) {
		/* Read configs that have firewall.conf suffix */
		if (!g_str_has_suffix(filename, FIREWALLFILE))
			continue;

		/*
		 * Add file name to read file list for checking if config file
		 * has been removed. At this point ignore file tests.
		 */
		read_files = g_slist_prepend(read_files, g_strdup(filename));
	}

	read_files = g_slist_sort(read_files, (GCompareFunc)g_strcmp0);

	g_dir_close(dir);

	/* Process ordered list of configuration files */
	for (slist_iter = read_files; slist_iter;
				slist_iter = slist_iter->next) {
		filename = slist_iter->data;

		/* If config file is already read */
		if (g_list_find_custom(configuration_files, filename,
					(GCompareFunc)g_strcmp0))
			continue;

		filepath = g_strconcat(FIREWALLCONFIGDIR, filename, NULL);

		DBG("processing new config %s", filepath);

		if (g_file_test(filepath, G_FILE_TEST_IS_REGULAR)) {

			err = init_dynamic_firewall_rules(filepath);

			if (!err) {
				DBG("new configuration %s loaded", filepath);

				configuration_files = g_list_prepend(
							configuration_files,
							g_strdup(filename));

				new_configuration_files = true;
			}
		}

		g_free(filepath);
	}

	configuration_files = g_list_sort(configuration_files,
				(GCompareFunc)g_strcmp0);

	list_iter = g_list_last(configuration_files);

	/* First check if any configs has been removed */
	while (list_iter)
	{
		config_file = list_iter->data;
		GList *list_iter_prev = g_list_previous(list_iter);

		/*
		 * If no files are read remove all configs. If the file that
		 * was previously read is not in the list of previosly read
		 * remove rules read from that removed config file.
		 */
		if (!g_slist_find_custom(read_files, config_file,
					(GCompareFunc)g_strcmp0)) {
			DBG("config %s removed, deleting rules", config_file);

			firewall_config_removed(config_file);

			g_free(list_iter->data);
			configuration_files = g_list_remove(configuration_files,
						config_file);
		}

		list_iter = list_iter_prev;
	}

	g_slist_free_full(read_files, g_free);

	/* Then check if there are new configs that were read without errors */
	if (!new_configuration_files) {
		DBG("no new configuration was found");
		return 0;
	}

	/* Apply general firewall rules that were added */
	__connman_firewall_enable_rule(general_firewall->ctx, FW_ALL_RULES);

	g_hash_table_iter_init(&iter, current_dynamic_rules);

	/*
	 * Go through all service specific firewalls and add new rules
	 * for each.
	 */
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		service = connman_service_lookup_from_identifier(key);

		if (!service)
			continue;

		type = connman_service_get_type(service);
		ifname = connman_service_get_interface(service);

		if (!has_dynamic_rules_set(type))
			continue;

		ctx = value;

		copy_new_dynamic_rules(dynamic_rules[type], ctx, ifname);

		g_free(ifname);
	}

	/* Go through existing services that may have new rules set */
	connman_service_iterate_services(enable_new_firewall_rules, NULL);

	return 0;
}

static struct connman_access_firewall_policy *firewall_access_policy = NULL;

static struct connman_access_firewall_policy *get_firewall_access_policy()
{
	if (!firewall_access_policy) {
		/* Use the default policy */
		firewall_access_policy =
				__connman_access_firewall_policy_create(NULL);
	}
	return firewall_access_policy;
}

static DBusMessage *reload(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	int err;

	DBG("conn %p", conn);

	if (__connman_access_firewall_manage(get_firewall_access_policy(),
				"Reload", dbus_message_get_sender(msg),
				CONNMAN_ACCESS_ALLOW) != CONNMAN_ACCESS_ALLOW) {
		DBG("%s is not allowed to reload firewall configurations",
				dbus_message_get_sender(msg));
		return __connman_error_permission_denied(msg);
	}

	err = firewall_reload_configurations();

	/* TODO proper error reporting if necessary/sensible */
	if (err)
		return __connman_error_failed(msg, err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusConnection *connection = NULL;

static const GDBusMethodTable firewall_methods[] = {
	{ GDBUS_ASYNC_METHOD("Reload", NULL, NULL, reload) },
	{ },
};

static struct connman_notifier firewall_notifier = {
	.name			= "firewall",
	.service_state_changed	= service_state_changed,
	.service_remove		= service_remove,
	.tethering_changed	= tethering_changed,
};

int __connman_firewall_init(void)
{
	int err;

	DBG("");

	flush_all_tables(AF_INET);
	flush_all_tables(AF_INET6);
	restore_policies_set = false;
	
	iptables_options = g_hash_table_new_full(g_str_hash, g_str_equal,
				g_free, g_free);
	initialize_iptables_options();

	err = init_all_dynamic_firewall_rules();

	if (!err) { 
		err = connman_notifier_register(&firewall_notifier);
		if (err < 0) {
			DBG("cannot register notifier, dynamic rules disabled");
			cleanup_dynamic_firewall_rules();
		}

		connection = connman_dbus_get_connection();

		if (!g_dbus_register_interface(connection,
					CONNMAN_FIREWALL_PATH,
					CONNMAN_FIREWALL_INTERFACE,
					firewall_methods, NULL, NULL, NULL,
					NULL)) {
			DBG("cannot register dbus, new firewall configuration "
						"cannot be installed runtime");

			dbus_connection_unref(connection);
			connection = NULL;
		}
	} else {
		DBG("dynamic rules disabled, policy ACCEPT set for all chains");
		connman_error("firewall initialization error, reset iptables");
		__connman_iptables_cleanup();
		__connman_iptables_init();
		__connman_iptables_iterate_chains(AF_INET, "filter",
					firewall_failsafe, "AF_INET");
		__connman_iptables_iterate_chains(AF_INET6, "filter",
					firewall_failsafe, "AF_INET6");
	}
	
	

	return 0;
}

void __connman_firewall_pre_cleanup(void)
{
	int err;

	if (!general_firewall)
		return;

	DBG("");

	err = restore_policies(AF_INET, general_firewall->policies,
				general_firewall->restore_policies);

	if (err)
		DBG("failed to restore IPv4 iptables policies, err %d", err);

	err = restore_policies(AF_INET6, general_firewall->policiesv6,
				general_firewall->restore_policiesv6);

	if (err)
		DBG("failed to restore IPv6 iptables policies, err %d", err);

	g_free(general_firewall->policies);
	general_firewall->policies = NULL;

	g_free(general_firewall->restore_policies);
	general_firewall->restore_policies = NULL;

	g_free(general_firewall->policiesv6);
	general_firewall->policiesv6 = NULL;

	g_free(general_firewall->restore_policiesv6);
	general_firewall->restore_policiesv6 = NULL;
}

void __connman_firewall_cleanup(void)
{
	DBG("");

	if (connection) {
		if (!g_dbus_unregister_interface(connection,
					CONNMAN_FIREWALL_PATH,
					CONNMAN_FIREWALL_INTERFACE))
			DBG("dbus unregister failed");

		dbus_connection_unref(connection);
	}

	__connman_access_firewall_policy_free(firewall_access_policy);
	firewall_access_policy = NULL;

	cleanup_dynamic_firewall_rules();
	cleanup_general_firewall();

	g_list_free_full(configuration_files, g_free);
	configuration_files = NULL;

	g_slist_free_full(managed_tables, cleanup_managed_table);
	managed_tables = NULL;
	
	g_hash_table_destroy(iptables_options);
	iptables_options = NULL;
}
