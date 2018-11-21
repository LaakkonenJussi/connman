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

#include "connman.h"

#define CHAIN_PREFIX "connman-"
#define FW_ALL_RULES -1

static const char *builtin_chains[] = {
	[NF_IP_PRE_ROUTING]	= "PREROUTING",
	[NF_IP_LOCAL_IN]	= "INPUT",
	[NF_IP_FORWARD]		= "FORWARD",
	[NF_IP_LOCAL_OUT]	= "OUTPUT",
	[NF_IP_POST_ROUTING]	= "POSTROUTING",
};

struct connman_managed_table {
	char *name;
	unsigned int chains[NF_INET_NUMHOOKS];
};

struct fw_rule {
	int id;
	bool enabled;
	bool allowed;
	char *table;
	char *chain;
	char *rule_spec;
	char *ifname;
};

struct firewall_context {
	GList *rules;
	bool enabled;
};

static GSList *managed_tables = NULL;

static bool firewall_is_up;
static unsigned int firewall_rule_id;

#define FIREWALLFILE "firewall.conf"
#define CONFIGFIREWALLFILE CONFIGDIR "/" FIREWALLFILE
#define GROUP_GENERAL "General"
#define GENERAL_FIREWALL_POLICIES 3

static char disabled_char = '%';

struct general_firewall_context {
	char **policies;
	char **restore_policies;
	struct firewall_context *ctx;
};

static struct general_firewall_context *general_firewall = NULL;

/* The dynamic rules that are loaded from config */
static struct firewall_context **dynamic_rules = NULL;

/*
 * The dynamic rules that are currently in use. Service name is used as hash
 * value and the struct firewall_context is the data held.
 */
static GHashTable *current_dynamic_rules = NULL;

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

static int insert_managed_chain(const char *table_name, int id)
{
	char *rule, *managed_chain;
	int err;

	managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX,
					builtin_chains[id]);

	err = __connman_iptables_new_chain(table_name, managed_chain);
	if (err < 0)
		goto out;

	rule = g_strdup_printf("-j %s", managed_chain);
	err = __connman_iptables_insert(table_name, builtin_chains[id], rule);
	g_free(rule);
	if (err < 0) {
		__connman_iptables_delete_chain(table_name, managed_chain);
		goto out;
	}

out:
	g_free(managed_chain);

	return err;
}

static int delete_managed_chain(const char *table_name, int id)
{
	char *rule, *managed_chain;
	int err;

	managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX,
					builtin_chains[id]);

	rule = g_strdup_printf("-j %s", managed_chain);
	err = __connman_iptables_delete(table_name, builtin_chains[id], rule);
	g_free(rule);

	if (err < 0)
		goto out;

	err =  __connman_iptables_delete_chain(table_name, managed_chain);

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

static int insert_managed_rule(const char *table_name,
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

		if (g_strcmp0(mtable->name, table_name) == 0)
			break;

		mtable = NULL;
	}

	if (!mtable) {
		mtable = g_new0(struct connman_managed_table, 1);
		mtable->name = g_strdup(table_name);

		managed_tables = g_slist_prepend(managed_tables, mtable);
	}

	if (mtable->chains[id] == 0) {
		DBG("table %s add managed chain for %s",
			table_name, chain_name);

		err = insert_managed_chain(table_name, id);
		if (err < 0)
			return err;
	}

	mtable->chains[id]++;
	chain = g_strdup_printf("%s%s", CHAIN_PREFIX, chain_name);

out:
	err = __connman_iptables_append(table_name, chain,
				full_rule ? full_rule : rule_spec);

	g_free(chain);
	g_free(full_rule);

	return err;
 }

static int delete_managed_rule(const char *table_name,
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
		return __connman_iptables_delete(table_name, chain_name,
					full_rule ? full_rule : rule_spec);
	}

	managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX, chain_name);

	err = __connman_iptables_delete(table_name, managed_chain,
				full_rule ? full_rule : rule_spec);

	for (list = managed_tables; list; list = list->next) {
		mtable = list->data;

		if (g_strcmp0(mtable->name, table_name) == 0)
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

	err = delete_managed_chain(table_name, id);

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

	/* If rule is not allowed*/
	if (!rule->allowed)
		return -EPERM;

	DBG("%s %s %s %s", rule->table, rule->chain, rule->ifname,
							rule->rule_spec);

	err = insert_managed_rule(rule->table, rule->chain, rule->ifname,
							rule->rule_spec);
	if (err < 0) {
		DBG("cannot insert managed rule %d", err);
		return err;
	}

	err = __connman_iptables_commit(rule->table);
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

	err = delete_managed_rule(rule->table, rule->chain, rule->ifname,
							rule->rule_spec);
	if (err < 0) {
		connman_error("Cannot remove previously installed "
			"iptables rules: %s", strerror(-err));
		return err;
	}

	err = __connman_iptables_commit(rule->table);
	if (err < 0) {
		connman_error("Cannot remove previously installed "
			"iptables rules: %s", strerror(-err));
		return err;
	}

	rule->enabled = false;

	return 0;
}

int __connman_firewall_add_rule(struct firewall_context *ctx,
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
	rule->enabled = false;
	rule->allowed = true;
	rule->table = g_strdup(table);
	rule->chain = g_strdup(chain);

	/*
	 * If rule starts with % (disabled_char) it is not allowed to use. The
	 * actual rule starts after this character.
	 */
	if (rule_spec[0] == disabled_char) {
		rule->allowed = false;
		rule->rule_spec = g_strdup(&(rule_spec[1]));
		g_free(rule_spec);
	} else {
		rule->rule_spec = rule_spec;
	}

	ctx->rules = g_list_append(ctx->rules, rule);
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

int __connman_firewall_enable_rule(struct firewall_context *ctx, int id)
{
	struct fw_rule *rule;
	GList *list;
	int err = -ENOENT;
	int count = 0;

	for (list = g_list_first(ctx->rules); list; list = g_list_next(list)) {
		rule = list->data;

		if (rule->id == id || id == FW_ALL_RULES) {
			err = firewall_enable_rule(rule);

			/* Rules that are forced off are silently ignored */
			if (err == -EPERM)
				err = 0;
			else if (err < 0)
				break;

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

static void flush_table(const char *table_name)
{
	GSList *chains = NULL, *list;
	char *rule, *managed_chain;
	int id, err;

	__connman_iptables_iterate_chains(table_name, iterate_chains_cb,
						&chains);

	for (list = chains; list; list = list->next) {
		id = GPOINTER_TO_INT(list->data);

		managed_chain = g_strdup_printf("%s%s", CHAIN_PREFIX,
						builtin_chains[id]);

		rule = g_strdup_printf("-j %s", managed_chain);
		err = __connman_iptables_delete(table_name,
						builtin_chains[id], rule);
		if (err < 0) {
			connman_warn("Failed to delete jump rule '%s': %s",
				rule, strerror(-err));
		}
		g_free(rule);

		err = __connman_iptables_flush_chain(table_name, managed_chain);
		if (err < 0) {
			connman_warn("Failed to flush chain '%s': %s",
				managed_chain, strerror(-err));
		}
		err = __connman_iptables_delete_chain(table_name, managed_chain);
		if (err < 0) {
			connman_warn("Failed to delete chain '%s': %s",
				managed_chain, strerror(-err));
		}

		g_free(managed_chain);
	}

	err = __connman_iptables_commit(table_name);
	if (err < 0) {
		connman_warn("Failed to flush table '%s': %s",
			table_name, strerror(-err));
	}

	g_slist_free(chains);
}

static void flush_all_tables(void)
{
	/* Flush the tables ConnMan might have modified
	 * But do so if only ConnMan has done something with
	 * iptables */

	if (!g_file_test("/proc/net/ip_tables_names",
			G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
		firewall_is_up = false;
		return;
	}

	firewall_is_up = true;

	flush_table("filter");
	flush_table("mangle");
	flush_table("nat");
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
	struct connman_service *service;
	char *ifname;

	rule = data;
	service = user_data;

	/* If rule is already enabled interface info is already set */
	if (!rule || !service || rule->enabled)
		return;

	ifname = connman_service_get_interface(service);

	if (rule->ifname && g_str_equal(rule->ifname, ifname)) {
		DBG("rule %d ifname %s not changed", rule->id, rule->ifname);
		g_free(ifname);
		return;
	}

	g_free(rule->ifname);
	rule->ifname = ifname;

	DBG("rule %d %s %s", rule->id, rule->ifname, rule->rule_spec);
}

static gpointer copy_fw_rule(gconstpointer src, gpointer data)
{
	struct connman_service *service;
	const struct fw_rule *old;
	struct fw_rule *new;
	
	old = src;
	service = data;

	if (!old)
		return NULL;

	new = g_try_new0(struct fw_rule, 1);

	if (!new)
		return NULL;

	new->id = firewall_rule_id++;
	new->enabled = false;
	new->allowed = old->allowed;
	new->table = g_strdup(old->table);
	new->chain = g_strdup(old->chain);
	new->rule_spec = g_strdup(old->rule_spec);

	setup_firewall_rule_interface(new, service);

	return new;
}

static struct firewall_context *clone_firewall_context(
						struct firewall_context *ctx,
						struct connman_service *service)
{
	struct firewall_context *clone;

	if (!ctx || !service)
		return NULL;
	
	clone = __connman_firewall_create();
	
	if (!clone)
		return NULL;
	
	clone->rules = g_list_copy_deep(ctx->rules, copy_fw_rule, service);
	
	return clone;
}

static int enable_dynamic_rules(struct connman_service *service)
{
	struct firewall_context *ctx;
	enum connman_service_type type;
	const char *identifier;
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

		/* Create a clone with interface info from service */
		ctx = clone_firewall_context(dynamic_rules[type], service);

		/* Allocation of ctx failed */
		if (!ctx)
			return -ENOMEM;

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

		/* Set interface information for each firewall rule */
		g_list_foreach(ctx->rules, setup_firewall_rule_interface,
					service);

		DBG("reused firewall for service %p %s", service, identifier);
	}

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
		else if (err == -EINVAL)
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

enum iptables_switch_type {
	IPTABLES_UNSET    = 0,
	IPTABLES_SWITCH   = 1,
	IPTABLES_MATCH    = 2,
	IPTABLES_TARGET   = 3,
	IPTABLES_PROTO    = 4,
	IPTABLES_PORT     = 5,
};

#define MAX_IPTABLES_SWITCH 6

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

static bool is_supported(enum iptables_switch_type type, const char* group,
								const char *str)
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
						NULL
	};
	const char *not_supported_dynamic_switches[] = { "--in-interface", "-i",
						"--out-interface", "-o",
						NULL
	};
	const char *not_supported_matches[] = { "comment", "state", NULL};

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

	/* Protocols that iptables supports with -p or --protocol switch */
	const char *supported_protocols[] = { 	"tcp",
						"udp",
						"udplite"
						"icmp",
						"icmpv6",
						"esp",
						"ah",
						"sctp",
						"mh",
						"all",
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
	case IPTABLES_SWITCH:
		for (i = 0; not_supported_switches[i]; i++) {
			if (!g_strcmp0(str, not_supported_switches[i]))
				return false;
		}

		/* If the rule is not in Group general */
		if (!is_general) {
			for (i = 0; not_supported_dynamic_switches[i]; i++) {
				if (!g_strcmp0(str,
					not_supported_dynamic_switches[i]))
					return false;
			} 
		}
		return true;
	case IPTABLES_MATCH:
		for (i = 0 ; not_supported_matches[i] ; i++) {
			if(!g_strcmp0(str, not_supported_matches[i]))
				return false;
		}
		return true;
	case IPTABLES_TARGET:
		for (i = 0 ; supported_targets[i] ; i++) {
			if(!g_strcmp0(str, supported_targets[i]))
				return true;
		}
		return false;
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
	default:
		return true;
	}
}

static bool is_port_switch(const char *str, bool multiport)
{
	const char *multiport_switches[] = { "--destination-ports", "--dports",
					"--source-ports", "--sports",
					"--port", "--ports",
					NULL
	};
	const char *port_switches[] = { "--destination-port", "--dport",
					"--source-port", "--sport",
					NULL
	};

	int i;

	if (!str || !*str)
		return true;

	if (multiport) {
		for (i = 0; multiport_switches[i]; i++) {
			if (!g_strcmp0(str, multiport_switches[i]))
				return true;
		}
	}

	/* Normal port switches can be used also with -m multiport */
	for (i = 0; port_switches[i]; i++) {
		if (!g_strcmp0(str, port_switches[i])) {
			return true;
		}
	}

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
			if (portnum && portnum < G_MAXUINT16)
				continue;
		}

		/* Check if service name is valid with any protocol */
		s = getservbyname(tokens[i], NULL);

		if (s) {
			if (!g_strcmp0(tokens[i], s->s_name))
				continue;
		}

		/* If one of the ports/services is invalid, rule is invalid */
		ret = false;
		DBG("invalid port/service %s in %s", tokens[i], str);
		break;
	}

	g_strfreev(tokens);

	return ret;
}

static bool validate_iptables_rule(const char *group, const char *rule_spec)
{
	gchar **argv = NULL;
	GError *error = NULL;
	bool ret = false;
	int i = 0;
	int argc = 0;
	unsigned int switch_types_found[MAX_IPTABLES_SWITCH] = { 0 };
	enum iptables_switch_type type = IPTABLES_UNSET;
	const char *match = NULL;

	if (!g_shell_parse_argv(rule_spec, &argc, &argv, &error)) {
		DBG("failed in parsing %s", error ? error->message : "");
		goto out;
	}

	/* -j TARGET is the bare minimum of a rule */
	if (argc < 2 || !argv[0][0]) {
		DBG("parsed content is invalid");
		goto out;
	}

	/* Rule must start with '-' char */
	if (argv[0][0] != '-') {
		DBG("invalid rule %s, does not start with '-'", rule_spec);
		goto out;
	}

	for (i = 0; i < argc; ) {
		const char *arg = argv[i++];

		if (!is_supported(IPTABLES_SWITCH, group, arg)) {
			DBG("switch %s is not supported", arg);
			goto out;
		}

		if (!g_strcmp0(arg, "-m")) {
			type = IPTABLES_MATCH;
			match = argv[i++];

			if (!match) {
				DBG("trailing '-m' in rule \"%s\"", rule_spec);
				goto out;
			}

			/* multiport match has to have valid port switches */
			if (!g_strcmp0(match, "multiport")) {
				const char *opt = argv[i++];

				if (!opt) {
					DBG("empty %s %s switch", arg, match);
					goto out;
				}

				if (!is_port_switch(opt, true)) {
					DBG("non-supported %s %s switch %s",
						arg, match, opt);
					goto out;
				}

				const char *param = argv[i++];
				if (!param) {
					DBG("empty parameter with %s", opt);
					goto out;
				}

				/* Negated switch must be skipped */
				if (!g_strcmp0(param, "!"))
					param = argv[i++];

				if (!validate_ports_or_services(param)) {
					DBG("invalid ports %s %s", opt, param);
					goto out;
				}
			}
		}

		if (!g_strcmp0(arg, "-j")) {
			type = IPTABLES_TARGET;
			match = argv[i++];

			if (!match) {
				DBG("trailing '-j' in rule \"%s\"", rule_spec);
				goto out;
			}
		}

		if (!g_strcmp0(arg, "-p")) {
			type = IPTABLES_PROTO;
			match = argv[i++];

			if (!match) {
				DBG("trailing '-p' in rule \"%s\"", rule_spec);
				goto out;
			}

			/* Negated switch must be skipped */
			if (!g_strcmp0(match, "!"))
				match = argv[i++];
		}

		if (is_port_switch(arg, false)) {
			type = IPTABLES_PORT;
			match = argv[i++];

			if (!match) {
				DBG("trailing '%s' in rule \"%s\"", arg,
					rule_spec);
				goto out;
			}

			/* Negated switch must be skipped */
			if (!g_strcmp0(match, "!"))
				match = argv[i++];

			if (!validate_ports_or_services(match)) {
				DBG("invalid ports %s %s", arg, match);
				goto out;
			}
		}

		if (match && !is_supported(type, group, match)) {
			DBG("%s %s is not supported", arg, match);
			goto out;
		}

		/* Record the current switch type */
		switch_types_found[type]++;
		type = IPTABLES_UNSET;
		match = NULL;
	}

	/* There can be 0...2 port switches in rule */
	if (switch_types_found[IPTABLES_PORT] > 2)
		goto out;

	/* There should be 0...1 matches in one rule */
	if (switch_types_found[IPTABLES_MATCH] > 1)
		goto out;

	/* There should be 0...1 protocols defined in rule */
	if (switch_types_found[IPTABLES_PROTO] > 1)
		goto out;

	/* There has to be exactly one target in rule */
	if (switch_types_found[IPTABLES_TARGET] != 1)
		goto out;

	ret = true;

out:
	g_clear_error(&error);

	return ret;
}

typedef int (*add_rules_cb_t)(const char *group, int chain_id, char** rules);

static int add_dynamic_rules_cb(const char *group, int chain_id, char** rules)
{
	enum connman_service_type type;
	char table[] = "filter";
	int count = 0;
	int err = 0;
	int id;
	int i; 

	if (!dynamic_rules || !rules)
		return 0;

	type = __connman_service_string2type(group);

	if (!dynamic_rules[type])
		dynamic_rules[type] = __connman_firewall_create();

	for(i = 0; rules[i] ; i++) {

		DBG("process rule tech %s chain %s rule %s", group,
					builtin_chains[chain_id], rules[i]);

		if (!validate_iptables_rule(group, rules[i])) {
			DBG("failed to add rule, rule is invalid");
			continue;
		}

		id = __connman_firewall_add_rule(dynamic_rules[type], table,
						builtin_chains[chain_id],
						rules[i]);

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

static int add_general_rules_cb(const char *group, int chain_id, char** rules)
{
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

		DBG("processing %s rule chain %s rule %s", GROUP_GENERAL,
					builtin_chains[chain_id], rules[i]);

		if (!validate_iptables_rule(group, rules[i])) {
			DBG("invalid general rule");
			continue;
		}

		id = __connman_firewall_add_rule(general_firewall->ctx, table,
					builtin_chains[chain_id], rules[i]);

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

static int add_rules_from_group(GKeyFile *config, const char *group,
							add_rules_cb_t cb)
{
	GError *error = NULL;
	char** rules;
	int chain;
	int count;
	int err = 0;
	gsize len;

	DBG("");

	if (!group || !*group || !cb)
		return 0;

	for (chain = NF_IP_LOCAL_IN; chain < NF_IP_NUMHOOKS - 1; chain++) {

		rules = __connman_config_get_string_list(config, group,
					builtin_chains[chain], &len, &error);

		if (rules && len) {
			DBG("found %d rules in group %s chain %s", len, group,
						builtin_chains[chain]);

			count = cb(group, chain, rules);
			
			if (count < 0) {
				DBG("cannot add rules from config");
				err = -EINVAL;
			} else if (count < len) {
				DBG("%d invalid rules were detected and "
					"%d rules were added",
					len - count, count);
			} else {
				DBG("all %d rules were added", count);
			}
		} else if (rules && error) {
				/*
				 * A real error has happened, error with rules
				 * set as NULL = no such key exists in group
				 */
				DBG("group %s chain %s error: %s", group,
						builtin_chains[chain],
						error->message);
		} else {
			DBG("no rules found for group %s chain %s", group,
						builtin_chains[chain]);
		}

		g_clear_error(&error);

		g_strfreev(rules);
	}

	return err;
}

static bool check_config_key(const char* group, const char* key)
{
	char *policy;
	bool is_general = false;
	bool ret = false;
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
		if (!g_strcmp0(key, builtin_chains[i])) {
			DBG("match key %s chain %s", key, builtin_chains[i]);
			return true;
		}

		/* No other than General group should have policies set. */
		if (is_general) {
			policy = g_strconcat(builtin_chains[i], "_POLICY",
						NULL);

			ret = !g_strcmp0(key, policy);

			g_free(policy);
			
			if (ret) {
				DBG("match key %s chain %s POLICY", key,
						builtin_chains[i]);
				return ret;
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

static int enable_general_firewall()
{
	char table[] = "filter";
	int err;
	int i;

	DBG("");

	for (i = NF_IP_LOCAL_IN; i < NF_IP_NUMHOOKS - 1 ; i++) {
		if (!general_firewall->policies[i-1])
			continue;

		err = __connman_iptables_change_policy(table,
					builtin_chains[i],
					general_firewall->policies[i-1]);

		if (err)
			DBG("cannot set chain %s policy %s", builtin_chains[i],
					general_firewall->policies[i-1]);
		else {
			DBG("set chain %s policy %s", builtin_chains[i],
					general_firewall->policies[i-1]);

			err = __connman_iptables_commit(table);

			if (err)
				DBG("cannot commit changes on table %s", table);
		}
	}

	if (!general_firewall || !general_firewall->ctx) {
		DBG("no general firewall or firewall context set");
		return -EINVAL;
	}

	if (!g_list_length(general_firewall->ctx->rules)) {
		DBG("no general rules set");

		/* No rules defined, no error */
		return 0; 
	} else {
		DBG("%d general rules", g_list_length(general_firewall->ctx->rules));
	}

	return __connman_firewall_enable(general_firewall->ctx);
}

static bool is_valid_policy(char* policy)
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

static int init_general_firewall_policies(GKeyFile *config)
{
	GError *error = NULL;
	char *policy;
	int err = 0;
	int i;

	DBG("");

	if (!general_firewall || !config)
		return -EINVAL;

	general_firewall->policies = g_try_new0(char*,
				sizeof(char*) * GENERAL_FIREWALL_POLICIES);

	if (!general_firewall->policies)
		return -ENOMEM;

	general_firewall->restore_policies = g_try_new0(char*,
				sizeof(char*) * GENERAL_FIREWALL_POLICIES);

	if (!general_firewall->restore_policies)
		return -ENOMEM;
	
	for (i = NF_IP_LOCAL_IN; i < NF_IP_NUMHOOKS - 1; i++) {

		/* Policies index is one less than with chains */
		policy = g_strconcat(builtin_chains[i], "_POLICY", NULL);

		if (!policy)
			continue;

		if (general_firewall->policies[i-1])
			g_free(general_firewall->policies[i-1]);

		general_firewall->policies[i-1] = __connman_config_get_string(
					config, GROUP_GENERAL, policy, &error);

		if (!general_firewall->policies[i-1]) {
			DBG("no policy set for chain %s", builtin_chains[i]);
		} else if (!is_valid_policy(general_firewall->policies[i-1])) {
			g_free(general_firewall->policies[i-1]);
			general_firewall->policies[i-1] = NULL;
		} else {
			DBG("set chain %s policy %s", builtin_chains[i],
					general_firewall->policies[i-1]);
		}

		/* If policy is read and error is set is is a proper error.*/
		if (general_firewall->policies[i - 1] && error)
			DBG("failed to read %s: %s", policy, error->message);

		g_clear_error(&error);

		g_free(policy);
	}

	g_clear_error(&error);

	// TODO add function into iptables.c to get chain policy
	for (i = 0; i < GENERAL_FIREWALL_POLICIES ; i++)
		general_firewall->restore_policies[i] = g_strdup("ACCEPT");

	return err;
}

static int init_general_firewall(GKeyFile *config)
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

	err = add_rules_from_group(config, GROUP_GENERAL, add_general_rules_cb);

	if (err)
		DBG("cannot setup general firewall rules");
	else
		err = enable_general_firewall();

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

	if (init_general_firewall(config))
		DBG("Cannot setup general firewall");

	if (!dynamic_rules)
		dynamic_rules = g_try_new0(struct firewall_context*,
					sizeof(struct firewall_context*) *
					MAX_CONNMAN_SERVICE_TYPES);

	if (!dynamic_rules) {
		ret = -ENOMEM;
		goto out;
	}

	current_dynamic_rules = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, remove_ctx);

	for (type = CONNMAN_SERVICE_TYPE_UNKNOWN;
			type < MAX_CONNMAN_SERVICE_TYPES ; type++) {

		group = __connman_service_type2string(type);

		if (!group)
			continue;

		if (add_rules_from_group(config, group, add_dynamic_rules_cb))
			DBG("failed to process rules from group type %d", type);
	}

out:
	if (config)
		g_key_file_unref(config);

	return ret;
}

static void cleanup_general_firewall()
{
	char table[] = "filter";
	int err;
	int i;

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

	for (i = NF_IP_LOCAL_IN; i < NF_IP_NUMHOOKS - 1; i++) {

		/* If a policy has not been set it has not been changed */
		if (!general_firewall->policies[i-1])
			continue;

		g_free(general_firewall->policies[i-1]);

		if (!general_firewall->restore_policies[i-1])
			continue;

		err = __connman_iptables_change_policy(table,
				builtin_chains[i],
				general_firewall->restore_policies[i-1]);

		if (err) {
			DBG("cannot restore chain %s policy %s",
				builtin_chains[i],
				general_firewall->restore_policies[i-1]);
		} else {
			err = __connman_iptables_commit(table);

			if (err)
				DBG("cannot commit policy restore on "
					"chain %s policy %s",
					builtin_chains[i],
					general_firewall->restore_policies[i-1]);
		}

		g_free(general_firewall->restore_policies[i-1]);
	}

	g_free(general_firewall->policies);
	general_firewall->policies = NULL;

	g_free(general_firewall->restore_policies);
	general_firewall->restore_policies = NULL;

	g_free(general_firewall);
	general_firewall = NULL;
}

static void cleanup_dynamic_firewall_rules()
{
	enum connman_service_type type;

	DBG("");

	if (current_dynamic_rules)
		g_hash_table_destroy(current_dynamic_rules);

	if (!dynamic_rules)
		return;

	/* These rules are never enabled directly */
	for (type = CONNMAN_SERVICE_TYPE_UNKNOWN + 1;
			type < MAX_CONNMAN_SERVICE_TYPES ; type++) {

		if (!dynamic_rules[type])
			continue;

		__connman_firewall_destroy(dynamic_rules[type]);
		dynamic_rules[type] = NULL;
	}

	cleanup_general_firewall();

	g_free(dynamic_rules);
	dynamic_rules = NULL;
}

static struct connman_notifier firewall_notifier = {
	.name			= "firewall",
	.service_state_changed	= service_state_changed,
	.service_remove		= service_remove,
};

int __connman_firewall_init(void)
{
	int err;

	DBG("");

	flush_all_tables();

	err = init_dynamic_firewall_rules(CONFIGFIREWALLFILE);

	if (!err) { 
		err = connman_notifier_register(&firewall_notifier);
		if (err < 0) {
			DBG("cannot register notifier, dynamic rules disabled");
			cleanup_dynamic_firewall_rules();
		}
	}

	return 0;
}

void __connman_firewall_cleanup(void)
{
	DBG("");

	cleanup_dynamic_firewall_rules();

	g_slist_free_full(managed_tables, cleanup_managed_table);
	managed_tables = NULL;
}
