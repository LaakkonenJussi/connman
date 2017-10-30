/*
 *
 *  Connection Manager wrapper to expose firewall functions for SailfishOS
 *
 *  Copyright (C) 2017 Jolla Ltd. All rights reserved.
 *  Contact: Jussi Laakkonen <jussi.laakkonen@jolla.com>
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

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include "src/connman.h"

#include <errno.h>
#include <exposed_api.h>

#define INFO(fmt,arg...) connman_info(fmt, ## arg)

int connman_iptables_new_chain(const char *table_name,
					const char *chain)
{
	return __connman_iptables_new_chain(table_name, chain);
}
	
int connman_iptables_delete_chain(const char *table_name,
					const char *chain)
{
	return __connman_iptables_delete_chain(table_name, chain);
}

int connman_iptables_flush_chain(const char *table_name,
					const char *chain)
{
	return __connman_iptables_flush_chain(table_name, chain);
}
	
int connman_iptables_iterate_chains(const char *table_name,
				connman_iptables_iterate_chains_cb_t cb,
				void *user_data)
{
	return __connman_iptables_iterate_chains(table_name, cb, user_data);
}

int connman_iptables_init(void)
{
	return __connman_iptables_init();
}

int connman_iptables_insert(const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	return __connman_iptables_insert(table_name, chain, rule_spec);
}

int connman_iptables_append(const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	return __connman_iptables_append(table_name, chain, rule_spec);
}
	
int connman_iptables_delete(const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	return __connman_iptables_delete(table_name, chain, rule_spec);
}
	
int connman_iptables_commit(const char *table_name)
{
	return __connman_iptables_commit(table_name);
}

int connman_iptables_change_policy(const char *table_name,
					const char *chain,
					const char *policy)
{
	return __connman_iptables_change_policy(table_name, chain, policy);
}

int connman_iptables_save(const char* fpath)
{
	return __connman_iptables_save(fpath);
}

int connman_iptables_restore(const char* fpath)
{
	return __connman_iptables_restore(fpath);
}

int connman_iptables_clear(const char* tablename)
{
	return __connman_iptables_clear(tablename);
}

const char* connman_iptables_default_save_path(int ip_version)
{
	return __connman_iptables_default_save_path(ip_version);
}


static int sailfish_exposed_api_init()
{
	DBG("Sailfish exposed api init()");
	return 0;
}

void sailfish_exposed_api_exit()
{
	DBG("Sailfish exposed api exit()");
}

CONNMAN_PLUGIN_DEFINE(sailfish_exposed_api, "Sailfish exposed api functions",
	VERSION,
	CONNMAN_PLUGIN_PRIORITY_HIGH - 1,
	sailfish_exposed_api_init, sailfish_exposed_api_exit)


