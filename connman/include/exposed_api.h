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

#ifndef __CONNMAN_FIREWALL_H
#define __CONNMAN_FIREWALL_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IPTABLES FUNCTIONS */

int connman_iptables_new_chain(const char *table_name,
					const char *chain);
	
int connman_iptables_delete_chain(const char *table_name,
					const char *chain);

int connman_iptables_flush_chain(const char *table_name,
					const char *chain);

/* Disabled for now. The 2nd parameter is defined in
* src/connman.h
*/
/*int connman_iptables_iterate_chains(const char *table_name,
				connman_iptables_iterate_chains_cb_t cb,
				void *user_data);*/

int connman_iptables_init(void);

int connman_iptables_insert(const char *table_name,
				const char *chain,
				const char *rule_spec);

int connman_iptables_append(const char *table_name,
				const char *chain,
				const char *rule_spec);
	
int connman_iptables_delete(const char *table_name,
				const char *chain,
				const char *rule_spec);
	
int connman_iptables_commit(const char *table_name);

int connman_iptables_dump(const char *table_name);

int connman_iptables_change_policy(const char *table_name,
					const char *chain,
					const char *policy);
					
/* IPTABLES FUNCTIONS END */

/* FIREWALL FUNCTIONS */

int connman_firewall_init(void);

void connman_firewall_cleanup(void);
	
bool connman_firewall_is_up(void);
	
struct firewall_context *connman_firewall_create(void);

void connman_firewall_destroy(struct firewall_context *ctx);

int connman_firewall_enable(struct firewall_context *ctx);

int connman_firewall_disable(struct firewall_context *ctx);

int connman_firewall_add_rule(struct firewall_context *ctx,
				const char *table,
				const char *chain,
				const char *rule_fmt, ...);

int connman_firewall_enable_rule(struct firewall_context *ctx, int id);
	
int connman_firewall_disable_rule(struct firewall_context *ctx, int id);

int connman_firewall_remove_rule(struct firewall_context *ctx, int id);

/* FIREWALL FUNCTIONS END */

/* NAT FUNCTIONS */

int connman_nat_init(void);

int connman_nat_enable(const char *name, const char *address,
				unsigned char prefixlen);

void connman_nat_disable(const char *name);

void connman_nat_cleanup(void);

/* NAT FUNCTIONS END */

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_FIREWALL_H */
