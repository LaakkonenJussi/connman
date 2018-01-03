/*
 *
 *  Connection Manager wrapper implementation of the exposed iptables functions
 *  for SailfishOS MDM. Contains save, restore and clear functionality.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <limits.h>

#include <netdb.h>
#include <iptables.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <libgen.h>
#include <endian.h>

#include <linux/netfilter/xt_connmark.h>

#include <iptables_extension.h>
#include <libiptc/libiptc.h>

#define INFO(fmt,arg...)					connman_info(fmt, ## arg)
#define ERR(fmt,arg...)						connman_error(fmt, ## arg)

#define IPTABLES_NAMES_FILE					"/proc/net/ip_tables_names"
#define IPTABLES_DEFAULT_V4_SAVE_FILE 		"iptables/rules.v4"

static bool save_in_progress = false;

gint check_save_directory(const char* fpath)
{
	gchar* path = NULL;
	gint mode = S_IRWXU;
	gint rval = 0;
	
	if(!fpath || !(*fpath))
		return 1;
		
	path = g_path_get_dirname(fpath);
	
	if(!g_str_has_prefix(path, STORAGEDIR))
	{
		rval = 1;
		goto out;
	}

	if(g_file_test(path,G_FILE_TEST_EXISTS))
	{
		// regular file
		if(!g_file_test(path,G_FILE_TEST_IS_DIR))
		{
			DBG("check_save_directory() Removing %s",path);
			if(g_remove(path))
			{
				rval = -1;
				goto out;
			}
		}
		// exists and is a dir
		else
		{
			DBG("check_save_directory() Dir %s exists, nothing done.", path);
			goto out;
		}
	}
	
	DBG("check_save_directory() Creating new dir for saving %s", path);
	rval = g_mkdir_with_parents(path,mode);

out:
	g_free(path);
	
	return rval;
	
}

gint iptables_set_file_contents(const gchar *fpath, GString *str,
	gboolean free_str)
{
	gboolean rval = false;
	
	if(fpath && *fpath && !check_save_directory(fpath) && str && str->len)
	{
		GError *err = NULL;
		
		rval = g_file_set_contents(fpath, str->str, str->len, &err);
		
		if(!rval || err)
		{
			ERR("iptables_set_file_contents() %s", err->message);
			g_error_free(err);
		}
	}
	
	if(free_str && str)
		g_string_free(str, true);
	
	return rval ? 0 : 1;
}

GString* iptables_get_file_contents(const gchar* fpath)
{
	GString *contents = NULL;
	
	if(fpath && *fpath)
	{
		gchar *content = NULL;
		gsize len = -1;
		GError *err = NULL;
		
		if(g_file_get_contents(fpath, &content, &len, &err))
			contents = g_string_new_len(content, len);
		else
		{
			ERR("iptables_get_file_contents() %s", err->message);
			g_error_free(err);
		}
		
		g_free(content);
	}
	return contents;
}

typedef struct output_capture_data {
	gint stdout_pipes[2];
	gint stdout_saved;
	gint stdout_read_limit;
	gint stdout_bytes_read;
	gchar *stdout_data;
} output_capture_data;

gint stdout_capture_start(output_capture_data *data)
{
	data->stdout_saved = dup(fileno(stdout));
	
	if(pipe(data->stdout_pipes))
	{
		ERR("stdout_capture_start() cannot create pipe");
		return 1;
	}
	
	if(dup2(data->stdout_pipes[1], fileno(stdout)) == -1)
	{
		ERR("stdout_capture_start() cannot duplicate fp with dup2");
		return -1;
	}
	
	if(close(data->stdout_pipes[1]))
	{
		ERR("stdout_capture_start() cannot close existing fp");
		return 1;
	}
	data->stdout_pipes[1] = -1;
	
	return 0;
}

void stdout_capture_data(output_capture_data *data)
{
	data->stdout_data = g_try_malloc0(data->stdout_read_limit);

	data->stdout_bytes_read = read(data->stdout_pipes[0],
		data->stdout_data,
		data->stdout_read_limit);
}

gint stdout_capture_end(output_capture_data *data)
{
	gint rval = dup2(data->stdout_saved,fileno(stdout));
	if(close(data->stdout_pipes[0]))
		ERR("stdout_capture_end() Cannot close capture fd @ 0");
	data->stdout_pipes[0] = -1;
	
	return rval != -1 ? 0 : 1;
}

/*
	Calls the save() function of iptables entry. Captures the stdout
	of the save() method and appends it to given GString.

*/
static void print_target_or_match(GString *line, const void *ip,
	const struct xtables_target *target, const struct xt_entry_target *t_entry,
	const struct xtables_match *match, const struct xt_entry_match *m_entry)
{
	output_capture_data data = {
		.stdout_pipes = {0},
		.stdout_saved = 0,
		.stdout_read_limit = 2000,
		.stdout_bytes_read = 0,
		.stdout_data = NULL
	};
	
	if(!(line && ip && ((target && t_entry) || (match && m_entry))))
		return;


	if(stdout_capture_start(&data))
		return;
	
	if(target && t_entry && target->save)
		target->save(ip,t_entry);
	else if(match && m_entry && match->save)
		match->save(ip,m_entry);
		
	if(fflush(stdout))
	{
		stdout_capture_end(&data);
		return;
	}
		
	stdout_capture_data(&data);
	
	if(data.stdout_bytes_read > 0)
	{
		g_string_append(line,data.stdout_data);
		g_free(data.stdout_data);
	}
		
	if(stdout_capture_end(&data))
		return;
}

static void print_target(GString *line, const void *ip,
	const struct xtables_target *target, const struct xt_entry_target *entry)
{
	if(line && ip && target && entry)
		print_target_or_match(line,ip,target,entry,NULL,NULL);
}

static void print_match(GString *line, const void *ip,
	const struct xtables_match *match, const struct xt_entry_match *entry)
{
	if(line && ip && match && entry)
		print_target_or_match(line,ip,NULL,NULL,match,entry);
}

// Adapted from iptables source iptables.c
static void print_proto(GString* line, uint16_t proto, int invert)
{
	if (proto) {
		unsigned int i;
		const char *invertstr = invert ? " !" : "";

		const struct protoent *pent = getprotobynumber(proto);
		if (pent)
		{
			g_string_append_printf(line,"%s -p %s", invertstr, pent->p_name);
			return;
		}

		for (i = 0; xtables_chain_protos[i].name != NULL; ++i)
		{
			if (xtables_chain_protos[i].num == proto)
			{
				g_string_append_printf(line,"%s -p %s",
				       invertstr, xtables_chain_protos[i].name);
				return;
			}
		}
		g_string_append_printf(line,"%s -p %u", invertstr, proto);
	}
}

// Adapted from iptables source iptables.c
#define IP_PARTS_NATIVE(n)			\
(unsigned int)((n)>>24)&0xFF,			\
(unsigned int)((n)>>16)&0xFF,			\
(unsigned int)((n)>>8)&0xFF,			\
(unsigned int)((n)&0xFF)

#define IP_PARTS(n) IP_PARTS_NATIVE(ntohl(n))

// Adapted from iptables source iptables.c
static void print_ip(GString* line, const char *prefix, uint32_t ip,
		     uint32_t mask, int invert)
{
	uint32_t bits, hmask = ntohl(mask);
	int i;
	
	if (!mask && !ip && !invert)
		return;
	
	g_string_append_printf(line, "%s %s %u.%u.%u.%u",
		invert ? " !" : "",
		prefix,
		IP_PARTS(ip));

	if (mask == 0xFFFFFFFFL)
		g_string_append(line,"/32");
	else
	{
		i    = 32;
		bits = 0xFFFFFFFEL;
		while (--i >= 0 && hmask != bits)
			bits <<= 1;
		if (i >= 0)
			g_string_append_printf(line,"/%u", i);
		else
			g_string_append_printf(line,"/%u.%u.%u.%u", IP_PARTS(mask));
	}
}

// Adapted from iptables source iptables.c
static void print_iface(GString* line, char letter, const char *iface,
	const unsigned char *mask, int invert)
{
	unsigned int i;

	if (mask[0] == 0)
		return;

	g_string_append_printf(line,"%s -%c ", invert ? " !" : "", letter);

	for (i = 0; i < IFNAMSIZ; i++)
	{
		if (mask[i] != 0)
		{
			if (iface[i] != '\0')
				g_string_append_printf(line,"%c", iface[i]);
		}
		else
		{
			/* we can access iface[i-1] here, because
			 * a few lines above we make sure that mask[0] != 0 */
			if (iface[i-1] != '\0')
				g_string_append(line,"+");
			break;
		}
	}
}

/* Re-implemented XT_MATCH_ITERATE preprocessor macro in C from iptables
	source include/linux/netfilter/x_tables.h
*/
static int match_iterate(
	GString *line, const struct ipt_entry *e,
	int (*fn) (
		GString *line, const struct xt_entry_match *e, 
		const struct ipt_ip *ip), 
	 const struct ipt_ip *ip)
{
	guint i;
	gint rval = 0;
	struct xt_entry_match *match;
	
	for(i = sizeof(struct ipt_entry);
		i < (e)->target_offset;
		i += match->u.match_size)
	{
		match = (void *)e + i;
		rval = fn(line,match,ip);
		if(rval != 0)
			break;
	}
	return rval;
}

// Adapted from iptables source iptables.c
static int print_match_save(GString *line, const struct xt_entry_match *e,
			const struct ipt_ip *ip)
{
	struct xtables_match *match =
		xtables_find_match(e->u.user.name, XTF_TRY_LOAD, NULL);

	if (match) {
		g_string_append_printf(line, " -m %s", e->u.user.name);
		print_match(line, ip, match, e);
		free(match); // xtables_find_match allocates a clone
	}
	else
	{
		if (e->u.match_size) {
			ERR("print_match_save() Can't find library for match `%s'\n",
				e->u.user.name);
			return 1;
		}
	}
	return 0;
}

// Adapted from iptables source iptables.c
void print_iptables_rule(GString* line, const struct ipt_entry *e,
		struct xtc_handle *h, const char *chain, int counters)
{
	const struct xt_entry_target *t = NULL;
	const char *target_name = NULL;

	/* print counters for iptables-save */
	if (counters > 0)
		g_string_append_printf(line,"[%llu:%llu] ", 
				(unsigned long long)e->counters.pcnt,
				(unsigned long long)e->counters.bcnt);
	
	/* print chain name */
	g_string_append_printf(line,"-A %s", chain);

	/* Print IP part. */
	print_ip(line,"-s", e->ip.src.s_addr,e->ip.smsk.s_addr,
			e->ip.invflags & IPT_INV_SRCIP);	

	print_ip(line,"-d", e->ip.dst.s_addr, e->ip.dmsk.s_addr,
			e->ip.invflags & IPT_INV_DSTIP);

	print_iface(line,'i', e->ip.iniface, e->ip.iniface_mask,
		    e->ip.invflags & IPT_INV_VIA_IN);

	print_iface(line,'o', e->ip.outiface, e->ip.outiface_mask,
		    e->ip.invflags & IPT_INV_VIA_OUT);

	print_proto(line,e->ip.proto, e->ip.invflags & XT_INV_PROTO);

	if (e->ip.flags & IPT_F_FRAG)
		g_string_append_printf(line,"%s -f",
			e->ip.invflags & IPT_INV_FRAG ? " !" : "");
	
	/* Print matchinfo part */
	if (e->target_offset)
		match_iterate(line, e, print_match_save, &e->ip);

	/* print counters for iptables -R */
	if (counters < 0)
		g_string_append_printf(line," -c %llu %llu", (unsigned long long)e->counters.pcnt, (unsigned long long)e->counters.bcnt);
	
	/* Print target name */
	target_name = iptc_get_target(e, h);
	if (target_name && (*target_name != '\0'))
		g_string_append_printf(line," -%c %s", e->ip.flags & IPT_F_GOTO ? 'g' : 'j', target_name);

	/* Print targetinfo part */
	t = ipt_get_target((struct ipt_entry *)e);
	if (t->u.user.name[0])
	{
		const struct xtables_target *target =
			xtables_find_target(t->u.user.name, XTF_TRY_LOAD);
		
		if (!target)
		{
			ERR("print_iptables_rule() can't find library for target `%s'\n",
				t->u.user.name);
			return;
		}

		print_target(line, &e->ip, target, t);
	}

	g_string_append(line, "\n");
}

// From iptables-save.c
int iptables_check_table(const char *table_name)
{
	int ret = 1;
	FILE *procfile = NULL;
	char read_table_name[XT_TABLE_MAXNAMELEN+1];
	
	if(!table_name || !(*table_name))
		return ret;
	
	memset(&read_table_name,0,sizeof(read_table_name));

	procfile = fopen(IPTABLES_NAMES_FILE, "re");
	
	if(!procfile)
		return ret;
	
	while (fgets(read_table_name, sizeof(read_table_name), procfile))
	{
		if (read_table_name[strlen(read_table_name) - 1] != '\n')
			ERR("iptables_check_table() Badly formed table_name `%s'",
				read_table_name);
			
		read_table_name[strlen(read_table_name) - 1] = '\0';
		
		ret = g_ascii_strcasecmp(read_table_name,table_name);
		
		if(!ret) // 0, match
			break;
		
		memset(&read_table_name,0,sizeof(read_table_name));
	}

	fclose(procfile);
	return ret;
}

static struct xtc_handle* get_iptc_handle(const char *table_name)
{
	struct xtc_handle *h = NULL;
	
	if(table_name && *table_name)
	{
		h = iptc_init(table_name);
	
		if (!h)
		{
			xtables_load_ko(xtables_modprobe_program, false);
			h = iptc_init(table_name);
		}
		if (!h)
			ERR("get_iptc_handle() Cannot initialize iptc: %s for table %s\n",
				iptc_strerror(errno), table_name);
	}
	
	return h;
}

// Adapted from iptables source iptables-save.c
static int iptables_save_table(const char *fpath, GString** output,
	const char *table_name, gboolean save_to_file)
{
	struct xtc_handle *h = NULL;
	const char *chain = NULL;
	GString *line = NULL;
	time_t now = {0};
	
	if(iptables_check_table(table_name))
	{
		ERR("iptables_save_table() called with invalid table name");
		return 1;
	}
	
	if(!save_to_file && (!output || !(*output) || (*output)->len))
	{
		ERR("iptables_save_table() invalid GString pointer given");
		return 1;
	}
	
	DBG("%s %s", "iptables_save_table() saving table: ", table_name);
	
	if(!(h = get_iptc_handle(table_name)))
		return 1;
	
	// Create new Gstring only if saving to file
	if(fpath)
	{
		line = g_string_new("");
		now = time(NULL);
	
		g_string_append_printf(line,"# Generated by connman on %s", ctime(&now));
		g_string_append_printf(line,"*%s\n", table_name);
	}
	else
		line = *output; // Use given GString

	/* Dump out chain names first,
	 * thereby preventing dependency conflicts */
	for (chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h))
	{
		g_string_append_printf(line,":%s ", chain);
		if (iptc_builtin(chain, h)) {
			struct xt_counters count = {0};
			
			g_string_append_printf(line,"%s ",
					iptc_get_policy(chain, &count, h));
					
			g_string_append_printf(line,"[%llu:%llu]\n", 
					(unsigned long long)count.pcnt,
					(unsigned long long)count.bcnt);
		} else
			g_string_append_printf(line,"- [0:0]\n");
	}

	for (chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h))
	{
		const struct ipt_entry *e = NULL;

		/* Dump out rules */
		e = iptc_first_rule(chain, h);
		while(e)
		{
			print_iptables_rule(line, e, h, chain, 0);
			e = iptc_next_rule(e, h);
		}
	}

	now = time(NULL);
	
	if(fpath)
	{
		g_string_append_printf(line,"COMMIT\n");
		g_string_append_printf(line,"# Completed on %s", ctime(&now));
	}
	
	iptc_free(h);
	
	if(fpath)
		return iptables_set_file_contents(fpath, line, true);
	else
		return 0;
}

static int iptables_clear_table(const char *table_name)
{
	struct xtc_handle *h = NULL;
	const char *chain = NULL;
	gint rval = 0;
	
	if(iptables_check_table(table_name))
	{
		ERR("iptables_clear_table() called with invalid table name");
		return 1;
	}
			
	if(!(h = get_iptc_handle(table_name)))
		return 1;
	
	for (chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h))
	{
		if(!iptc_flush_entries(chain,h))
			rval = 1;
	}

	if(!iptc_commit(h))
		rval = 1;
	
	if(h)
		iptc_free(h);

	return rval;
}

static int iptables_iptc_set_policy(const gchar* table_name, const gchar* chain, 
	const gchar* policy, guint64 packet_counter, guint64 byte_counter)
{
	gint rval = 0;
	struct xtc_handle *h = NULL;
	struct xt_counters counters = {0};
	
	if(!(table_name && *table_name && chain && *chain && policy && *policy))
		return 1;
		
	if(!(h = get_iptc_handle(table_name)))
		return 1;

	if(!iptc_is_chain(chain,h))
	{
		DBG("iptables_iptc_set_policy() chain does not exist, adding new.");
		rval = connman_iptables_new_chain(table_name, chain);
		goto out; // No policy change for custom chains
	}
	
	// Do nothing for chains that are not builtin, iptc_set_policy supports
	// builtin only
	if(!iptc_builtin(chain,h))
		goto out;

	counters.pcnt = packet_counter;
	counters.bcnt = byte_counter;

	DBG("Setting to table \"%s\" chain \"%s\" policy \"%s\" counters %llu %llu",
		table_name, chain, policy, packet_counter, byte_counter);

	if(!iptc_set_policy(chain, policy, &counters, h)) // returns 1 on success
	{
		ERR("iptables_iptc_set_policy() policy cannot be set %s", 
			iptc_strerror(errno));
		rval = 1;
		goto out;
	}
	
	if(!iptc_commit(h))
	{
		ERR("iptables_iptc_set_policy() commit error %s", iptc_strerror(errno));
		rval = 1;
	}

out:
	if(h)
		iptc_free(h);

	return rval;
}

static int iptables_parse_policy(const gchar* table_name, const gchar* policy)
{
	gint rval = 1;
	
	if(table_name && *table_name && policy && *policy)
	{
		// Format :CHAIN POLICY [int:int]
		gchar** tokens = g_strsplit(&(policy[1]), " ", 3);
		
		gchar** counter_tokens = g_strsplit_set(tokens[2], "[:]", 0);
		
		// counters start with '[' so first token is empty, start from 1
		guint64 packet_counter = g_ascii_strtoull(counter_tokens[1], NULL, 10);
		guint64 byte_counter = g_ascii_strtoull(counter_tokens[2], NULL, 10);
				
		rval = iptables_iptc_set_policy(table_name, tokens[0], tokens[1],
				packet_counter, byte_counter);

		g_strfreev(tokens);
		g_strfreev(counter_tokens);
	}
	
	return rval;
}

static int iptables_parse_rule(const gchar* table_name, const gchar* rule)
{
	gint rval = 1;
	
	if(table_name && *table_name && rule && *rule)
	{
		gint i = 0;
		// Format, e.g., -A CHAIN -p tcp -s 1.2.3.4  ...
		gchar** tokens = g_strsplit(&(rule[1])," ", 0);
		
		GString *rule_str = g_string_new(NULL);
		
		// Start from rule spec
		for(i = 2 ; tokens[i] && *(tokens[i]); i++)
			g_string_append_printf(rule_str,"%s ", tokens[i]);
			
		DBG("Adding to table \"%s\" chain \"%s\" rule: %s",
			table_name, tokens[1], rule_str->str);
			
		rval = __connman_iptables_append(table_name, tokens[1], rule_str->str);
		
		g_strfreev(tokens);
		g_string_free(rule_str,true);
	}
	
	return rval;
}

static int iptables_restore_table(const char *table_name, const char *fpath)
{
	gint rval = 0, i = 0;
	gboolean content_matches = false;
	gboolean process = true;
	
	if(!table_name || iptables_check_table(table_name))
	{
		ERR("iptables_restore_table() called with invalid table name");
		return 1;
	}
	
	GString *content = iptables_get_file_contents(fpath);
	
	if(!content)
		return 1;
		
	gchar** tokens = g_strsplit(content->str,"\n",0);
	
	for(i = 0; tokens[i] && process; i++)
	{	
		switch(tokens[i][0])
		{
			// Skip comment
			case '#':
				break;
			// Table name
			case '*':
				content_matches = !g_ascii_strcasecmp(&(tokens[i][1]), 
					table_name) ? true : false;
				break;
			// Chain and policy
			case ':':
				if(content_matches)
					rval += iptables_parse_policy(table_name, tokens[i]);
				break;
			// Rule
			case '-':
				if(content_matches)
					rval += iptables_parse_rule(table_name, tokens[i]);
				break;
			// If any other prefix for a line is found and we are processing
			// 'COMMIT' is the last line in iptables saved format, stop processing
			default:
				if(content_matches)
					process = false;
				break;
		}
	}
	g_strfreev(tokens);
	
	g_string_free(content,true);
	
	if(content_matches)
		rval += __connman_iptables_commit(table_name);
	else
		ERR("iptables_restore_table() requested table name does not match file table name");

	return rval;
}

/*
*
* return: 0 on success, 1 error and -1 if save is already in progress
*/
int connman_iptables_save(const char* table_name, const char* fpath)
{
	// TODO ADD MUTEX
	gint rval = 1;
	char *save_file = NULL;
	
	if(save_in_progress)
	{
		DBG("SAVE ALREADY IN PROGRESS");
		return -1;
	}
		
	// Remove all /./ and /../ and expand symlink
	save_file = realpath(fpath,NULL);

	if(save_file && g_file_test(save_file, G_FILE_TEST_EXISTS))
	{
		// Don't allow to overwrite executables, allow only connman storage
		if(g_file_test(save_file,G_FILE_TEST_IS_EXECUTABLE) ||
			!g_str_has_prefix(save_file, STORAGEDIR))
		{
			ERR("connman_iptables_save() cannot save firewall to %s", save_file);
			goto out;
		}
	}
	// File does not exist, use default
	else
		save_file = g_strdup_printf("%s/%s", STORAGEDIR, 
					IPTABLES_DEFAULT_V4_SAVE_FILE);
		
	DBG("connman_iptables_save() saving firewall to %s", save_file);

	save_in_progress = true;
	
	rval = iptables_save_table(save_file, NULL, table_name, true);
	
	save_in_progress = false;
	
out:
	g_free(save_file);

	return rval;
}


int connman_iptables_restore(const char* table_name, const char* fpath)
{
	gint rval = 1;
	gchar *load_file = NULL;
		
	// Remove all /./ and /../ and expand symlink
	load_file = realpath(fpath,NULL);

	if(load_file)
	{
		// Allow only regular files from connman storage
		if(!g_file_test(load_file,G_FILE_TEST_EXISTS) ||
			!g_file_test(load_file,G_FILE_TEST_IS_REGULAR) ||
			!g_str_has_prefix(load_file, STORAGEDIR))
				goto out;
	}
	// File not given or found
	else
		load_file = g_strdup_printf("%s/%s", STORAGEDIR, 
						IPTABLES_DEFAULT_V4_SAVE_FILE);
				
	DBG("connman_iptables_restore() restoring firewall from %s", load_file);
		
	if(!iptables_clear_table(table_name))
		rval = iptables_restore_table(table_name, load_file);
	else
		ERR("connman_iptables_restore() cannot restore table %s", table_name);
	
out:
	g_free(load_file);	
	return rval;
}

int connman_iptables_clear(const char* table_name)
{
	return iptables_clear_table(table_name);
}

const char* __connman_iptables_default_save_path(int ip_version)
{
	if(ip_version == 4)
		return g_strdup_printf("%s/%s", STORAGEDIR,
			IPTABLES_DEFAULT_V4_SAVE_FILE);
	else
		return g_strdup("Not implemented");
}

/*
	Returns: 0 Ok, -1 Parameter error, -EINVAL or -ENOMEM on Error
*/
int connman_iptables_new_chain(const char *table_name,
					const char *chain)
{
	if(!table_name || !(*table_name) || !chain || !(*chain))
		return -1;

	return __connman_iptables_new_chain(table_name, chain);
}

/*
	Returns: 0 Ok, -1 Parameter error, -EINVAL or -ENOMEM on error,
*/
int connman_iptables_delete_chain(const char *table_name,
					const char *chain)
{
	if(!table_name || !(*table_name) || !chain || !(*chain))
		return -1;

	return __connman_iptables_delete_chain(table_name, chain);
}

int connman_iptables_flush_chain(const char *table_name,
					const char *chain)
{
	if(!table_name || !(*table_name) || !chain || !(*chain))
		return -1;
		
	return __connman_iptables_flush_chain(table_name, chain);
}
	
int connman_iptables_iterate_chains(const char *table_name,
				connman_iptables_iterate_chains_cb_t cb,
				void *user_data)
{
	return __connman_iptables_iterate_chains(table_name, cb, user_data);
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

const char* connman_iptables_default_save_path(int ip_version)
{
	return __connman_iptables_default_save_path(ip_version);
}

static connman_iptables_content* iptables_content_new(const gchar* table_name)
{
	connman_iptables_content* content = g_new0(connman_iptables_content,1);
	content->chains = NULL;
	content->rules = NULL;
	content->table = g_strdup(table_name);
	
	return content;
}

void iptables_content_free(connman_iptables_content *content)
{
	if(!content)
		return;
		
	g_list_free(content->chains);
	g_list_free(content->rules);
	g_free(content->table);
	g_free(content);
}


connman_iptables_content* iptables_get_content(GString *output, const gchar* table_name)
{
	connman_iptables_content *content = NULL;
	gchar **tokens = NULL, **policy_tokens = NULL;
	gboolean process = true;
	gint i = 0;
	
	if(!output || !output->len)
		return NULL;

	content = iptables_content_new(table_name);
		
	tokens = g_strsplit(output->str, "\n", -1);
	
	for(i = 0; tokens[i] && process; i++)
	{
		switch(tokens[i][0])
		{
			// Skip comment and table name
			case '#':
			case '*':
				break;
			// Chain and policy
			case ':':
				// TODO improve this to allocate less memory
				policy_tokens = g_strsplit(&(tokens[i][1]), " ", 3);
				if(g_strv_length(policy_tokens) > 2)
				{
					content->chains = g_list_prepend(content->chains,
						g_strdup_printf("%s %s", 
							policy_tokens[0], policy_tokens[1]));
				}
				g_strfreev(policy_tokens);

				break;
			// Rule
			case '-':
				content->rules = g_list_prepend(content->rules,
					g_strdup(tokens[i]));	
				break;
			// Anything else, stop processing
			default:
				process = false;
				break;
		}
	}
	
	content->chains = g_list_reverse(content->chains);
	content->rules = g_list_reverse(content->rules);
	
	g_strfreev(tokens);
	
	return content;
}

void connman_iptables_free_content(connman_iptables_content *content)
{
	iptables_content_free(content);
}

connman_iptables_content* connman_iptables_get_content(const char *table_name)
{
	connman_iptables_content *content = NULL;
	
	GString *output = g_string_new(NULL);
	
	if(!iptables_save_table(NULL, &output, table_name, false))
		content = iptables_get_content(output, table_name);
	
	g_string_free(output, true);
	
	return content;
}

static int sailfish_iptables_extension_init()
{
	DBG("Sailfish iptables extension init()");
	return 0;
}

void sailfish_iptables_extension_exit()
{
	DBG("Sailfish iptables extension exit()");
}

CONNMAN_PLUGIN_DEFINE(sailfish_iptables_extension, "Sailfish iptables extension",
	VERSION,
	CONNMAN_PLUGIN_PRIORITY_HIGH - 1,
	sailfish_iptables_extension_init, sailfish_iptables_extension_exit)


