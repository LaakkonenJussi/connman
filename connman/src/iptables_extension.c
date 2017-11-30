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

#include <linux/netfilter/xt_connmark.h>

#include <iptables_extension.h>

#define INFO(fmt,arg...)					connman_info(fmt, ## arg)
#define ERR(fmt,arg...)						connman_error(fmt, ## arg)

#define IPTABLES_NAMES_FILE					"/proc/net/ip_tables_names"
#define IPTABLES_DEFAULT_V4_SAVE_FILE 		"iptables/rules.v4"

static gint fsock_write = -1;
static bool save_in_progress = false;

gint check_save_directory(const char* fpath)
{
	gchar* path = g_path_get_dirname(fpath);
	gint mode = S_IRWXU;
	gint rval = 0;
	
	if(g_file_test(path,G_FILE_TEST_EXISTS))
	{
		// regular file
		if(!g_file_test(path,G_FILE_TEST_IS_DIR))
		{
			DBG("Removing %s",path);
			if(g_remove(path))
			{
				g_free(path);
				return -1;
			}
		}
		// exists and is a dir
		else
		{
			DBG("Nothing done, dir %s exists", path);
			g_free(path);
			return 0;
		}
	}
	
	DBG("Creating new dir for saving %s", path);
	rval = g_mkdir_with_parents(path,mode);
	
	g_free(path);
	
	return rval;
	
}

/*
*	Returns: int (0 ok, -1 cannot write or create to file, 1 cannot create dir)
*/

gint open_write_socket(const gchar* fpath)
{
	gint mode = S_IRUSR|S_IWUSR;
	gint flags = O_WRONLY;
	
	if(check_save_directory(fpath))
		return 1;
	
	flags |= (g_file_test(fpath,G_FILE_TEST_EXISTS|G_FILE_TEST_IS_REGULAR) ?
		O_TRUNC : O_CREAT);
	
	if(((fsock_write = g_open(fpath, flags, mode)) > 0) &&
		g_file_test(fpath,G_FILE_TEST_EXISTS))
	{
		DBG("IPTABLES save file opened, path %s",fpath);
		return 0;
	}
	else
	{
		ERR("IPTABLES cannot be saved to %s - socket: %d",fpath,fsock_write);
		return -1;
	}
}

gint close_write_socket()
{
	GError *error = NULL;
	gint rval = 0;
	
	if(fsock_write < 0)
	{
		ERR("FILE CLOSE ERROR invalid socket");
		return -1;
	}
		
	if(!g_close(fsock_write,&error))
	{
		ERR("FILE CLOSE ERROR %s", (error ? error->message : ""));
		if(error)
			g_error_free(error);
		rval = 1;
	}
	else
		DBG("IPTABLES save file closed");
		
	fsock_write = -1;
	return rval;
}

gint iptables_append_to_file(gchar* data, gint datalen, gboolean freedata)
{
	gint wrote = 0;
	if(fsock_write > 0)
	{
		wrote = write(fsock_write, data, datalen);
		if(freedata)
			g_free(data);
		return wrote;
	}
	return 0;
}

gboolean iptables_append_gstring_to_file(GString *str)
{
	if(str)
	{
		gchar* line = g_string_free(str,FALSE);
		gint len = strlen(line);
		return iptables_append_to_file(line,len,TRUE) == len;
	}
	return FALSE;
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

	if (mask == 0xFFFFFFFFU)
		g_string_append(line,"/32");
	else
	{
		i    = 32;
		bits = 0xFFFFFFFEU;
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

	line = g_string_new("");
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
	const struct xtables_match *match =
		xtables_find_match(e->u.user.name, XTF_TRY_LOAD, NULL);

	if (match) {
		g_string_append_printf(line, " -m %s", e->u.user.name);
		print_match(line, ip, match, e);
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

// Adapted from iptables source iptables-save.c
static gint iptables_for_each_table(int (*func) (const char *tablename))
{
	int ret = 0;
	FILE *procfile = NULL;
	char tablename[XT_TABLE_MAXNAMELEN+1];

	procfile = fopen(IPTABLES_NAMES_FILE, "re");
	
	while (fgets(tablename, sizeof(tablename), procfile))
	{
		if (tablename[strlen(tablename) - 1] != '\n')
			ERR("iptables_for_each_table() Badly formed tablename `%s'",
				tablename);
			
		tablename[strlen(tablename) - 1] = '\0';
		ret += func(tablename);
	}

	fclose(procfile);
	return ret;
}

// Adapted from iptables source iptables-save.c
static int iptables_save_table(const char *tablename)
{
	struct xtc_handle *h = NULL;
	const char *chain = NULL;
	GString *line = NULL;
	
	if(!tablename)
	{
		ERR("iptables_save_table() called with empty table");
		return 1;
	}
	
	DBG("%s %s", "iptables save table: ", tablename);
	
	h = iptc_init(tablename);
	if (h == NULL)
	{
		xtables_load_ko(xtables_modprobe_program, false);
		h = iptc_init(tablename);
	}
	if (!h)
	{
		ERR("iptables_save_table() Cannot initialize: %s\n",
			   iptc_strerror(errno));
		return 1;
	}

	line = g_string_new("");
	time_t now = time(NULL);

	g_string_append_printf(line,"# Generated by connman on %s", ctime(&now));
	g_string_append_printf(line,"*%s\n", tablename);

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
	g_string_append_printf(line,"COMMIT\n");
	g_string_append_printf(line,"# Completed on %s", ctime(&now));
	iptc_free(h);
	
	if(!iptables_append_gstring_to_file(line))
	{
		ERR("print_ip invalid lenght write at iptables save");
		return 1;
	}
	
	return 0;
}

static int iptables_clear_table(const char *tablename)
{
	struct xtc_handle *h = NULL;
	const char *chain = NULL;
	gint rval = 0;
	DBG("iptables clear %s",tablename);
	
	if(!tablename)
	{
		ERR("iptables_clear_table() called with empty table");
		return 1;
	}
			
	h = iptc_init(tablename);
	
	if (!h)
	{
		xtables_load_ko(xtables_modprobe_program, false);
		h = iptc_init(tablename);
	}
	if (!h)
	{
		ERR("iptables_clear_table() Cannot initialize: %s\n",
			   iptc_strerror(errno));
		return 1;
	}
	
	for (chain = iptc_first_chain(h); chain; chain = iptc_next_chain(h))
	{
		if(!iptc_flush_entries(chain,h))
			rval = 1;
	}

	if(!iptc_commit(h))
		rval = 1;
	
	iptc_free(h);

	return rval;
}

int __connman_iptables_save(const char* fpath)
{
	// TODO ADD MUTEX
	gint rval = -1;
	char *save_file = NULL, *dir = NULL;
	
	if(save_in_progress)
	{
		DBG("SAVE ALREADY IN PROGRESS");
		return -1;
	}

	if(fsock_write != -1)
		close_write_socket();
		
	if(fpath)
	{
		// Remove all /./ and /../ and expand symlink
		save_file = realpath(fpath,NULL);

		if(save_file)
		{
			// Don't allow to overwrite executables, allow only connman storage
			if(g_file_test(save_file,G_FILE_TEST_IS_EXECUTABLE) ||
				!g_str_has_prefix(save_file, STORAGEDIR))
				goto out;
		}
		// File does not exist, check directory where file will be located
		else
		{
			dir = realpath(dirname((char*)fpath),NULL);
			
			// Allow only to connman storage
			if(dir && !g_str_has_prefix(dir, STORAGEDIR))
				goto out;
		}
	}
	
	// File not given, use default
	if(!save_file)
		save_file = g_strdup_printf("%s/%s", STORAGEDIR, 
						IPTABLES_DEFAULT_V4_SAVE_FILE);
	
	DBG("connman_iptables_save() saving firewall to %s", save_file);

	save_in_progress = true;
	
	if(!open_write_socket(save_file))
	{
		rval = (fsock_write > 0 ? 
			iptables_for_each_table(&iptables_save_table) : 1);
		close_write_socket();
	}
	save_in_progress = false;
	
out:
	if(save_file)
		g_free(save_file);
	if(dir)
		g_free(dir);

	return rval;
}


int __connman_iptables_restore(const char* fpath)
{
	DBG("%s", "iptables restore clear all iptables tables");
	
	/*TODO: first do clear iptables_for_each_table(&iptables_clear_table);
	 and restore the firewall from given file.
	*/ 
	return 0;
}

int __connman_iptables_clear(const char* tablename)
{
	if(tablename)
	{
		DBG("iptables clear table %s", tablename);
		return iptables_clear_table(tablename);
	}
	else
	{
		DBG("iptables clear all tables");
		return iptables_for_each_table(&iptables_clear_table);
	}
}

const char* __connman_iptables_default_save_path(int ip_version)
{
	if(ip_version == 4)
		return g_strdup_printf("%s/%s", STORAGEDIR,
			IPTABLES_DEFAULT_V4_SAVE_FILE);
	else
		return g_strdup("Not implemented");
}

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


