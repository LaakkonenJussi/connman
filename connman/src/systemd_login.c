/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2020  Jolla Ltd.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
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
#include <string.h>

#include <glib.h>
#include <systemd/sd-login.h>

#include "connman.h"

#define DEFAULT_SEAT "seat0"

enum sd_session_state {
	SD_SESSION_UNDEF,
	SD_SESSION_ONLINE,
	SD_SESSION_ACTIVE,
	SD_SESSION_CLOSING,
};

struct systemd_login_data {
	uid_t active_uid;
	sd_login_monitor *login_monitor;
	GIOChannel *iochannel_in;
	guint iochannel_in_id;
};

struct systemd_login_data *login_data = NULL;

static enum sd_session_state get_session_state(const char *state)
{
	if (!g_strcmp0(state, "online"))
		return SD_SESSION_ONLINE;

	if (!g_strcmp0(state, "active"))
		return SD_SESSION_ACTIVE;

	if (!g_strcmp0(state, "closing"))
		return SD_SESSION_CLOSING;

	return SD_SESSION_UNDEF;
}

static bool get_session_uid_and_state(uid_t *uid,
			enum sd_session_state *session_state)
{
	char **sessions = NULL;
	char *seat;
	char *state;
	int err;
	int i;
	bool ignore_session = false;
	
	err = sd_get_sessions(&sessions);
	if (err < 1 || !sessions) {
		DBG("failed to get sessions");
		return false;
	}

	*uid = 0;
	*session_state = SD_SESSION_UNDEF;

	/*
	 * This assumes that there is only one real session with the
	 * DEFAULT_SEAT.
	 */
	for (i = 0; sessions[i]; i++) {
		ignore_session = false;

		err = sd_session_get_seat(sessions[i], &seat);
		if (err)
			continue; /* Ignore if failed or no seat. */

		if (g_ascii_strcasecmp(seat, DEFAULT_SEAT))
			ignore_session = true;

		g_free(seat);

		if (ignore_session)
			continue;
	
		err = sd_session_get_state(sessions[i], &state);
		if (err) {
			DBG("failed to get session %s state", sessions[i]);
			continue;
		}

		*session_state = get_session_state(state);
		g_free(state);

		err = sd_session_get_uid(sessions[i], uid);
		if (err) {
			DBG("failed to get session %s uid", sessions[i]);
			continue;
		}
	}

	g_strfreev(sessions);

	return *session_state == SD_SESSION_UNDEF && *uid == 0 ? false : true;
}

static void user_change_result_cb(int err)
{
	if (err)
		DBG("user change not successful %d:%s", err, strerror(-err));

	DBG("user changed");
}

static int check_session_status(struct systemd_login_data *login_data)
{
	enum sd_session_state state;
	uid_t uid;

	DBG("");

	if (!get_session_uid_and_state(&uid, &state)) {
		DBG("failed %d %d", uid, state);
		return false;
	}

	switch (state) {
	case SD_SESSION_ACTIVE:
		if (uid != login_data->active_uid) {
			DBG("user active changed, change to uid %d", uid);
			__connman_storage_change_user(uid,
						user_change_result_cb);
		} else {
			DBG("active user not changed, state active");
		}

		break;
	case SD_SESSION_ONLINE:
		if (uid != login_data->active_uid) {
			DBG("user changed, change to uid %d", uid);
			__connman_storage_change_user(uid,
						user_change_result_cb);
		} else {
			DBG("active user not changed, state online");
		}

		break;
	case SD_SESSION_CLOSING:
		DBG("logout, go to root");
		__connman_storage_change_user(0, user_change_result_cb);

		break;
	case SD_SESSION_UNDEF:
		DBG("unsupported status");
		break;
	}

	if (uid != login_data->active_uid) {
		DBG("active user %d -> user %d", login_data->active_uid, uid);
		login_data->active_uid = uid;
	}

	return true;
}

static void close_io_channel(struct systemd_login_data *login_data)
{
	DBG("");

	if (login_data->iochannel_in_id) {
		g_source_remove(login_data->iochannel_in_id);
		login_data->iochannel_in_id = 0;
	}

	if (login_data->iochannel_in) {
		g_io_channel_shutdown(login_data->iochannel_in, FALSE, NULL);
		g_io_channel_unref(login_data->iochannel_in);
		login_data->iochannel_in = NULL;
	}
}

static gboolean io_channel_cb(GIOChannel *source, GIOCondition condition,
			gpointer user_data)
{
	struct systemd_login_data *login_data = user_data;

	if (condition && G_IO_IN) {
		if (!check_session_status(login_data))
			DBG("failed to check session status");
		
		if (sd_login_monitor_flush(login_data->login_monitor))
			DBG("failed to flush login monitor");

	} else if (condition && G_IO_ERR) {
		DBG("iochannel error, closing");
		close_io_channel(login_data);
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

int __systemd_login_init()
{
	int err;
	int fd;

	DBG("");

	if (login_data)
		return -EALREADY;
	
	login_data = g_new0(struct systemd_login_data, 1);

	err = sd_login_monitor_new("session", &login_data->login_monitor);
	if (err < 0) {
		DBG("cannot initialize systemd login monitor (%s)",
					strerror(-err));
		login_data->login_monitor = NULL;
		return -ECONNABORTED;
	}

	check_session_status(login_data);

	fd = sd_login_monitor_get_fd(login_data->login_monitor);
	login_data->iochannel_in = g_io_channel_unix_new(fd);
	login_data->iochannel_in_id = g_io_add_watch(login_data->iochannel_in,
				G_IO_IN | G_IO_ERR, (GIOFunc)io_channel_cb,
				login_data);

	return 0;
}

void __systemd_login_cleanup()
{
	DBG("");

	if (!login_data)
		return;

	close_io_channel(login_data);

	if (sd_login_monitor_unref(login_data->login_monitor))
		DBG("cannot unref login monitor");
	else
		login_data->login_monitor = NULL;
	
	g_free(login_data);
	login_data = NULL;
}

